"""Create N repos for one stack, each with a vulnerable package file and Dependabot on.

Usage: provision.py STACK COUNT DEPENDENCY --org ORG [--issue N] [--issue-url URL]
                    [--report out/STACK.json] [--nudge-after SECONDS]
                    [--nudge-attempts N] [--workers N] [--stack-jobs N]

Repos are named `<stack>-<NN>`, numbered after the highest existing one in the org
(`python-03` exists -> `python-04`, `python-05`, ...). For each repo it:
  1. creates a private repo with an initial README commit on `main` and the
     `issue-repo-dependency-updater` and stack topics,
  2. enables Dependabot alerts (and the dependency graph) and Dependabot security updates,
  3. pushes one commit on top of `main` with the package file, a lockfile where one can be
     generated, `.github/dependabot.yml` and a README (and enables both again if step 2 failed).
--workers repos are created at once. Mutating API calls are paced to MUTATIONS_PER_MINUTE
split across --stack-jobs (the stack jobs running at once on the same token), which keeps
the token under GitHub's secondary rate limits. The lockfile is generated once per stack and
reused, with the repo name swapped in.
A push that Dependabot misses gets no `Graph Update` run and the repo waits ~30 min for a
periodic scan. Pushing the manifest to an existing default branch, with Dependabot already on,
avoids racing the first push to an empty repo. As a safety net, while the stack is being
provisioned, every repo with no Dependabot run --nudge-after seconds after its push (or after
its last nudge) gets a commit touching the package file and `dependabot.yml`, up to
--nudge-attempts times (`nudged_at`, `nudges`). Nudges are git pushes, not REST commits, so they
don't count against the content-creation limit.
GH_TOKEN must be able to create and administer repos in the org.
"""

import argparse
import datetime as dt
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

import gh
import manifests
from stacks import STACKS, TOPIC, repo_index, repo_name

FETCH_ATTEMPTS = 3
NUDGE_AFTER = 60
NUDGE_ATTEMPTS = 3
WORKERS = 8
# Mutating REST calls per minute for the whole token (5 secondary-limit points each, of 900/min),
# leaving room for the GETs; repo creation also stays under the 80/min content-creation limit.
MUTATIONS_PER_MINUTE = 120
POLL_EVERY = 5


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def org_repo_names(org):
    return [r["name"] for r in gh.api(f"orgs/{org}/repos?type=all&per_page=100", paginate=True)]


def next_names(stack, count, existing):
    used = [i for i in (repo_index(stack, n) for n in existing) if i is not None]
    start = max(used, default=0) + 1
    return [repo_name(stack, i) for i in range(start, start + count)]


class LockCache:
    """Generates the stack's lockfiles once (same dependency for every repo) and retargets them."""

    def __init__(self):
        self.lock = threading.Lock()
        self.locks = None

    def get(self, stack, files, spec, repo, org, registry=None):
        with self.lock:
            if self.locks is None:
                self.locks = manifests.lockfiles(stack, files, spec, registry=registry)
                return dict(self.locks)
        return manifests.retarget_lockfiles(stack, self.locks, repo, org)


def build_files(stack, repo, spec, org, issue_url, make_lockfiles=True, registry=None, lock_cache=None):
    files = {
        STACKS[stack]["file"]: manifests.package_file(stack, repo, spec, org, registry),
        ".github/dependabot.yml": manifests.dependabot_yml(stack, registry),
        "README.md": manifests.readme(repo, stack, spec, issue_url, registry),
        **manifests.registry_files(stack, registry),
    }
    if not make_lockfiles:
        locks = {}
    elif lock_cache:
        locks = lock_cache.get(stack, files, spec, repo, org, registry)
    else:
        locks = manifests.lockfiles(stack, files, spec, registry=registry)
    files.update(locks)
    lockfile = next((p for p in locks if p != STACKS[stack]["file"]), None)
    return files, lockfile


def git_runner(root, token):
    def git(*args):
        p = subprocess.run(["git", "-c", "user.name=github-actions[bot]",
                            "-c", "user.email=41898282+github-actions[bot]@users.noreply.github.com",
                            *args], cwd=root, capture_output=True, text=True)
        if p.returncode:
            raise gh.GhError(f"git {args[0]}: {(p.stderr + p.stdout).replace(token, '***').strip()[:300]}")
        return p.stdout.strip()
    return git


def push(org, repo, files, message, sleep=time.sleep):
    """Commit `files` on top of the remote `main` (the auto_init README commit) and push."""
    token = os.environ["GH_TOKEN"]
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        for path, text in files.items():
            (root / path).parent.mkdir(parents=True, exist_ok=True)
            (root / path).write_text(text)

        git = git_runner(root, token)
        url = f"https://x-access-token:{token}@github.com/{org}/{repo}.git"
        git("init", "-q", "-b", "main")
        for attempt in range(FETCH_ATTEMPTS):
            try:
                git("fetch", "-q", "--depth", "1", url, "main")
                git("reset", "-q", "--soft", "FETCH_HEAD")
                break
            except gh.GhError:
                if attempt + 1 < FETCH_ATTEMPTS:
                    sleep(2)
        git("add", "-A")
        git("commit", "-q", "-m", message)
        git("push", "-q", url, "main")
        return git("rev-parse", "HEAD")


def enable_dependabot(org, repo):
    gh.api(f"repos/{org}/{repo}/vulnerability-alerts", "PUT")
    gh.api(f"repos/{org}/{repo}/automated-security-fixes", "PUT")


def provision_one(org, stack, repo, spec, issue, issue_url, make_lockfiles=True, registry=None,
                  lock_cache=None):
    r = {"repo": f"{org}/{repo}", "name": repo, "url": f"https://github.com/{org}/{repo}",
         "stack": stack, "dependency": spec, "registry": registry, "lockfile": None, "error": None}
    try:
        created = gh.api(f"orgs/{org}/repos", "POST", {
            "name": repo, "private": True, "auto_init": True,
            "description": f"{stack} repo with a vulnerable {spec}, generated from {issue_url}",
            "has_wiki": False, "has_projects": False,
        })
        r["created_at"] = created["created_at"]
        gh.api(f"repos/{org}/{repo}/topics", "PUT", {"names": [TOPIC, stack, f"issue-{issue}"]})
        try:
            enable_dependabot(org, repo)
            r["dependabot_enabled_at"] = now()
        except gh.GhError as e:
            r["enable_before_push_error"] = str(e)
        files, r["lockfile"] = build_files(stack, repo, spec, org, issue_url, make_lockfiles, registry,
                                           lock_cache)
        r["files"] = sorted(files)
        r["sha"] = push(org, repo, files, f"Add {spec} and Dependabot config (#{issue})")
        r["pushed_at"] = now()
        if "enable_before_push_error" in r:
            enable_dependabot(org, repo)
            r["dependabot_enabled_at"] = now()
    except gh.GhError as e:
        r["error"] = str(e)
    return r


def parse_ts(ts):
    return dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))


def has_dependabot_run(org, repo):
    runs = gh.api(f"repos/{org}/{repo}/actions/runs?event=dynamic&per_page=1")
    return bool((runs or {}).get("total_count"))


def touch(path, text, stamp):
    """Append a harmless marker to a package file or `dependabot.yml`."""
    if path.endswith(".json"):
        doc = json.loads(text)
        doc["description"] = f"rerun requested {stamp}"
        return json.dumps(doc, indent=2) + "\n"
    comment = "//" if path.endswith("go.mod") else "#"
    return text + ("" if text.endswith("\n") else "\n") + f"{comment} rerun requested {stamp}\n"


def nudge_commit(org, repo, stack, stamp=None):
    """One pushed commit touching the package file and `dependabot.yml`.

    The package file change makes the dependency graph re-read it (a `Graph Update` run, then
    the alert and security update); the `dependabot.yml` change makes Dependabot reload its config.
    """
    stamp = stamp or now()
    token = os.environ["GH_TOKEN"]
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        git = git_runner(root, token)
        url = f"https://x-access-token:{token}@github.com/{org}/{repo}.git"
        git("init", "-q", "-b", "main")
        git("fetch", "-q", "--depth", "1", url, "main")
        git("reset", "-q", "--hard", "FETCH_HEAD")
        for path in (STACKS[stack]["file"], ".github/dependabot.yml"):
            f = root / path
            f.write_text(touch(path, f.read_text(), stamp))
        git("commit", "-q", "-am", "Rerun Dependabot")
        git("push", "-q", url, "main")
        return git("rev-parse", "HEAD")


def utcnow():
    return dt.datetime.now(dt.timezone.utc)


class Watch:
    """Nudges repos that get no Dependabot run, while the rest of the stack is still being created.

    A repo is checked `after` seconds after its push and after each nudge; it is dropped as soon as
    it has a Dependabot run, or after `attempts` nudges.
    """

    def __init__(self, org, after=NUDGE_AFTER, attempts=NUDGE_ATTEMPTS, clock=utcnow, sleep=time.sleep,
                 workers=1):
        self.org, self.after, self.attempts = org, after, attempts
        self.clock, self.sleep, self.workers = clock, sleep, workers
        self.pending = []

    def add(self, r):
        if self.after > 0 and not r["error"] and r.get("pushed_at"):
            self.pending.append([parse_ts(r["pushed_at"]) + dt.timedelta(seconds=self.after), r])

    def check(self, item):
        """Nudge one due repo; returns True when it no longer needs watching."""
        r = item[1]
        nudges = r.get("nudges", [])
        try:
            if has_dependabot_run(self.org, r["name"]):
                return True
            if len(nudges) >= self.attempts:
                print(f"{r['repo']}: still no Dependabot run after {len(nudges)} nudges", file=sys.stderr)
                return True
            stamp = self.clock().isoformat(timespec="seconds").replace("+00:00", "Z")
            nudge_commit(self.org, r["name"], r["stack"], stamp)
            r["nudges"] = nudges + [stamp]
            r.setdefault("nudged_at", stamp)
            print(f"{r['repo']}: no Dependabot run yet, nudge {len(r['nudges'])}", file=sys.stderr)
        except gh.GhError as e:
            print(f"{r['repo']}: nudge check failed: {e}", file=sys.stderr)
        item[0] = self.clock() + dt.timedelta(seconds=self.after)
        return False

    def poll(self):
        """Check every repo that is due (`workers` at once); never sleeps."""
        due = [p for p in self.pending if p[0] <= self.clock()]
        if self.workers > 1 and len(due) > 1:
            with ThreadPoolExecutor(min(self.workers, len(due))) as pool:
                finished = list(pool.map(self.check, due))
        else:
            finished = [self.check(item) for item in due]
        for item, done in zip(due, finished):
            if done:
                self.pending.remove(item)

    def drain(self):
        """Keep polling until every repo has a Dependabot run or is out of nudges."""
        while self.pending:
            wait = (min(p[0] for p in self.pending) - self.clock()).total_seconds()
            if wait > 0:
                self.sleep(wait)
            self.poll()


def run(org, stack, count, spec, issue, issue_url, existing=None, make_lockfiles=True, registry=None,
        nudge_after=0, nudge_attempts=NUDGE_ATTEMPTS, watch=None, workers=WORKERS, poll_every=POLL_EVERY):
    """Create the repos `workers` at a time, nudging the pushed ones while the rest are created."""
    existing = org_repo_names(org) if existing is None else existing
    names = next_names(stack, count, existing)
    workers = max(1, min(workers, len(names) or 1))
    watch = watch or Watch(org, nudge_after, nudge_attempts, workers=workers)
    lock_cache = LockCache()
    done = {}
    with ThreadPoolExecutor(workers) as pool:
        running = {pool.submit(provision_one, org, stack, name, spec, issue, issue_url, make_lockfiles,
                               registry, lock_cache): name for name in names}
        while running:
            finished, _ = wait(running, timeout=poll_every, return_when=FIRST_COMPLETED)
            for f in finished:
                r = done[running.pop(f)] = f.result()
                print(f"{r['repo']}: {r['error'] or 'ok'} ({len(done)}/{len(names)})", file=sys.stderr)
                watch.add(r)
            watch.poll()
    watch.drain()
    repos = [done[n] for n in names]
    return {"stack": stack, "dependency": spec, "registry": registry, "requested": count,
            "created": sum(r["error"] is None for r in repos), "repos": repos}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("stack", choices=sorted(STACKS))
    ap.add_argument("count", type=int)
    ap.add_argument("dependency")
    ap.add_argument("--org", required=True)
    ap.add_argument("--issue", default="0")
    ap.add_argument("--issue-url", default="")
    ap.add_argument("--advisory", default="null", help="advisory JSON from the parse step")
    ap.add_argument("--registry", default="", help="custom registry URL (blank = public registry)")
    ap.add_argument("--report")
    ap.add_argument("--nudge-after", type=int, default=NUDGE_AFTER,
                    help="nudge repos with no Dependabot run this many seconds after push/last nudge (0 = off)")
    ap.add_argument("--nudge-attempts", type=int, default=NUDGE_ATTEMPTS)
    ap.add_argument("--workers", type=int, default=WORKERS, help="repos created at once")
    ap.add_argument("--stack-jobs", type=int, default=1,
                    help="stack jobs running at once on the same token; they share MUTATIONS_PER_MINUTE")
    args = ap.parse_args()

    gh.set_mutation_rate(MUTATIONS_PER_MINUTE / max(1, args.stack_jobs))
    report = run(args.org, args.stack, args.count, args.dependency.strip(), args.issue, args.issue_url,
                 registry=args.registry.strip() or None, nudge_after=args.nudge_after,
                 nudge_attempts=args.nudge_attempts, workers=args.workers)
    report["advisory"] = json.loads(args.advisory or "null")
    print(json.dumps(report, indent=2))
    if args.report:
        pathlib.Path(args.report).write_text(json.dumps(report))
    if report["created"] < args.count:
        sys.exit(1)


if __name__ == "__main__":
    main()
