"""Create N repos for one stack, each with a vulnerable package file and Dependabot on.

Usage: provision.py STACK COUNT DEPENDENCY --org ORG [--issue N] [--issue-url URL]
                    [--report out/STACK.json] [--nudge-after SECONDS]
                    [--nudge-attempts N]

Repos are named `<stack>-<NN>`, numbered after the highest existing one in the org
(`python-03` exists -> `python-04`, `python-05`, ...). For each repo it:
  1. creates a private repo with an initial README commit on `main` and the
     `dependabot-tester` and stack topics,
  2. enables Dependabot alerts (and the dependency graph) and Dependabot security updates,
  3. pushes one commit on top of `main` with the package file, a lockfile where one can be
     generated, `.github/dependabot.yml` and a README, then enables both again.
A push that Dependabot misses gets no `Graph Update` run and the repo waits ~30 min for a
periodic scan. Pushing the manifest to an existing default branch, with Dependabot already on,
avoids racing the first push to an empty repo. As a safety net, while the stack is being
provisioned, every repo with no Dependabot run --nudge-after seconds after its push (or after
its last nudge) gets a commit touching the package file and `dependabot.yml`, up to
--nudge-attempts times (`nudged_at`, `nudges`).
GH_TOKEN must be able to create and administer repos in the org.
"""

import argparse
import base64
import datetime as dt
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time

import gh
import manifests
from stacks import STACKS, TOPIC, repo_index, repo_name

FETCH_ATTEMPTS = 3
NUDGE_AFTER = 60
NUDGE_ATTEMPTS = 3


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def org_repo_names(org):
    return [r["name"] for r in gh.api(f"orgs/{org}/repos?type=all&per_page=100", paginate=True)]


def next_names(stack, count, existing):
    used = [i for i in (repo_index(stack, n) for n in existing) if i is not None]
    start = max(used, default=0) + 1
    return [repo_name(stack, i) for i in range(start, start + count)]


def build_files(stack, repo, spec, org, issue_url, make_lockfiles=True, registry=None):
    files = {
        STACKS[stack]["file"]: manifests.package_file(stack, repo, spec, org, registry),
        ".github/dependabot.yml": manifests.dependabot_yml(stack, registry),
        "README.md": manifests.readme(repo, stack, spec, issue_url, registry),
        **manifests.registry_files(stack, registry),
    }
    locks = manifests.lockfiles(stack, files, spec, registry=registry) if make_lockfiles else {}
    files.update(locks)
    lockfile = next((p for p in locks if p != STACKS[stack]["file"]), None)
    return files, lockfile


def push(org, repo, files, message, sleep=time.sleep):
    """Commit `files` on top of the remote `main` (the auto_init README commit) and push."""
    token = os.environ["GH_TOKEN"]
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        for path, text in files.items():
            (root / path).parent.mkdir(parents=True, exist_ok=True)
            (root / path).write_text(text)

        def git(*args):
            p = subprocess.run(["git", "-c", "user.name=github-actions[bot]",
                                "-c", "user.email=41898282+github-actions[bot]@users.noreply.github.com",
                                *args], cwd=root, capture_output=True, text=True)
            if p.returncode:
                raise gh.GhError(f"git {args[0]}: {(p.stderr + p.stdout).replace(token, '***').strip()[:300]}")
            return p.stdout.strip()

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


def provision_one(org, stack, repo, spec, issue, issue_url, make_lockfiles=True, registry=None):
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
        except gh.GhError as e:
            r["enable_before_push_error"] = str(e)
        files, r["lockfile"] = build_files(stack, repo, spec, org, issue_url, make_lockfiles, registry)
        r["files"] = sorted(files)
        r["sha"] = push(org, repo, files, f"Add {spec} and Dependabot config (#{issue})")
        r["pushed_at"] = now()
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
    """One commit touching the package file and `dependabot.yml`.

    The package file change makes the dependency graph re-read it (a `Graph Update` run, then
    the alert and security update); the `dependabot.yml` change makes Dependabot reload its config.
    """
    stamp = stamp or now()
    base = f"repos/{org}/{repo}"
    head = gh.api(f"{base}/git/ref/heads/main")["object"]["sha"]
    tree = []
    for path in (STACKS[stack]["file"], ".github/dependabot.yml"):
        cur = gh.api(f"{base}/contents/{path}?ref={head}")
        text = base64.b64decode(cur["content"]).decode()
        tree.append({"path": path, "mode": "100644", "type": "blob", "content": touch(path, text, stamp)})
    base_tree = gh.api(f"{base}/git/commits/{head}")["tree"]["sha"]
    new_tree = gh.api(f"{base}/git/trees", "POST", {"base_tree": base_tree, "tree": tree})["sha"]
    commit = gh.api(f"{base}/git/commits", "POST", {"message": "Rerun Dependabot", "tree": new_tree,
                                                    "parents": [head]})["sha"]
    gh.api(f"{base}/git/refs/heads/main", "PATCH", {"sha": commit})
    return commit


def utcnow():
    return dt.datetime.now(dt.timezone.utc)


class Watch:
    """Nudges repos that get no Dependabot run, while the rest of the stack is still being created.

    A repo is checked `after` seconds after its push and after each nudge; it is dropped as soon as
    it has a Dependabot run, or after `attempts` nudges.
    """

    def __init__(self, org, after=NUDGE_AFTER, attempts=NUDGE_ATTEMPTS, clock=utcnow, sleep=time.sleep):
        self.org, self.after, self.attempts = org, after, attempts
        self.clock, self.sleep = clock, sleep
        self.pending = []

    def add(self, r):
        if self.after > 0 and not r["error"] and r.get("pushed_at"):
            self.pending.append([parse_ts(r["pushed_at"]) + dt.timedelta(seconds=self.after), r])

    def poll(self):
        """Check every repo that is due; never sleeps."""
        due = [p for p in self.pending if p[0] <= self.clock()]
        for item in due:
            r = item[1]
            nudges = r.get("nudges", [])
            try:
                if has_dependabot_run(self.org, r["name"]):
                    self.pending.remove(item)
                    continue
                if len(nudges) >= self.attempts:
                    self.pending.remove(item)
                    print(f"{r['repo']}: still no Dependabot run after {len(nudges)} nudges", file=sys.stderr)
                    continue
                stamp = self.clock().isoformat(timespec="seconds").replace("+00:00", "Z")
                nudge_commit(self.org, r["name"], r["stack"], stamp)
                r["nudges"] = nudges + [stamp]
                r.setdefault("nudged_at", stamp)
                print(f"{r['repo']}: no Dependabot run yet, nudge {len(r['nudges'])}", file=sys.stderr)
            except gh.GhError as e:
                print(f"{r['repo']}: nudge check failed: {e}", file=sys.stderr)
            item[0] = self.clock() + dt.timedelta(seconds=self.after)

    def drain(self):
        """Keep polling until every repo has a Dependabot run or is out of nudges."""
        while self.pending:
            wait = (min(p[0] for p in self.pending) - self.clock()).total_seconds()
            if wait > 0:
                self.sleep(wait)
            self.poll()


def run(org, stack, count, spec, issue, issue_url, existing=None, make_lockfiles=True, registry=None,
        nudge_after=0, nudge_attempts=NUDGE_ATTEMPTS, watch=None):
    existing = org_repo_names(org) if existing is None else existing
    watch = watch or Watch(org, nudge_after, nudge_attempts)
    repos = []
    for name in next_names(stack, count, existing):
        r = provision_one(org, stack, name, spec, issue, issue_url, make_lockfiles, registry)
        print(f"{r['repo']}: {r['error'] or 'ok'}", file=sys.stderr)
        repos.append(r)
        watch.add(r)
        watch.poll()
    watch.drain()
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
    args = ap.parse_args()

    report = run(args.org, args.stack, args.count, args.dependency.strip(), args.issue, args.issue_url,
                 registry=args.registry.strip() or None, nudge_after=args.nudge_after,
                 nudge_attempts=args.nudge_attempts)
    report["advisory"] = json.loads(args.advisory or "null")
    print(json.dumps(report, indent=2))
    if args.report:
        pathlib.Path(args.report).write_text(json.dumps(report))
    if report["created"] < args.count:
        sys.exit(1)


if __name__ == "__main__":
    main()
