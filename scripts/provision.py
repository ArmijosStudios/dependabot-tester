"""Create N repos for one stack, each with a vulnerable package file and Dependabot on.

Usage: provision.py STACK COUNT DEPENDENCY --org ORG [--issue N] [--issue-url URL]
                    [--report out/STACK.json]

Repos are named `<stack>-<NN>`, numbered after the highest existing one in the org
(`python-03` exists -> `python-04`, `python-05`, ...). For each repo it:
  1. creates a private, empty repo with the `dependabot-tester` and stack topics,
  2. pushes one commit to `main` with the package file, a lockfile where one can be
     generated, `.github/dependabot.yml` and a README,
  3. enables Dependabot alerts (and the dependency graph) and Dependabot security updates.
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

import gh
import manifests
from stacks import STACKS, TOPIC, repo_index, repo_name


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


def push(org, repo, files, message):
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

        git("init", "-q", "-b", "main")
        git("add", "-A")
        git("commit", "-q", "-m", message)
        git("push", "-q", f"https://x-access-token:{token}@github.com/{org}/{repo}.git", "main")
        return git("rev-parse", "HEAD")


def provision_one(org, stack, repo, spec, issue, issue_url, make_lockfiles=True, registry=None):
    r = {"repo": f"{org}/{repo}", "name": repo, "url": f"https://github.com/{org}/{repo}",
         "stack": stack, "dependency": spec, "registry": registry, "lockfile": None, "error": None}
    try:
        created = gh.api(f"orgs/{org}/repos", "POST", {
            "name": repo, "private": True, "auto_init": False,
            "description": f"{stack} repo with a vulnerable {spec}, generated from {issue_url}",
            "has_wiki": False, "has_projects": False,
        })
        r["created_at"] = created["created_at"]
        gh.api(f"repos/{org}/{repo}/topics", "PUT", {"names": [TOPIC, stack, f"issue-{issue}"]})
        files, r["lockfile"] = build_files(stack, repo, spec, org, issue_url, make_lockfiles, registry)
        r["files"] = sorted(files)
        r["sha"] = push(org, repo, files, f"Add {spec} and Dependabot config (#{issue})")
        r["pushed_at"] = now()
        gh.api(f"repos/{org}/{repo}/vulnerability-alerts", "PUT")
        r["alerts_enabled_at"] = now()
        gh.api(f"repos/{org}/{repo}/automated-security-fixes", "PUT")
        r["security_updates_enabled_at"] = now()
    except gh.GhError as e:
        r["error"] = str(e)
    return r


def run(org, stack, count, spec, issue, issue_url, existing=None, make_lockfiles=True, registry=None):
    existing = org_repo_names(org) if existing is None else existing
    repos = []
    for name in next_names(stack, count, existing):
        r = provision_one(org, stack, name, spec, issue, issue_url, make_lockfiles, registry)
        print(f"{r['repo']}: {r['error'] or 'ok'}", file=sys.stderr)
        repos.append(r)
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
    args = ap.parse_args()

    report = run(args.org, args.stack, args.count, args.dependency.strip(), args.issue, args.issue_url,
                 registry=args.registry.strip() or None)
    report["advisory"] = json.loads(args.advisory or "null")
    print(json.dumps(report, indent=2))
    if args.report:
        pathlib.Path(args.report).write_text(json.dumps(report))
    if report["created"] < args.count:
        sys.exit(1)


if __name__ == "__main__":
    main()
