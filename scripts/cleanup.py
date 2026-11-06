"""Delete repos created by this tool (topic `issue-repo-dependency-updater`).

Usage: cleanup.py --org ORG [--stacks python,node] [--issue N] [--dry-run]

Only repos that carry the topic and are named `<stack>-<number>` are touched.
GH_TOKEN needs permission to delete repos in the org.
"""

import argparse
import sys

import gh
from stacks import STACKS, TOPIC, repo_index, repo_key


def targets(repos, stacks=None, issue=None):
    stacks = stacks or list(STACKS)
    out = []
    for r in repos:
        topics = set(r.get("topics") or [])
        if TOPIC not in topics or (issue and f"issue-{issue}" not in topics):
            continue
        if any(repo_index(s, r["name"]) is not None for s in stacks):
            out.append(r["full_name"])
    return sorted(out, key=lambda n: repo_key(n.split("/")[1]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--org", required=True)
    ap.add_argument("--stacks", default="", help="comma-separated; default all")
    ap.add_argument("--issue", default="", help="only repos created by this issue number")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    stacks = [s.strip() for s in args.stacks.split(",") if s.strip()]
    unknown = [s for s in stacks if s not in STACKS]
    if unknown:
        sys.exit(f"Unknown stack(s): {', '.join(unknown)}")

    names = targets(gh.api(f"orgs/{args.org}/repos?type=all&per_page=100", paginate=True), stacks, args.issue)
    failed = 0
    for name in names:
        if args.dry_run:
            print(f"would delete {name}")
            continue
        try:
            gh.api(f"repos/{name}", "DELETE")
            print(f"deleted {name}")
        except gh.GhError as e:
            failed += 1
            print(f"failed {name}: {e}")
    print(f"{len(names) - failed}/{len(names)} repo(s) {'matched' if args.dry_run else 'deleted'}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
