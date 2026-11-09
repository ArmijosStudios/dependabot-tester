"""Delete repos created by this tool, and nothing else in the org.

Usage: cleanup.py --org ORG [--source-repo NAME] [--stacks python,node] [--issue N] [--dry-run]

A repo is only deleted when everything `provision.py` stamps on it matches:
  - its name is `<stack>-<number>`,
  - it has the `dependabot-tester` (or legacy `issue-repo-dependency-updater`), `<stack>`
    and `issue-<N>` topics,
  - its description is the generated one pointing at issue N of this repo
    (or its old name, `issue-repo-dependency-updater`),
  - it isn't a fork.
Repos that match only some of these are listed as skipped and left alone.
GH_TOKEN needs permission to delete repos in the org.
"""

import argparse
import os
import re
import sys

import gh
from stacks import LEGACY_SOURCE_REPOS, LEGACY_TOPICS, STACKS, TOPIC, repo_index, repo_key


def source_names(source_repo):
    return {source_repo.split("/")[-1], *LEGACY_SOURCE_REPOS}


def generated_by_us(repo, org, sources):
    """(stack, issue) when every provision marker on `repo` matches, else None."""
    stack = next((s for s in STACKS if repo_index(s, repo["name"]) is not None), None)
    if stack is None or repo.get("fork"):
        return None
    topics = set(repo.get("topics") or [])
    issues = {t[len("issue-"):] for t in topics if re.fullmatch(r"issue-\d+", t)}
    if not topics & {TOPIC, *LEGACY_TOPICS} or stack not in topics or len(issues) != 1:
        return None
    m = re.fullmatch(
        rf"{re.escape(stack)} repo with a vulnerable .+, generated from "
        rf"https://github\.com/{re.escape(org)}/({'|'.join(map(re.escape, sorted(sources)))})/issues/(\d+)",
        repo.get("description") or "", flags=re.IGNORECASE)
    if not m or m.group(2) not in issues:
        return None
    return stack, m.group(2)


def targets(repos, org, source_repo, stacks=None, issue=None):
    """(full names to delete, full names that look generated but fail a check)."""
    stacks = set(stacks or STACKS)
    sources = source_names(source_repo)
    out, skipped = [], []
    for r in repos:
        if not any(repo_index(s, r["name"]) is not None for s in stacks):
            continue
        match = generated_by_us(r, org, sources)
        if match is None:
            skipped.append(r["full_name"])
            continue
        stack, from_issue = match
        if stack in stacks and (not issue or from_issue == str(issue)):
            out.append(r["full_name"])
    key = lambda n: repo_key(n.split("/")[1])
    return sorted(out, key=key), sorted(skipped, key=key)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--org", required=True)
    ap.add_argument("--source-repo", default=os.environ.get("GITHUB_REPOSITORY", "dependabot-tester"),
                    help="repo whose issues created the repos (default $GITHUB_REPOSITORY)")
    ap.add_argument("--stacks", default="", help="comma-separated; default all")
    ap.add_argument("--issue", default="", help="only repos created by this issue number")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    stacks = [s.strip() for s in args.stacks.split(",") if s.strip()]
    unknown = [s for s in stacks if s not in STACKS]
    if unknown:
        sys.exit(f"Unknown stack(s): {', '.join(unknown)}")
    if args.issue and not args.issue.strip().isdigit():
        sys.exit(f"--issue must be a number, got {args.issue!r}")

    repos = gh.api(f"orgs/{args.org}/repos?type=all&per_page=100", paginate=True)
    names, skipped = targets(repos, args.org, args.source_repo, stacks, args.issue.strip())
    for name in skipped:
        print(f"skipped {name}: named like a generated repo but not created by {args.source_repo}")
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
