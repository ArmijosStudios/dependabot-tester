"""Parse a "Repo dependency rollout" issue form body into a GitHub Actions matrix.

Reads the issue body from $ISSUE_BODY and writes `matrix`, `max_parallel`
and `limit` to $GITHUB_OUTPUT. Stacks with no dependency get one picked from
the GitHub Advisory Database (see pick_vulnerable.py). Exits non-zero with a
readable message on bad input.
"""

import json
import os
import re
import subprocess
import sys

from stacks import MAX_REPOS_PER_STACK, STACKS

NO_RESPONSE = "_No response_"
REGISTRY_URL = re.compile(r"https?://[^\s\"'<>`]+")


def sections(body):
    """Split an issue-form body into {heading: value}."""
    parts = re.split(r"^###\s+(.+?)\s*$", body.replace("\r\n", "\n"), flags=re.M)
    out = {}
    for heading, value in zip(parts[1::2], parts[2::2]):
        value = value.strip()
        out[heading.strip().lower()] = "" if value == NO_RESPONSE else value
    return out


def key_values(text):
    """Parse `python=10, node: 5` style lines into {stack: value}."""
    out = {}
    for item in re.split(r"[\n,]+", text):
        item = item.strip().strip("`").strip()
        if not item:
            continue
        m = re.match(r"^([A-Za-z]+)\s*[=:]\s*(.+)$", item)
        if not m:
            raise ValueError(f"Can't parse `{item}`; expected `stack=value`.")
        out[m.group(1).lower()] = m.group(2).strip()
    return out


def parse(body):
    s = sections(body)

    raw_limit = s.get("concurrency limit", "")
    if not re.fullmatch(r"\d+", raw_limit) or int(raw_limit) < 1:
        raise ValueError(f"Concurrency limit must be a positive integer, got `{raw_limit}`.")
    limit = int(raw_limit)

    selected = [
        name.lower()
        for name in re.findall(r"^\s*-\s*\[[xX]\]\s*(\S+)", s.get("tech stacks", ""), flags=re.M)
    ]
    unknown = [x for x in selected if x not in STACKS]
    if unknown:
        raise ValueError(f"Unknown tech stack(s): {', '.join(unknown)}.")
    if not selected:
        raise ValueError("Select at least one tech stack.")

    per_stack = key_values(s.get("concurrency per stack", ""))
    deps = key_values(s.get("dependency per stack", ""))
    registries = {k: v.rstrip("/") for k, v in key_values(s.get("registry per stack", "")).items()}
    for stack, url in registries.items():
        if not REGISTRY_URL.fullmatch(url):
            raise ValueError(f"Registry for `{stack}` must be an http(s) URL, got `{url}`.")
    extra = sorted((set(per_stack) | set(deps) | set(registries)) - set(selected))
    unknown = [x for x in extra if x not in STACKS]
    if unknown:
        raise ValueError(f"Unknown tech stack(s): {', '.join(unknown)}.")

    matrix = []
    for stack in selected:
        raw = per_stack.get(stack, str(limit))
        if not re.fullmatch(r"\d+", raw) or int(raw) < 1:
            raise ValueError(f"Concurrency for `{stack}` must be a positive integer, got `{raw}`.")
        count = min(int(raw), limit)
        if count > MAX_REPOS_PER_STACK:
            raise ValueError(f"At most {MAX_REPOS_PER_STACK} repos per stack, got {count} for `{stack}`.")
        matrix.append({
            "stack": stack,
            "requested": int(raw),
            "count": count,
            "dependency": deps.get(stack),
            "registry": registries.get(stack),
            "advisory": None,
        })
    return limit, matrix


def resolve(matrix, picker=None):
    """Fill blank dependencies with a vulnerable package picked from the GitHub Advisory Database."""
    if picker is None:
        from pick_vulnerable import pick as picker
    for entry in matrix:
        if not entry["dependency"]:
            entry.update(picker(entry["stack"]))
    return matrix


def main():
    try:
        limit, matrix = parse(os.environ.get("ISSUE_BODY", ""))
        resolve(matrix)
    except (ValueError, subprocess.CalledProcessError) as e:
        print(f"::error::{e}")
        with open(os.environ.get("ERROR_FILE", "parse-error.txt"), "w") as f:
            f.write(str(e))
        sys.exit(1)

    print(json.dumps({"limit": limit, "matrix": matrix}, indent=2))
    with open(os.environ["GITHUB_OUTPUT"], "a") as f:
        f.write(f"limit={limit}\n")
        f.write(f"max_parallel={limit}\n")
        f.write(f"matrix={json.dumps(matrix)}\n")


if __name__ == "__main__":
    main()
