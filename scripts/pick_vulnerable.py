"""Pick a dependency with a critical/high GitHub advisory that Dependabot can fix.

Usage: pick_vulnerable.py STACK

Searches reviewed, non-withdrawn advisories in the GitHub Advisory Database
(critical first, then high, newest first) for the stack's ecosystem. A candidate
must have a `first_patched_version` (so Dependabot can open a security PR) and a
stable release in the registry inside the vulnerable range. The highest such
release is pinned. Every generated repo is brand new, so there is no earlier
Dependabot PR or alert to collide with. Advisories are read with the `gh` CLI
(GH_TOKEN); registries are public.
"""

import argparse
import json
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

from stacks import STACKS

SEVERITIES = ("critical", "high")
MAX_REGISTRY_LOOKUPS = 40
STABLE = re.compile(r"^v?\d+(\.\d+)*(\+incompatible)?$")


def vkey(version):
    """Sortable key; pre-releases sort just below their release."""
    v = version.strip().lstrip("v").split("+")[0]
    m = re.match(r"^(\d+(?:\.\d+)*)(.*)$", v)
    if not m:
        return None
    nums = [int(x) for x in m.group(1).split(".")][:6]
    return tuple(nums + [0] * (6 - len(nums))) + ((0,) if not m.group(2) else (-1,))


def in_range(version, spec):
    """True if version satisfies an advisory range like `>= 1.0, < 1.2.3`."""
    key = vkey(version)
    if key is None:
        return False
    for part in spec.split(","):
        m = re.match(r"^\s*(>=|<=|>|<|=)?\s*(\S+)\s*$", part)
        if not m:
            return False
        op, bound = m.group(1) or "=", vkey(m.group(2))
        if bound is None:
            return False
        if not {">=": key >= bound, "<=": key <= bound, ">": key > bound,
                "<": key < bound, "=": key == bound}[op]:
            return False
    return True


def fetch_json(url, headers=None):
    req = urllib.request.Request(url, headers={"User-Agent": "dependabot-tester", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.load(resp)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, ValueError):
        return None


def fetch_text(url):
    req = urllib.request.Request(url, headers={"User-Agent": "dependabot-tester"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.read().decode()
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
        return None


def registry_versions(stack, name):
    if stack == "python":
        data = fetch_json(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json")
        if not data:
            return []
        return [v for v, files in data.get("releases", {}).items()
                if files and not all(f.get("yanked") for f in files)]
    if stack == "node":
        data = fetch_json(f"https://registry.npmjs.org/{name.replace('/', '%2f')}",
                          {"Accept": "application/vnd.npm.install-v1+json"})
        return list((data or {}).get("versions", {}))
    if stack == "ruby":
        data = fetch_json(f"https://rubygems.org/api/v1/versions/{urllib.parse.quote(name)}.json")
        return sorted({v["number"] for v in data or [] if not v.get("prerelease")})
    if stack == "go":
        escaped = re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), name)
        text = fetch_text(f"https://proxy.golang.org/{escaped}/@v/list")
        return (text or "").split()
    raise ValueError(stack)


def advisories(ecosystem, severity):
    path = (f"advisories?ecosystem={ecosystem}&severity={severity}&type=reviewed"
            "&per_page=100&sort=published&direction=desc")
    out = subprocess.run(["gh", "api", path], check=True, capture_output=True, text=True).stdout
    return json.loads(out)


def spec_for(stack, name, version):
    if stack == "python":
        return f"{name}=={version}"
    if stack == "go":
        return f"{name}@v{version.lstrip('v')}"
    return f"{name}@{version}"


def pick(stack, get_advisories=advisories, get_versions=registry_versions):
    eco = STACKS[stack]["advisory_ecosystem"]
    lookups = 0
    for severity in SEVERITIES:
        for adv in get_advisories(eco, severity):
            if adv.get("withdrawn_at"):
                continue
            for vuln in adv.get("vulnerabilities") or []:
                pkg = vuln.get("package") or {}
                name, patched, rng = pkg.get("name"), vuln.get("first_patched_version"), vuln.get("vulnerable_version_range")
                if pkg.get("ecosystem") != eco or not name or not patched or not rng:
                    continue
                if lookups >= MAX_REGISTRY_LOOKUPS:
                    raise ValueError(f"No suitable critical/high {eco} advisory found in {lookups} registry lookups.")
                lookups += 1
                patched_key = vkey(patched)
                vulnerable = [v for v in get_versions(stack, name)
                              if STABLE.match(v) and in_range(v, rng)
                              and (patched_key is None or vkey(v) < patched_key)]
                if not vulnerable:
                    continue
                version = max(vulnerable, key=vkey)
                return {
                    "dependency": spec_for(stack, name, version),
                    "advisory": {
                        "ghsa": adv["ghsa_id"],
                        "cve": adv.get("cve_id"),
                        "severity": adv["severity"],
                        "summary": adv.get("summary", ""),
                        "url": adv["html_url"],
                        "vulnerable_range": rng,
                        "patched": patched,
                    },
                }
    raise ValueError(f"No suitable critical/high {eco} advisory with a patched version was found.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("stack", choices=sorted(STACKS))
    args = ap.parse_args()
    try:
        print(json.dumps(pick(args.stack), indent=2))
    except ValueError as e:
        sys.exit(str(e))


if __name__ == "__main__":
    main()
