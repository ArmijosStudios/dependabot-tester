"""Tech stack registry and repo naming shared by every script."""

import re

STACKS = {
    "python": {"ecosystem": "pip", "advisory_ecosystem": "pip", "file": "requirements.txt",
               "registry_type": "python-index"},
    "node": {"ecosystem": "npm", "advisory_ecosystem": "npm", "file": "package.json",
             "registry_type": "npm-registry"},
    "ruby": {"ecosystem": "bundler", "advisory_ecosystem": "rubygems", "file": "Gemfile",
             "registry_type": "rubygems-server"},
    "go": {"ecosystem": "gomod", "advisory_ecosystem": "go", "file": "go.mod",
           "registry_type": "goproxy-server"},
}

MAX_REPOS_PER_STACK = 200
TOPIC = "dependabot-tester"
# Topics older generated repos were stamped with; cleanup still accepts them.
LEGACY_TOPICS = ("issue-repo-dependency-updater",)
# Former names of this repo; generated repo descriptions link to issues under them.
LEGACY_SOURCE_REPOS = ("issue-repo-dependency-updater",)


def repo_name(stack, index):
    """(`python`, 1) -> `python-01`, (`python`, 150) -> `python-150`."""
    return f"{stack}-{index:02d}"


def repo_index(stack, name):
    """`python-07` -> 7; None for names that aren't `<stack>-<number>`."""
    m = re.fullmatch(rf"{re.escape(stack)}-(\d+)", name)
    return int(m.group(1)) if m else None


def repo_key(name):
    """Sort key that puts `python-99` before `python-100`."""
    prefix, _, num = name.rpartition("-")
    return (prefix, int(num)) if num.isdigit() else (name, -1)
