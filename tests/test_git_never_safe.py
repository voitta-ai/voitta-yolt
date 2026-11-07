"""Guard: no git command is ever classified `safe`.

A git read is not a read of fixed data. It loads a repository's config and
acts on it, so what it does depends on which repository it loads, and a
static classifier cannot vouch for that. In the hook this costs nothing,
because `safe` and `unknown` are the same silent exit. A CLI consumer that
auto-runs `safe` is different: it would skip its own check for that command.
So git reads are delegated, and these tests fail on any rule change that
would make one `safe`.

Two layers:

  - Structural: the bundled `git` spec carries no key that can produce
    `safe`. This catches a new rule before anyone thinks to probe it.
  - Behavioral: a sweep of read-shaped subcommands, global options and
    wrappers through the real classifier never comes back `safe`.
"""

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
HOOKS_DIR = REPO_ROOT / "hooks"
sys.path.insert(0, str(HOOKS_DIR))

from grammar_classifier import GrammarClassifier  # noqa: E402
from rule_classifier import DECISION_SAFE, load_shell_rules  # noqa: E402
from yolt_analyzer import SafetyAnalyzer, load_rules as load_py_rules  # noqa: E402


SUBCOMMANDS = (
    "status", "log", "diff", "show", "rev-parse HEAD", "describe",
    "shortlog", "show-ref", "ls-files", "ls-tree HEAD", "cat-file -p HEAD",
    "blame f", "name-rev HEAD", "reflog", "worktree list", "remote -v",
    "branch -a", "tag --list", "stash list", "ls-remote", "merge-base HEAD x",
    "cherry -v", "for-each-ref", "grep x", "config --get user.email",
    "version", "help", "count-objects", "fsck", "fetch", "pull",
)

PREFIXES = (
    "", "--no-pager ", "-C x ", "--git-dir=y ", "--work-tree=x ",
    "--exec-path=/tmp ", "-c color.ui=never ", "--bare ",
)

WRAPPERS = (
    "{}", "/usr/bin/{}", "cd x && {}", "command {}", "env {}",
    "bash -c '{}'", "echo $({})",
)


def _walk(node, path=()):
    """Yield (path, key, value) for every key in a nested dict."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield path, k, v
            yield from _walk(v, path + (k,))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk(v, path + (i,))


class GitNeverSafeTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.shell_rules = load_shell_rules(REPO_ROOT / "rules")
        py_rules = load_py_rules(REPO_ROOT / "rules")
        cls.clf = GrammarClassifier(
            cls.shell_rules,
            python_analyzer_factory=lambda: SafetyAnalyzer(py_rules),
        )

    def test_git_spec_has_no_safe_source(self):
        spec = self.shell_rules["commands"]["git"]
        offenders = []
        for path, k, v in _walk(spec):
            if isinstance(k, str) and k.startswith("safe") and v:
                offenders.append((path, k))
            elif v == DECISION_SAFE:
                offenders.append((path, k))
        self.assertEqual(offenders, [])

    def test_git_reads_never_classify_safe(self):
        offenders = []
        for sub in SUBCOMMANDS:
            for prefix in PREFIXES:
                git = "git " + prefix + sub
                for wrap in WRAPPERS:
                    cmd = wrap.format(git)
                    decision, reason = self.clf.classify(cmd)
                    if decision == DECISION_SAFE:
                        offenders.append((cmd, reason))
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
