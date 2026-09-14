"""A write target spelled with a variable must not evade the deny list.

#128. `_redirect_write_target` read only `word` and `string` nodes, but
tree-sitter parses `> $HOME/path` as a `concatenation`. Neither branch
matched, the target stayed None, and the caller read None as "not a write
redirect" -- so the redirect was dropped from consideration and the line was
judged on `echo` alone.

On master that produced `permissionDecision: allow`, so YOLT actively granted
a write to `$HOME/.ssh/authorized_keys` while asking about the identical
`~/.ssh/authorized_keys`.

Two things are under test, and the second is the one that matters in a year:

1. the spellings that were open are closed;
2. a write redirect whose target CANNOT be read costs friction rather than
   silence, so the next unanticipated node shape is a prompt, not a grant.
"""

import sys
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parent.parent / "hooks"
RULES = Path(__file__).resolve().parent.parent / "rules"
sys.path.insert(0, str(HOOKS))

from grammar_classifier import (  # noqa: E402
    UNEXTRACTABLE_WRITE_TARGET, GrammarClassifier,
)
from rule_classifier import _expand_home, load_shell_rules  # noqa: E402
from yolt_analyzer import SafetyAnalyzer, load_rules  # noqa: E402


def classify(command):
    rules = load_shell_rules(rules_dir=RULES)
    py_rules = load_rules(rules_dir=RULES)
    classifier = GrammarClassifier(
        rules, python_analyzer_factory=lambda: SafetyAnalyzer(py_rules)
    )
    retval = classifier.classify(command)[0]
    return retval


class SpellingCannotEvadeTheDenyList(unittest.TestCase):
    """Every one of these was `safe`, and granted, before #128."""

    def test_home_variable_ssh_keys(self):
        self.assertEqual(
            classify("echo x > $HOME/.ssh/authorized_keys"), "unsafe")

    def test_braced_home_variable(self):
        self.assertEqual(
            classify("echo x > ${HOME}/.claude/settings.json"), "unsafe")

    def test_home_variable_aws_credentials(self):
        self.assertEqual(
            classify("echo x > $HOME/.aws/credentials"), "unsafe")

    def test_home_variable_bashrc(self):
        self.assertEqual(classify("echo x > $HOME/.bashrc"), "unsafe")

    def test_duplicate_slash(self):
        self.assertEqual(
            classify("echo x > ~/.claude//settings.json"), "unsafe")

    def test_traversal_lands_on_the_entry_it_passes_through(self):
        self.assertEqual(classify("echo x > ~/.claude/../.bashrc"), "unsafe")

    def test_tilde_still_works(self):
        # The spelling that always worked, asserted so a normaliser change
        # cannot trade one for the other.
        self.assertEqual(
            classify("echo x > ~/.ssh/authorized_keys"), "unsafe")

    def test_append_redirect_too(self):
        self.assertEqual(
            classify("echo x >> $HOME/.ssh/authorized_keys"), "unsafe")


class UnreadableTargetCostsFriction(unittest.TestCase):
    """The structural half: unreadable is not the same as absent."""

    def test_bare_variable_target_is_not_safe(self):
        self.assertNotEqual(classify("echo x > $OUT"), "safe")

    def test_sentinel_is_distinct_from_none(self):
        # None means "not a write redirect". Conflating the two is what
        # turned an unreadable target into a grant.
        self.assertIsNotNone(UNEXTRACTABLE_WRITE_TARGET)
        self.assertIsNot(UNEXTRACTABLE_WRITE_TARGET, None)

    def test_unreadable_target_downgrades_the_whole_statement(self):
        classifier = GrammarClassifier(
            load_shell_rules(rules_dir=RULES),
            python_analyzer_factory=lambda: SafetyAnalyzer(
                load_rules(rules_dir=RULES)),
        )
        original = classifier._redirect_write_target
        classifier._redirect_write_target = (
            lambda node, src: UNEXTRACTABLE_WRITE_TARGET)
        try:
            # `echo` alone is safe; the unreadable redirect must stop that.
            self.assertEqual(
                classifier.classify("echo hello > /tmp/ok")[0], "unknown")
        finally:
            classifier._redirect_write_target = original


class NormaliserKeepsOrdinaryPathsAlone(unittest.TestCase):
    def test_tmp_stays_safe(self):
        self.assertEqual(classify("echo x > /tmp/scratch"), "safe")

    def test_home_variable_to_a_safe_path_stays_safe(self):
        self.assertEqual(classify("echo x > $HOME/.cache/thing"), "safe")

    def test_no_redirect_is_unaffected(self):
        self.assertEqual(classify("echo hello"), "safe")

    def test_expand_home_is_idempotent(self):
        once = _expand_home("$HOME/.ssh/id_rsa")
        self.assertEqual(_expand_home(once), once)

    def test_expand_home_leaves_unknown_variables(self):
        self.assertIn("$OTHER", _expand_home("$OTHER/x"))


if __name__ == "__main__":
    unittest.main()
