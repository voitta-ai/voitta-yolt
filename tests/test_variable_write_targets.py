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

import os
import sys
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parent.parent / "hooks"
RULES = Path(__file__).resolve().parent.parent / "rules"
sys.path.insert(0, str(HOOKS))

HOME = os.path.expanduser("~")

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


class RedirectMustNotMaskTheCommand(unittest.TestCase):
    """An unclassifiable redirect target must not hide a dangerous command.

    `_walk_redirected` returned as soon as a write target was not known-safe,
    so the command itself was never classified. That was latent: before #128
    an unreadable target was dropped, `write_targets` came back empty, and the
    command got classified by accident. Reading the target correctly exposed
    it -- measured on the dogfood corpus, two real
    `terraform destroy -auto-approve > $LOG` lines went from `unsafe` to
    `unknown`, which is a destructive command losing its prompt.

    Aggregation already ranks unsafe above unknown. The bug was the early
    return, not the precedence.
    """

    def test_destroy_survives_an_unreadable_redirect(self):
        self.assertEqual(
            classify("terraform destroy -auto-approve > $SC/run.log 2>&1"),
            "unsafe")

    def test_rm_survives_an_unreadable_redirect(self):
        self.assertEqual(classify("rm -rf /tmp/x > $LOG"), "unsafe")

    def test_harmless_command_still_reports_the_redirect(self):
        # The unknown verdict is still produced when nothing outranks it.
        self.assertEqual(classify("echo hi > $LOG"), "unknown")

    def test_protected_target_still_wins_over_a_safe_command(self):
        self.assertEqual(
            classify("echo x > $HOME/.ssh/authorized_keys"), "unsafe")


class RedirectAndCommandBothReport(unittest.TestCase):
    """Neither branch of the redirect walk may mask the other's reason.

    Raised by review r2 on #129: the unsafe branch still returned early
    while the unknown branch had been fixed to fall through, so
    `rm -rf /tmp/x > ~/.bashrc` reported only the redirect and never
    `rm: mutating`.

    The verdict was `unsafe` either way, so this was never a security gap.
    The reason is not decoration though: `scripts/replay_unsafe.py` groups
    the corpus BY reason and #100 drafts the non-delegable list from that
    grouping, so a masked `rm: mutating` under-counts rm in the measurement
    that decides what Phase 3 deletes.
    """

    def _reason(self, command):
        rules = load_shell_rules(rules_dir=RULES)
        py_rules = load_rules(rules_dir=RULES)
        c = GrammarClassifier(
            rules, python_analyzer_factory=lambda: SafetyAnalyzer(py_rules))
        retval = c.classify(command)
        return retval

    def test_destructive_command_survives_a_protected_redirect(self):
        decision, reason = self._reason("rm -rf /tmp/x > ~/.bashrc")
        self.assertEqual(decision, "unsafe")
        self.assertIn("~/.bashrc", reason)
        self.assertIn("rm: mutating", reason)

    def test_destroy_survives_a_protected_redirect(self):
        decision, reason = self._reason(
            "terraform destroy -auto-approve > ~/.ssh/authorized_keys")
        self.assertEqual(decision, "unsafe")
        self.assertIn("authorized_keys", reason)
        self.assertIn("terraform destroy", reason)

    def test_safe_command_contributes_no_extra_reason(self):
        decision, reason = self._reason("echo hi > ~/.bashrc")
        self.assertEqual(decision, "unsafe")
        self.assertNotIn(";", reason)

    def test_identical_reasons_are_not_repeated(self):
        # `echo a > $X; echo b > $Y` produced the same sentence twice.
        decision, reason = self._reason("echo a > $X; echo b > $Y")
        self.assertEqual(decision, "unknown")
        self.assertEqual(reason.count("writes to a file via redirection"), 1)


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


class HeredocRedirectTargetIsSeen(unittest.TestCase):
    """A heredoc nests its redirect deeper, and the scan used to miss it.

    #136. tree-sitter puts the `file_redirect` inside the `heredoc_redirect`
    rather than beside it:

        redirected_statement
          command            'cat'
          heredoc_redirect   "<<'X' > ~/.ssh/authorized_keys"
            file_redirect      '> ~/.ssh/authorized_keys'

    The walker scanned direct children only, so the target never reached the
    deny list, the statement was judged on the verb, and `cat` reported
    `read-only` for a command installing an SSH key. The hook granted it.

    Third route into one outcome, after #128's `$HOME` spelling and the
    single-quoted `raw_string` gap: a write target that never reaches the
    deny list.
    """

    def test_cat_heredoc_into_authorized_keys(self):
        self.assertEqual(
            classify("cat <<'XX' > ~/.ssh/authorized_keys\nssh-rsa AAAA\nXX"),
            "unsafe")

    def test_python_heredoc_into_bashrc(self):
        self.assertEqual(
            classify("python3 <<'XX' > ~/.bashrc\nimport os\nXX"), "unsafe")

    def test_heredoc_into_a_benign_target_stays_safe(self):
        self.assertIn(
            classify("cat <<'XX' > /tmp/ok\nhello\nXX"),
            ("safe", "unknown"))

    def test_heredoc_with_no_redirect_is_unaffected(self):
        self.assertIn(classify("cat <<'XX'\nhello\nXX"), ("safe", "unknown"))

    def test_destructive_heredoc_body_still_reported(self):
        # The body analysis must survive the redirect fix, not be replaced
        # by it.
        self.assertEqual(
            classify("python3 <<'XX' > /tmp/ok\n"
                     "import shutil\nshutil.rmtree('/')\nXX"), "unsafe")


class SingleQuotedTargetIsSeen(unittest.TestCase):
    """Quoting a protected path used to be enough to lose the prompt.

    #132. A single-quoted target parses as `raw_string`, which matched no
    branch in `_redirect_write_target`, so the target stayed None and the
    statement classified `unknown` -- silent, rather than the `ask` the same
    path gets when written bare or double-quoted.

    Fourth and last of the known routes into one outcome, after #128's
    `$HOME` spelling, #136's heredoc nesting, and the function-body gap
    recorded on #136: a write target that never reaches the deny list.
    """

    def test_single_quoted_protected_path(self):
        self.assertEqual(
            classify("echo x > '{}/.ssh/authorized_keys'".format(HOME)),
            "unsafe")

    def test_single_quoted_bashrc(self):
        self.assertEqual(
            classify("echo x > '{}/.bashrc'".format(HOME)), "unsafe")

    def test_quoting_does_not_change_the_verdict(self):
        # The point of the fix: three spellings of one path, one answer.
        bare = classify("echo x > ~/.ssh/authorized_keys")
        dq = classify('echo x > "{}/.ssh/authorized_keys"'.format(HOME))
        sq = classify("echo x > '{}/.ssh/authorized_keys'".format(HOME))
        self.assertEqual(bare, "unsafe")
        self.assertEqual(dq, "unsafe")
        self.assertEqual(sq, "unsafe")

    def test_single_quoted_benign_target_stays_safe(self):
        self.assertEqual(classify("echo x > '/tmp/ok'"), "safe")

    def test_single_quotes_are_what_make_spaces_usable(self):
        # The reason people single-quote paths at all. Must not card.
        self.assertEqual(classify("echo x > '/tmp/my file'"), "safe")

    def test_composes_with_the_heredoc_fix(self):
        self.assertEqual(
            classify("cat <<'XX' > '{}/.bashrc'\nk\nXX".format(HOME)),
            "unsafe")
