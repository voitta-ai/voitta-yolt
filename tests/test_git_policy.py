"""Deny-side git policy — and above all, that it never denies on a failed probe.

#97 requires this file. Its ancestor (#82) used the same probes to *grant*,
where every probe failure collapsed to a single False and meant "no grant",
so the original `ask` stood. Inverted, that collapse is a session-bricking
bug: an unset `git config user.email` would read as "not solo" and deny every
force push in the repository.

So the invariant under test is narrow and absolute:

    no probe failure, of any kind, may ever produce a deny.

Everything else here is secondary.
"""

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "hooks"))

from git_policy import (  # noqa: E402
    SHARED, SOLO, UNDETERMINED, GitDenyPolicy, GitProbe, _push_targets,
)


def fake_runner(*, git_dir=".git", common_dir=".git", branch="feature/x",
                default_branch="master", email="me@example.com",
                log_authors="me@example.com\nme@example.com",
                fail=()):
    """A stand-in for `_run_git`. `fail` names sub-probes that return None."""
    def run(directory, args):
        head = args[0]
        if head == "rev-parse" and "--git-dir" in args:
            if "state" in fail:
                return None
            return "{}\n{}\n{}\n".format(git_dir, common_dir, branch)
        if head == "symbolic-ref":
            if "default_branch" in fail:
                return None
            return "origin/{}\n".format(default_branch)
        if head == "config":
            if "email" in fail:
                return None
            return "{}\n".format(email)
        if head == "rev-parse" and "--verify" in args:
            # Two different callers use --verify, and a fixture that cannot
            # tell them apart cannot simulate either failure honestly.
            # _default_branch probes fully-qualified refs (refs/heads/main,
            # refs/remotes/origin/main); authorship probes bare ones
            # (origin/master, master).
            fully_qualified = any(a.startswith("refs/") for a in args)
            if fully_qualified:
                if "default_branch" in fail:
                    return None
            elif "base_ref" in fail:
                return None
            return "abc123\n"
        if head == "log":
            if "history" in fail:
                return None
            return log_authors + "\n"
        return ""
    return run


def policy(entries, **kw):
    probe = GitProbe(runner=fake_runner(**kw))
    # The probe consults os.path.isdir before running anything.
    return GitDenyPolicy({"enabled": True, "deny": entries}, probe=probe)


PUSH_DEFAULT = [{"argv": ["git", "push"],
                 "refuse_when": ["default_branch_target"]}]
PUSH_FORCE_SHARED = [{"argv": ["git", "push"],
                      "only_flags": ["--force", "-f"],
                      "refuse_when": ["shared_history"]}]

HERE = str(Path(__file__).resolve().parent)


class FailedProbeNeverDenies(unittest.TestCase):
    """The load-bearing invariant. Each case is a real failure mode."""

    def test_git_unavailable_or_not_a_repo(self):
        p = policy(PUSH_DEFAULT, fail=("state",))
        self.assertIsNone(p.evaluate(["git", "push"], HERE))

    def test_user_email_unset_does_not_deny_force_push(self):
        # The exact bug a verbatim port would have shipped: no user.email
        # means authorship is unknowable, not "someone else wrote it".
        p = policy(PUSH_FORCE_SHARED, fail=("email",))
        self.assertIsNone(p.evaluate(["git", "push", "--force"], HERE))

    def test_no_comparable_base_ref(self):
        p = policy(PUSH_FORCE_SHARED, fail=("base_ref",))
        self.assertIsNone(p.evaluate(["git", "push", "--force"], HERE))

    def test_unreadable_history(self):
        p = policy(PUSH_FORCE_SHARED, fail=("history",))
        self.assertIsNone(p.evaluate(["git", "push", "--force"], HERE))

    def test_default_branch_undeterminable(self):
        p = policy(PUSH_DEFAULT, fail=("default_branch",), branch="master")
        self.assertIsNone(p.evaluate(["git", "push"], HERE))

    def test_detached_head(self):
        p = policy(PUSH_DEFAULT, branch="HEAD")
        self.assertIsNone(p.evaluate(["git", "push"], HERE))

    def test_directory_unknown(self):
        p = policy(PUSH_DEFAULT)
        self.assertIsNone(p.evaluate(["git", "push"], None))

    def test_dash_c_target_with_expansion(self):
        p = policy(PUSH_DEFAULT, branch="master")
        self.assertIsNone(p.evaluate(["git", "-C", "$DIR", "push"], HERE))

    def test_env_kill_switch(self):
        os.environ["YOLT_NO_POLICIES"] = "1"
        try:
            p = policy(PUSH_DEFAULT, branch="master")
            self.assertIsNone(p.evaluate(["git", "push"], HERE))
        finally:
            del os.environ["YOLT_NO_POLICIES"]


class AuthorshipIsTriState(unittest.TestCase):
    def test_solo(self):
        probe = GitProbe(runner=fake_runner())
        self.assertEqual(probe.authorship(HERE)[0], SOLO)

    def test_shared(self):
        probe = GitProbe(runner=fake_runner(
            log_authors="me@example.com\nsomeone@else.org"))
        self.assertEqual(probe.authorship(HERE)[0], SHARED)

    def test_undetermined_is_not_shared(self):
        for mode in ("email", "base_ref", "history", "default_branch"):
            probe = GitProbe(runner=fake_runner(fail=(mode,)))
            self.assertEqual(probe.authorship(HERE)[0], UNDETERMINED, mode)


class DeniesWhenItShould(unittest.TestCase):
    def test_push_with_no_refspec_while_on_default_branch(self):
        # argv says nothing about the target; only repo state does.
        p = policy(PUSH_DEFAULT, branch="master")
        reason = p.evaluate(["git", "push", "-f"], HERE)
        self.assertIsNotNone(reason)
        self.assertIn("default branch", reason)

    def test_push_naming_the_default_branch_explicitly(self):
        p = policy(PUSH_DEFAULT, branch="feature/x")
        self.assertIsNotNone(
            p.evaluate(["git", "push", "origin", "master"], HERE))

    def test_push_all_denies_because_it_includes_the_default_branch(self):
        p = policy(PUSH_DEFAULT, branch="feature/x")
        reason = p.evaluate(["git", "push", "--all", "origin"], HERE)
        self.assertIsNotNone(reason)
        self.assertIn("every branch", reason)

    def test_explicit_default_branch_alongside_tags(self):
        p = policy(PUSH_DEFAULT, branch="feature/x")
        self.assertIsNotNone(
            p.evaluate(["git", "push", "origin", "master", "--tags"], HERE))

    def test_force_push_over_someone_elses_commits(self):
        p = policy(PUSH_FORCE_SHARED,
                   log_authors="me@example.com\nsomeone@else.org")
        reason = p.evaluate(["git", "push", "--force"], HERE)
        self.assertIsNotNone(reason)
        self.assertIn("someone@else.org", reason)


class LeavesAloneWhatItShould(unittest.TestCase):
    def test_push_to_feature_branch(self):
        p = policy(PUSH_DEFAULT, branch="feature/x")
        self.assertIsNone(p.evaluate(["git", "push"], HERE))

    def test_force_push_over_only_your_own_commits(self):
        p = policy(PUSH_FORCE_SHARED)
        self.assertIsNone(p.evaluate(["git", "push", "--force"], HERE))

    def test_non_force_push_is_outside_the_force_entry(self):
        p = policy(PUSH_FORCE_SHARED,
                   log_authors="me@example.com\nsomeone@else.org")
        self.assertIsNone(p.evaluate(["git", "push"], HERE))

    def test_unmatched_argv(self):
        p = policy(PUSH_DEFAULT, branch="master")
        self.assertIsNone(p.evaluate(["git", "status"], HERE))


class PushTargetResolution(unittest.TestCase):
    def test_no_refspec_uses_current_branch(self):
        self.assertEqual(_push_targets(["git", "push", "-f"], "master"),
                         {"master"})

    def test_explicit_refspec(self):
        self.assertEqual(
            _push_targets(["git", "push", "origin", "master"], "feat"),
            {"master"})

    def test_src_colon_dst_uses_the_destination(self):
        self.assertEqual(
            _push_targets(["git", "push", "origin", "HEAD:master"], "feat"),
            {"master"})

    def test_every_refspec_counts_not_just_the_last(self):
        # From the adversarial review on #122. Taking only the last refspec
        # let `git push origin master feature/x` past the default-branch
        # guard, because the guard only ever saw `feature/x`.
        self.assertEqual(
            _push_targets(["git", "push", "origin", "master", "feature/x"],
                          "feature/x"),
            {"master", "feature/x"})

    def test_refs_heads_is_normalised(self):
        self.assertEqual(
            _push_targets(["git", "push", "origin", "refs/heads/master"],
                          "feat"),
            {"master"})

    def test_tag_ref_is_not_a_branch(self):
        self.assertIsNone(
            _push_targets(["git", "push", "origin", "refs/tags/v1"], "feat"))

    def test_tags_does_not_suppress_an_explicit_refspec(self):
        # From the re-review on #122, and a bug the *previous* fix
        # introduced: lumping --tags in with --all made
        # `git push origin master --tags` unresolvable, so the
        # default-branch guard stopped seeing the explicit `master`.
        for argv in (["git", "push", "origin", "master", "--tags"],
                     ["git", "push", "--tags", "origin", "master"]):
            self.assertEqual(_push_targets(argv, "feat"), {"master"}, argv)

    def test_tags_alone_touches_no_branch(self):
        self.assertIsNone(_push_targets(["git", "push", "--tags"], "feat"))

    def test_all_and_mirror_include_every_branch(self):
        for flag in ("--all", "--mirror"):
            targets = _push_targets(["git", "push", flag, "origin"], "feat")
            self.assertIn("*", targets, flag)

    def test_expansion_is_unresolvable(self):
        self.assertIsNone(
            _push_targets(["git", "push", "origin", "$B"], "feat"))


if __name__ == "__main__":
    unittest.main()


class ThroughTheClassifier(unittest.TestCase):
    """Drive the deny path through GrammarClassifier, not just the policy.

    The unit tests above call GitDenyPolicy directly, which meant three
    separate wiring bugs -- an unimported DECISION_DENY in two modules and a
    `cd` hook that never landed -- passed every one of them while the hook
    crashed or silently ignored a `cd`. Anything that only exercises the
    policy object cannot see the wiring.
    """

    def _classifier(self, cwd, **kw):
        import json
        from grammar_classifier import GrammarClassifier
        from rule_classifier import load_shell_rules
        rules_dir = Path(__file__).resolve().parent.parent / "rules"
        rules = load_shell_rules(rules_dir=rules_dir)
        probe = GitProbe(runner=fake_runner(**kw))
        policy = GitDenyPolicy(rules["policies"]["git"], probe=probe)
        return GrammarClassifier(rules, cwd=cwd, policy=policy)

    def test_deny_reaches_the_decision(self):
        c = self._classifier(HERE, branch="master")
        decision, reason = c.classify("git push")
        self.assertEqual(decision, "deny")
        self.assertIn("default branch", reason)

    def test_feature_branch_still_only_asks(self):
        c = self._classifier(HERE, branch="feature/x")
        self.assertEqual(c.classify("git push")[0], "unsafe")

    def test_cd_moves_the_judged_directory(self):
        # `cd` to a tracked path, then push. Without cd tracking the policy
        # judges the wrong tree and the deny never fires.
        c = self._classifier("/nonexistent-start", branch="master")
        decision, _reason = c.classify("cd {} && git push".format(HERE))
        self.assertEqual(decision, "deny")

    def test_unresolvable_cd_disables_the_policy(self):
        c = self._classifier(HERE, branch="master")
        self.assertEqual(c.classify("cd $D && git push")[0], "unsafe")

    def test_deny_outranks_unsafe_siblings(self):
        c = self._classifier(HERE, branch="master")
        self.assertEqual(c.classify("rm -rf /tmp/x && git push")[0], "deny")
