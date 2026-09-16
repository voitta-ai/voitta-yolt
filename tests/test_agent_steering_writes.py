"""Writes that steer the agent must not classify `safe`.

#121. `rules/shell.json` listed `~/.claude/*` in `safe_write_targets` and
named only `settings.json` and `settings.local.json` in
`unsafe_write_targets`, so a write into `~/.claude/skills/`, `agents/`,
`hooks/`, `commands/` or `plugins/` -- or a project `.mcp.json` -- exited
silently with no opinion.

The rules file already stated the principle for the one path it applied it
to: settings.json is unsafe *because it can disable this hook*. A skill file
is read into the model's context on every later turn, an agent definition
carries tool grants, and files under `hooks/` are executed by the host. Same
property, same treatment.

The tests that matter here are the pairs: the steering path is refused AND
the ordinary path beside it is untouched. A guard that flips everything
under `~/.claude` would pass half of this file and be useless.
"""

import sys
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parent.parent / "hooks"
RULES = Path(__file__).resolve().parent.parent / "rules"
sys.path.insert(0, str(HOOKS))

from grammar_classifier import GrammarClassifier  # noqa: E402
from rule_classifier import load_shell_rules  # noqa: E402
from yolt_analyzer import SafetyAnalyzer, load_rules  # noqa: E402


def classify(command):
    rules = load_shell_rules(rules_dir=RULES)
    py_rules = load_rules(rules_dir=RULES)
    classifier = GrammarClassifier(
        rules, python_analyzer_factory=lambda: SafetyAnalyzer(py_rules)
    )
    retval = classifier.classify(command)[0]
    return retval


class SteeringWritesAreRefused(unittest.TestCase):
    """Each of these is a path that changes what the agent does next."""

    def test_skill_file(self):
        self.assertEqual(
            classify("echo x > ~/.claude/skills/evil/SKILL.md"), "unsafe")

    def test_agent_definition(self):
        self.assertEqual(
            classify("echo x > ~/.claude/agents/thing.md"), "unsafe")

    def test_slash_command(self):
        self.assertEqual(
            classify("echo x > ~/.claude/commands/deploy.md"), "unsafe")

    def test_hook_script(self):
        self.assertEqual(
            classify("echo x > ~/.claude/hooks/pre-tool-use.sh"), "unsafe")

    def test_plugin_cache(self):
        self.assertEqual(
            classify("echo x > ~/.claude/plugins/cache/p/1.0/hooks/h.sh"),
            "unsafe")

    def test_global_claude_md(self):
        self.assertEqual(classify("echo x > ~/.claude/CLAUDE.md"), "unsafe")

    def test_project_mcp_config(self):
        self.assertEqual(classify("echo x > .mcp.json"), "unsafe")

    def test_nested_mcp_config(self):
        self.assertEqual(classify("echo x > sub/dir/.mcp.json"), "unsafe")

    def test_codex_config(self):
        self.assertEqual(classify("echo x > ~/.codex/config.toml"), "unsafe")

    def test_codex_hooks(self):
        self.assertEqual(classify("echo x > ~/.codex/hooks.json"), "unsafe")

    def test_settings_still_covered(self):
        # Pre-existing; asserted so a future edit to the list cannot drop it.
        self.assertEqual(
            classify("echo x > ~/.claude/settings.json"), "unsafe")


class BothHostsAreCoveredSymmetrically(unittest.TestCase):
    """The Claude side and the Codex side must protect the same shapes.

    The first draft of this list protected `agents/`, `commands/`, `hooks/`
    and `plugins/` under `~/.claude` but only four files under `~/.codex`.
    An agent definition steers whichever host reads it, so a list that
    protects one and not the other is not a policy, it is an oversight with
    a plausible shape.
    """

    def test_codex_agents(self):
        self.assertEqual(
            classify("echo x > ~/.codex/agents/thing.md"), "unsafe")

    def test_codex_prompts(self):
        self.assertEqual(
            classify("echo x > ~/.codex/prompts/p.md"), "unsafe")

    def test_codex_plugins(self):
        self.assertEqual(
            classify("echo x > ~/.codex/plugins/p/hook.sh"), "unsafe")

    def test_codex_rules(self):
        self.assertEqual(
            classify("echo x > ~/.codex/rules/r.json"), "unsafe")

    def test_codex_memories(self):
        self.assertEqual(
            classify("echo x > ~/.codex/memories/m.json"), "unsafe")

    def test_codex_auth_matches_the_other_credential_stores(self):
        # Listed on the same grounds as ~/.aws/credentials and ~/.netrc,
        # which were already here. Omitting it would be the same asymmetry
        # one category over.
        self.assertEqual(classify("echo x > ~/.codex/auth.json"), "unsafe")


class HostExecutedFilesAreCovered(unittest.TestCase):
    """Anything the host runs is a hook by another name."""

    def test_statusline_command(self):
        # settings.json points `statusLine.command` at this file and the
        # host executes it on every render. Same execution surface as
        # ~/.claude/hooks/, and it was not on the first draft of the list.
        self.assertEqual(
            classify("echo x > ~/.claude/statusline-command.sh"), "unsafe")

    def test_mcp_server_definitions(self):
        self.assertEqual(
            classify("echo x > ~/.claude/mcp-servers/s.json"), "unsafe")


class OrdinaryWritesAreUntouched(unittest.TestCase):
    """The other half. A guard that flips all of ~/.claude is not a guard."""

    def test_yolt_own_state_stays_safe(self):
        self.assertEqual(
            classify("echo x > ~/.claude/yolt/cache.json"), "safe")

    def test_claude_log_stays_safe(self):
        self.assertEqual(classify("echo x > ~/.claude/yolt.log"), "safe")

    def test_tmp_stays_safe(self):
        self.assertEqual(classify("echo x > /tmp/scratch"), "safe")

    def test_agent_state_and_logs_are_never_carded(self):
        """Ordinary agent state must not be flipped to `unsafe` by this list.

        Asserts `!= unsafe`, not `== safe`, and the difference is the point.
        `~/.claude/*` is a safe-write target so paths under it are `safe`,
        but `~/.codex/*` is not, so paths under it are `unknown` -- which
        also does not card. Asserting `== safe` here would be asserting an
        accident of which host's tree the file is in.

        An earlier revision did assert `== safe` and passed locally while
        failing CI. Cause worth recording: `mktemp -d` on macOS returns a
        path under `/var/folders`, and `/var/folders/*` is itself in
        `safe_write_targets`, so running the suite with
        `HOME=$(mktemp -d)` makes EVERY path under HOME classify `safe`.
        The local run was measuring the temp directory's location, not the
        rules.
        """
        for path in ("~/.claude/history.jsonl",
                     "~/.codex/logs_2.sqlite",
                     "~/.codex/sessions/s.jsonl"):
            self.assertNotEqual(
                classify("echo x > {}".format(path)), "unsafe", path)

    def test_claude_tree_state_is_positively_safe(self):
        # `~/.claude/*` IS a safe-write target, so this one is `safe` rather
        # than merely not-unsafe, and the specific entries added by this PR
        # must not have swallowed the broader glob.
        self.assertEqual(classify("echo x > ~/.claude/history.jsonl"), "safe")
        self.assertEqual(classify("echo x > ~/.claude/yolt/cache.json"), "safe")

    def test_reading_a_skill_is_not_a_write(self):
        self.assertIn(
            classify("cat ~/.claude/skills/x/SKILL.md"),
            ("safe", "unknown"))

    def test_listing_the_skills_dir_is_not_a_write(self):
        self.assertIn(classify("ls ~/.claude/skills"), ("safe", "unknown"))


class WriteVerbsAlsoRouteThroughTheList(unittest.TestCase):
    """`unsafe_write_targets` covers the write-target arguments of
    tee/cp/mv/install/dd, not redirects alone.

    The docstring used to claim `find` as well. Phase 3 (#100) dropped
    `find`'s `write_flag_value_targets` (`-fprint`/`-fprintf`/`-fls`)
    because that field consults `safe_write_targets`, i.e. whitelist
    semantics, which is what the phase retires -- so a `find -fprint` into
    a steering path is genuinely no longer flagged. Recorded here rather
    than left as a stale claim.
    """

    def test_tee(self):
        self.assertEqual(
            classify("tee ~/.claude/agents/x.md < /dev/null"), "unsafe")

    def test_cp(self):
        self.assertEqual(
            classify("cp /tmp/x ~/.claude/hooks/pre-tool-use.sh"), "unsafe")

    def test_mv(self):
        self.assertEqual(
            classify("mv /tmp/x ~/.claude/skills/y/SKILL.md"), "unsafe")

    def test_install(self):
        self.assertEqual(
            classify("install -m 644 /tmp/x ~/.claude/skills/y/SKILL.md"),
            "unsafe")

    def test_dd(self):
        self.assertEqual(
            classify("dd if=/dev/zero of=~/.codex/config.toml"), "unsafe")


class WriteVerbsOnOrdinaryTargetsAreDelegated(unittest.TestCase):
    """The other half of the pair, and the half that regressed twice.

    Phase 3 (#100) first DELETED these commands, which did not delegate
    them -- it deleted the steering-path coverage above, because the check
    is re-derived at each command site rather than living at one choke
    point (#136). They came back with `default: "ask"`, which consults the
    deny list only.

    So the standing requirement is two-sided: a protected destination
    still classifies, and an ordinary one now classifies `unknown` where
    before Phase 3 it was unconditionally `unsafe`. Asserting only the
    first half would pass against `default: "unsafe"` -- the pre-Phase-3
    behaviour this phase exists to remove.
    """

    def test_ordinary_cp_is_delegated(self):
        self.assertIn(classify("cp /tmp/a /tmp/b"), ("safe", "unknown"))

    def test_ordinary_mv_is_delegated(self):
        self.assertIn(classify("mv /tmp/a /tmp/b"), ("safe", "unknown"))

    def test_ordinary_tee_is_delegated(self):
        self.assertIn(classify("tee /tmp/out.txt"), ("safe", "unknown"))

    def test_ordinary_install_is_delegated(self):
        self.assertIn(
            classify("install -m 644 /tmp/a /tmp/build/a"),
            ("safe", "unknown"))

    def test_ordinary_dd_is_delegated(self):
        self.assertIn(classify("dd if=/tmp/a of=/tmp/b"), ("safe", "unknown"))


if __name__ == "__main__":
    unittest.main()
