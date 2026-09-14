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


class OrdinaryWritesAreUntouched(unittest.TestCase):
    """The other half. A guard that flips all of ~/.claude is not a guard."""

    def test_yolt_own_state_stays_safe(self):
        self.assertEqual(
            classify("echo x > ~/.claude/yolt/cache.json"), "safe")

    def test_claude_log_stays_safe(self):
        self.assertEqual(classify("echo x > ~/.claude/yolt.log"), "safe")

    def test_tmp_stays_safe(self):
        self.assertEqual(classify("echo x > /tmp/scratch"), "safe")

    def test_reading_a_skill_is_not_a_write(self):
        self.assertEqual(
            classify("cat ~/.claude/skills/x/SKILL.md"), "safe")

    def test_listing_the_skills_dir_is_not_a_write(self):
        self.assertEqual(classify("ls ~/.claude/skills"), "safe")


class WriteVerbsAlsoRouteThroughTheList(unittest.TestCase):
    """`unsafe_write_targets` covers redirects and the write-target
    arguments of tee/cp/mv/install/dd/find, not redirects alone."""

    def test_tee(self):
        self.assertEqual(
            classify("tee ~/.claude/agents/x.md < /dev/null"), "unsafe")

    def test_cp(self):
        self.assertEqual(
            classify("cp /tmp/x ~/.claude/hooks/pre-tool-use.sh"), "unsafe")

    def test_mv(self):
        self.assertEqual(
            classify("mv /tmp/x ~/.claude/skills/y/SKILL.md"), "unsafe")


if __name__ == "__main__":
    unittest.main()
