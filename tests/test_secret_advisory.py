"""Tests for the PreToolUse credential advisory (issue #85).

Invokes `python3 hooks/yolt_analyzer.py --hook` as a subprocess with a
simulated hook payload, and asserts on the JSON emitted on stdout.

Runs with stdlib unittest only:

    python3 -m unittest discover -v tests
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Synthetic value, shaped like the real thing, valid nowhere.
FAKE_GH_TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0" * 2


def run_hook(command, extra_env=None):
    """Fire the PreToolUse hook and return its parsed response ({} if
    it exited silently). Logging is pointed at a temp dir so the test
    never appends to the developer's real ~/.claude/yolt.log."""
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "permission_mode": "default",
    }
    with tempfile.TemporaryDirectory() as tmp:
        env = dict(os.environ)
        env["YOLT_LOG_FILE"] = str(Path(tmp) / "yolt.log")
        env["YOLT_RAN_LOG_FILE"] = ""
        if extra_env:
            env.update(extra_env)
        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "hooks" / "yolt_analyzer.py"),
             "--hook"],
            input=json.dumps(payload), capture_output=True, text=True,
            env=env, timeout=60,
        )
    if not proc.stdout.strip():
        return {}
    return json.loads(proc.stdout)


class AdvisoryTests(unittest.TestCase):

    def assert_warned(self, response, command_fragment=None):
        self.assertIn("systemMessage", response)
        self.assertIn("credential", response["systemMessage"])
        self.assertIn(
            "additionalContext", response.get("hookSpecificOutput", {}))
        # The warning must not quote the secret it is warning about.
        self.assertNotIn(FAKE_GH_TOKEN, json.dumps(response))
        if command_fragment:
            self.assertIn(command_fragment, response["systemMessage"])

    def test_warns_on_safe_command_without_blocking(self):
        # `curl` a URL with a token in a header: nothing unsafe by YOLT's
        # lights, which is exactly the case that motivated the issue.
        response = run_hook(
            'curl -H "Authorization: Bearer {}" https://api.github.com'.format(
                FAKE_GH_TOKEN))
        self.assert_warned(response)
        decision = response["hookSpecificOutput"].get("permissionDecision")
        self.assertNotEqual(decision, "deny")

    def test_advisory_names_shape_and_offset_only(self):
        response = run_hook("gh auth login --with-token {}".format(
            FAKE_GH_TOKEN))
        self.assert_warned(response, "github-token at char")

    def test_advisory_suggests_the_env_remediation(self):
        response = run_hook("gh auth login --with-token {}".format(
            FAKE_GH_TOKEN))
        # The runnable fix, not just a complaint: the value moves into an
        # env var so it never appears in argv.
        message = response["systemMessage"]
        self.assertIn("argv", message)
        self.assertIn('KEY="$(fetch-secret)"', message)
        self.assertIn("$KEY", message)

    def test_unsafe_command_keeps_its_decision(self):
        response = run_hook(
            'curl -X POST -H "Authorization: Bearer {}" '
            "https://api.github.com/repos/o/r/issues".format(FAKE_GH_TOKEN))
        self.assert_warned(response)
        # The advisory rides along; it does not replace the safety verdict.
        self.assertIn("permissionDecision", response["hookSpecificOutput"])

    def test_clean_command_gets_no_advisory(self):
        response = run_hook("ls /tmp")
        self.assertNotIn("systemMessage", response)
        self.assertNotIn(
            "additionalContext", response.get("hookSpecificOutput", {}))

    def test_shell_expansion_gets_no_advisory(self):
        # The form we are steering people toward must not be warned about.
        response = run_hook(
            'curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com')
        self.assertNotIn("systemMessage", response)

    def test_kill_switch(self):
        # An exact `== "0"` test would leave `false` / `off` silently
        # warning, which reads as a broken switch.
        for value in ("0", "false", "FALSE", "no", "off", " off "):
            response = run_hook(
                "gh auth login --with-token {}".format(FAKE_GH_TOKEN),
                extra_env={"YOLT_SECRET_WARN": value})
            self.assertNotIn(
                "systemMessage", response,
                "YOLT_SECRET_WARN={!r} did not disable".format(value))

    def test_advisory_stays_short(self):
        # It rides along with a prompt the user is already reading. A
        # wall of text is how a security control gets switched off.
        response = run_hook("gh auth login --with-token {}".format(
            FAKE_GH_TOKEN))
        self.assertLess(len(response["systemMessage"]), 400)


class DecisionIntegrityTests(unittest.TestCase):
    """The central claim of this PR: the advisory changes nothing.

    Asserting "the decision is not deny" is not enough — that would pass
    even if the advisory silently flipped `ask` to `allow`. These
    compare the same command with and without a credential and require
    the decision to come out identical.
    """

    def decision_of(self, response):
        return response.get("hookSpecificOutput", {}).get("permissionDecision")

    def test_decision_identical_with_and_without_credential(self):
        templates = [
            'curl -H "X-Api-Key: {}" https://service/endpoint',
            "gh auth login --with-token {}",
            'curl -X POST -H "Authorization: Bearer {}" https://api.github.com/x',
            "some-unknown-internal-cli --token {}",
        ]
        for template in templates:
            with_secret = run_hook(template.format(FAKE_GH_TOKEN))
            without_secret = run_hook(template.format("PLACEHOLDERVALUE"))
            # Guard against a vacuous pass: the credential case must
            # actually have warned, or this proves nothing.
            self.assertIn("systemMessage", with_secret, template)
            self.assertNotIn("systemMessage", without_secret, template)
            self.assertEqual(self.decision_of(with_secret),
                             self.decision_of(without_secret),
                             "advisory moved the decision for: " + template)

    def test_unknown_path_warns_without_claiming_a_decision(self):
        """The riskiest path: this previously printed nothing at all.

        Emitting a `permissionDecision` here would convert Claude Code's
        default prompt into an allow. The response must carry the
        warning and assert no decision.
        """
        response = run_hook(
            "some-unknown-internal-cli --token {}".format(FAKE_GH_TOKEN))
        self.assertIn("systemMessage", response)
        self.assertIsNone(self.decision_of(response),
                          "advisory asserted a permission decision on the "
                          "unknown fallthrough")

    def test_scanner_failure_does_not_break_the_hook(self):
        """A bug in a credential pattern must cost the warning, not the
        session. The safety decision is already made by this point."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "ya_advisory", REPO_ROOT / "hooks" / "yolt_analyzer.py")
        analyzer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(analyzer)

        def exploding_find_secrets(text):
            raise ValueError("simulated pattern bug")

        analyzer.find_secrets = exploding_find_secrets
        self.assertIsNone(analyzer.format_secret_advisory("ls /tmp"))


if __name__ == "__main__":
    unittest.main()
