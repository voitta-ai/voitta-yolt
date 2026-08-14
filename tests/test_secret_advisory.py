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
        self.assertIn("environment", response["systemMessage"])
        self.assertIn("$KEY", response["systemMessage"])

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
        response = run_hook(
            "gh auth login --with-token {}".format(FAKE_GH_TOKEN),
            extra_env={"YOLT_SECRET_WARN": "0"})
        self.assertNotIn("systemMessage", response)


if __name__ == "__main__":
    unittest.main()
