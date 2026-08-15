"""The hook must survive a missing redactor (issue #93).

The import used to be unguarded, on the theory that failing loudly beats
silently writing credentials. Measured, it did neither: ModuleNotFoundError
exits 1, a non-zero non-2 exit from PreToolUse is non-blocking, and hook
stderr is not surfaced -- so every Bash command ran unclassified, nothing
was logged, and nobody was told.

Runs with stdlib unittest only:

    python3 -m unittest discover -v tests
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

FAKE_GH_TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0" * 2


class RedactorUnavailableTests(unittest.TestCase):

    def run_without_redactor(self, command):
        """Fire the hook against a tree with secret_redact.py removed."""
        with tempfile.TemporaryDirectory() as tmp:
            hooks_dir = Path(tmp) / "hooks"
            hooks_dir.mkdir()
            for name in os.listdir(REPO_ROOT / "hooks"):
                if name.endswith(".py") and name != "secret_redact.py":
                    shutil.copy(REPO_ROOT / "hooks" / name, hooks_dir)
            shutil.copytree(REPO_ROOT / "rules", Path(tmp) / "rules")

            log_path = Path(tmp) / "yolt.log"
            env = dict(os.environ)
            env["YOLT_LOG_FILE"] = str(log_path)
            env["YOLT_RAN_LOG_FILE"] = ""
            env.pop("PYTHONPATH", None)

            payload = {
                "tool_name": "Bash",
                "tool_input": {"command": command},
                "permission_mode": "default",
            }
            proc = subprocess.run(
                [sys.executable, str(hooks_dir / "yolt_analyzer.py"), "--hook"],
                input=json.dumps(payload), capture_output=True, text=True,
                env=env, timeout=60,
            )
            written = log_path.read_text() if log_path.exists() else ""
            return proc, written

    def test_hook_survives_and_still_classifies(self):
        proc, written = self.run_without_redactor(
            "curl -H 'Authorization: Bearer {}' https://x".format(
                FAKE_GH_TOKEN))
        self.assertEqual(proc.returncode, 0,
                         "hook died: {}".format(proc.stderr[:400]))
        # Classification never needed the redactor, so it must survive.
        self.assertIn("permissionDecision", proc.stdout)

    def test_command_text_is_withheld_not_written_raw(self):
        proc, written = self.run_without_redactor(
            "curl -H 'Authorization: Bearer {}' https://x".format(
                FAKE_GH_TOKEN))
        self.assertTrue(written, "nothing logged at all")
        self.assertNotIn(FAKE_GH_TOKEN, written)
        record = json.loads(written.strip().splitlines()[-1])
        self.assertEqual(record["command"], "[WITHHELD:redactor-unavailable]")
        # The failure has to be visible somewhere, since hook stderr is not.
        self.assertIn("redactor_error", record)

    def test_decision_is_still_recorded(self):
        """The log stays useful for everything except the command text."""
        proc, written = self.run_without_redactor("ls /tmp")
        record = json.loads(written.strip().splitlines()[-1])
        self.assertIn(record["decision"], ("safe", "unsafe", "unknown"))


if __name__ == "__main__":
    unittest.main()
