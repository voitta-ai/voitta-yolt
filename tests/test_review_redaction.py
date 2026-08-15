"""The reviewer must not copy credentials out of the logs (issue #91).

`yolt_review.py` reads ~/.claude/yolt.log and writes command examples
into two more files. Redaction in the analyzer (issue #84) is write-time
only, so log lines predating it still hold plaintext — and without this,
every session copied more of them into review.md and suggestions.json.

Runs with stdlib unittest only:

    python3 -m unittest discover -v tests
"""

import datetime
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "hooks"))

# Synthetic value, shaped like the real thing, valid nowhere.
FAKE_GH_TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0" * 2


class ReviewerRedactionTests(unittest.TestCase):

    def write_log(self, path, command, count=12):
        """A log holding unredacted lines, i.e. one written before #84."""
        now = datetime.datetime.now(datetime.timezone.utc)
        with open(path, "w") as f:
            for i in range(count):
                ts = (now - datetime.timedelta(minutes=i)).isoformat()
                f.write(json.dumps({
                    "ts": ts,
                    "decision": "unknown",
                    "reason": "",
                    "command": command,
                    "permission_mode": "default",
                    "agent_id": None,
                }) + "\n")

    def test_generated_artifacts_carry_no_credential(self):
        command = "frobnicate push --token {} --env prod".format(
            FAKE_GH_TOKEN)
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "yolt.log"
            state_dir = Path(tmp) / "state"
            state_dir.mkdir()
            self.write_log(log_path, command)

            subprocess.run(
                [sys.executable, str(REPO_ROOT / "hooks" / "yolt_review.py"),
                 "--generate", "--log", str(log_path),
                 "--state-dir", str(state_dir)],
                capture_output=True, text=True, timeout=120,
            )

            produced = [p for p in state_dir.rglob("*") if p.is_file()]
            self.assertTrue(produced, "reviewer generated nothing")
            for path in produced:
                self.assertNotIn(
                    FAKE_GH_TOKEN, path.read_text(errors="replace"),
                    "credential copied into {}".format(path.name))

    def test_examples_stay_useful_after_redaction(self):
        """Redaction must not reduce an example to noise - the command
        shape is what makes a friction suggestion actionable."""
        command = "frobnicate push --token {} --env prod".format(
            FAKE_GH_TOKEN)
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "yolt.log"
            state_dir = Path(tmp) / "state"
            state_dir.mkdir()
            self.write_log(log_path, command)
            subprocess.run(
                [sys.executable, str(REPO_ROOT / "hooks" / "yolt_review.py"),
                 "--generate", "--log", str(log_path),
                 "--state-dir", str(state_dir)],
                capture_output=True, text=True, timeout=120,
            )
            doc = (state_dir / "review.md").read_text(errors="replace")
            self.assertIn("frobnicate push", doc)
            self.assertIn("--env prod", doc)

    def test_glob_collisions_are_redacted(self):
        """The sibling sink of `examples` (issue #91 follow-up).

        A collision is by definition a *non-safe* command, so it is the
        likelier of the two to carry auth — a `-X POST ... -H
        'Authorization: ...'` is exactly what gets flagged. The first fix
        redacted `examples` and left this one, which put the same
        credential in the same two files eight lines apart.
        """
        safe = "gh api /repos/o/r/issues?page={}"
        unsafe = ("gh api -X POST /repos/o/r/issues "
                  "-H 'Authorization: token {}'".format(FAKE_GH_TOKEN))
        now = datetime.datetime.now(datetime.timezone.utc)
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "yolt.log"
            state_dir = Path(tmp) / "state"
            state_dir.mkdir()
            with open(log_path, "w") as f:
                # Enough safe fires to clear the fastpath threshold, and a
                # single unsafe one so it stays a collision rather than
                # becoming its own suggestion.
                rows = [("safe", safe.format(i)) for i in range(12)]
                rows.append(("unsafe", unsafe))
                for i, (decision, command) in enumerate(rows):
                    f.write(json.dumps({
                        "ts": (now - datetime.timedelta(minutes=i)).isoformat(),
                        "decision": decision,
                        "reason": "gh api",
                        "command": command,
                        "permission_mode": "default",
                        "agent_id": None,
                    }) + "\n")

            subprocess.run(
                [sys.executable, str(REPO_ROOT / "hooks" / "yolt_review.py"),
                 "--generate", "--log", str(log_path),
                 "--state-dir", str(state_dir)],
                capture_output=True, text=True, timeout=120,
            )

            produced = [p for p in state_dir.rglob("*") if p.is_file()]
            self.assertTrue(produced, "reviewer generated nothing")
            for path in produced:
                text = path.read_text(errors="replace")
                self.assertNotIn(FAKE_GH_TOKEN, text,
                                 "credential reached {}".format(path.name))
            # Guard against a vacuous pass: the collision must have been
            # rendered at all.
            doc = (state_dir / "review.md").read_text(errors="replace")
            self.assertIn("Would also allow", doc)

    def test_falls_back_to_shape_reducer_without_the_redactor(self):
        """Fail closed: with `secret_redact` unimportable, examples must
        degrade to the value-stripping shape reducer, never to the raw
        command."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "yr_fallback", REPO_ROOT / "hooks" / "yolt_review.py")
        reviewer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(reviewer)

        reviewer._redact_values = None
        command = "frobnicate push --token {} --env prod".format(
            FAKE_GH_TOKEN)
        out = reviewer.redact_example(command)
        self.assertNotIn(FAKE_GH_TOKEN, out)
        self.assertIn("frobnicate", out)


if __name__ == "__main__":
    unittest.main()
