"""PreToolUse on tools other than Bash (issue #99).

The matcher widened from `Bash` to `*` because the subagent wedge #80
observed was a `Write`, not a Bash call — a guard registered on one tool
is not a guard.

Only two things happen on the non-Bash path, and these tests pin both
plus the boundary between them:

  1. the agent-steering write check, over a **closed** list of
     path-carrying fields;
  2. the credential advisory, over every string in the payload.

Everything else falls through to the host. The negative tests matter more
than the positive ones here: this path must not grow into a second
classifier for structured tools.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
HOOKS_DIR = REPO_ROOT / "hooks"
sys.path.insert(0, str(HOOKS_DIR))

from yolt_analyzer import (  # noqa: E402
    TOOL_WRITE_PATH_FIELDS,
    classify_tool_input,
    tool_input_text,
)

FAKE_TOKEN = "ghp_" + "D" * 36
PROTECTED = "~/.claude/settings.json"


def run_hook(payload, env=None):
    """Fire the PreToolUse hook and return the parsed response, or None."""
    run_env = dict(os.environ)
    if env:
        run_env.update(env)
    result = subprocess.run(
        [sys.executable, str(HOOKS_DIR / "yolt_analyzer.py"), "--hook"],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=30,
        env=run_env,
    )
    assert result.returncode == 0, result.stderr[:500]
    out = result.stdout.strip()
    if not out:
        retval = None
        return retval
    retval = json.loads(out.splitlines()[-1])
    return retval


def decision_of(response):
    if response is None:
        retval = None
        return retval
    retval = response.get("hookSpecificOutput", {}).get("permissionDecision")
    return retval


def protected_path():
    retval = str(Path.home() / ".claude" / "settings.json")
    return retval


class TestAgentSteeringWrites(unittest.TestCase):
    """A write to a path that steers the agent is the one thing this path
    objects to. It is the self-modification shape, and it is reachable
    from a structured tool without any shell involved."""

    def test_write_to_protected_path_asks(self):
        resp = run_hook({
            "tool_name": "Write",
            "tool_input": {"file_path": protected_path(), "content": "x"},
        })
        self.assertEqual(decision_of(resp), "ask")
        self.assertIn(
            "protected path",
            resp["hookSpecificOutput"]["permissionDecisionReason"],
        )

    def test_write_to_ordinary_path_is_silent(self):
        resp = run_hook({
            "tool_name": "Write",
            "tool_input": {"file_path": "/tmp/ordinary.txt", "content": "x"},
        })
        self.assertIsNone(resp)

    def test_every_listed_tool_and_field_is_wired(self):
        # Guards the table itself: a field added to TOOL_WRITE_PATH_FIELDS
        # without the classifier honouring it would be silently inert.
        for tool, fields in TOOL_WRITE_PATH_FIELDS.items():
            for field in fields:
                resp = run_hook({
                    "tool_name": tool,
                    "tool_input": {field: protected_path()},
                })
                self.assertEqual(
                    decision_of(resp), "ask",
                    "{}.{} did not gate a protected write".format(tool, field),
                )

    def test_home_relative_form_is_matched(self):
        resp = run_hook({
            "tool_name": "Write",
            "tool_input": {"file_path": PROTECTED, "content": "x"},
        })
        self.assertEqual(decision_of(resp), "ask")


class TestClosedFieldList(unittest.TestCase):
    """The write-target field list is closed on purpose. Guessing which
    field of an arbitrary payload is a write target eventually guesses
    wrong, and a wrong guess here is a false `deny` in a subagent — the
    wedge this hook exists to avoid."""

    def test_unlisted_tool_falls_through_even_with_a_protected_path(self):
        resp = run_hook({
            "tool_name": "SomeOtherTool",
            "tool_input": {"file_path": protected_path()},
        })
        self.assertIsNone(resp)

    def test_unlisted_field_on_a_listed_tool_falls_through(self):
        resp = run_hook({
            "tool_name": "Write",
            "tool_input": {"destination": protected_path(), "content": "x"},
        })
        self.assertIsNone(resp)

    def test_mcp_tool_with_a_pathlike_argument_falls_through(self):
        resp = run_hook({
            "tool_name": "mcp__fs__write_file",
            "tool_input": {"path": protected_path(), "contents": "x"},
        })
        self.assertIsNone(resp)

    def test_classify_is_pure_and_defaults_to_unknown(self):
        never = lambda target: False  # noqa: E731
        decision, reason = classify_tool_input(
            "Write", {"file_path": protected_path()}, never,
        )
        self.assertEqual(decision, "unknown")
        self.assertIn("no rule", reason)


class TestSubagentModeAwareness(unittest.TestCase):
    """#80 gap 1. `ask` becomes `deny` in a subagent because nothing can
    answer an ask there — except in modes where the operator already
    blanket-authorised, where the conversion would override them."""

    def _decision(self, mode, agent_id="agent_probe"):
        payload = {
            "tool_name": "Write",
            "tool_input": {"file_path": protected_path(), "content": "x"},
            "permission_mode": mode,
        }
        if agent_id:
            payload["agent_id"] = agent_id
        retval = decision_of(run_hook(payload))
        return retval

    def test_main_session_asks_in_every_mode(self):
        for mode in ("default", "acceptEdits", "plan", "auto",
                     "bypassPermissions", "dontAsk"):
            self.assertEqual(self._decision(mode, agent_id=None), "ask", mode)

    def test_subagent_denies_in_prompting_modes(self):
        for mode in ("default", "acceptEdits", "plan"):
            self.assertEqual(self._decision(mode), "deny", mode)

    def test_subagent_asks_where_operator_pre_authorised(self):
        # bypassPermissions / dontAsk: there was no prompt to hang on, so
        # converting to deny would override an explicit authorisation
        # rather than protect anything.
        for mode in ("bypassPermissions", "dontAsk"):
            self.assertEqual(self._decision(mode), "ask", mode)

    def test_subagent_under_auto_still_denies(self):
        # Deliberate deviation from the mode list in #80. Auto mode
        # delegates the decision to a classifier; it does not put an
        # operator behind a hook's `ask`, so a subagent receiving one has
        # nobody to answer it. A wrong deny costs seconds; the wrong ask
        # wedged an agent for 2h37m in the #80 probe.
        self.assertEqual(self._decision("auto"), "deny")

    def test_absent_permission_mode_denies_in_a_subagent(self):
        # Fail toward the restrictive side when the payload omits it.
        self.assertEqual(self._decision(None), "deny")


class TestCredentialAdvisory(unittest.TestCase):
    """The advisory follows the payload, not the shell."""

    def _advisory(self, payload):
        resp = run_hook(payload)
        retval = (resp or {}).get("systemMessage")
        return retval

    def test_fires_on_a_credential_in_a_write_body(self):
        adv = self._advisory({
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/tmp/cfg.env",
                "content": "GH_TOKEN={}\n".format(FAKE_TOKEN),
            },
        })
        self.assertIsNotNone(adv)
        self.assertIn("Write", adv)

    def test_fires_on_a_credential_nested_in_an_mcp_payload(self):
        adv = self._advisory({
            "tool_name": "mcp__svc__call",
            "tool_input": {
                "args": {"headers": [{"Authorization": "Bearer " + FAKE_TOKEN}]},
            },
        })
        self.assertIsNotNone(adv)

    def test_never_echoes_the_value(self):
        # A warning that quotes the secret puts the secret into the
        # transcript it is warning about.
        resp = run_hook({
            "tool_name": "Write",
            "tool_input": {"file_path": "/tmp/x", "content": FAKE_TOKEN},
        })
        self.assertNotIn(FAKE_TOKEN, json.dumps(resp))

    def test_wording_drops_the_argv_advice(self):
        # `argv` and `ps` do not apply to a structured tool, and advice
        # that does not apply is how a control earns its way into being
        # ignored.
        adv = self._advisory({
            "tool_name": "Write",
            "tool_input": {"file_path": "/tmp/x", "content": FAKE_TOKEN},
        })
        self.assertNotIn("argv", adv)
        self.assertNotIn("ps", adv.split("\n")[0])

    def test_bash_wording_is_unchanged(self):
        adv = self._advisory({
            "tool_name": "Bash",
            "tool_input": {
                "command": "curl -H 'Authorization: Bearer {}' https://x".format(
                    FAKE_TOKEN),
            },
        })
        self.assertIn("argv", adv)
        self.assertIn("command line", adv)

    def test_does_not_change_the_decision(self):
        # Same call with and without a credential must decide identically.
        clean = run_hook({
            "tool_name": "Write",
            "tool_input": {"file_path": protected_path(), "content": "x"},
        })
        dirty = run_hook({
            "tool_name": "Write",
            "tool_input": {"file_path": protected_path(),
                           "content": FAKE_TOKEN},
        })
        self.assertEqual(decision_of(clean), decision_of(dirty))
        self.assertIsNotNone(dirty.get("systemMessage"),
                             "vacuous: the credential case did not warn")

    def test_kill_switch_applies_to_the_tool_path_too(self):
        adv = self._advisory({
            "tool_name": "Write",
            "tool_input": {"file_path": "/tmp/x", "content": FAKE_TOKEN},
        })
        self.assertIsNotNone(adv)
        resp = run_hook(
            {"tool_name": "Write",
             "tool_input": {"file_path": "/tmp/x", "content": FAKE_TOKEN}},
            env={"YOLT_SECRET_WARN": "off"},
        )
        self.assertIsNone(resp)


class TestToolInputFlattening(unittest.TestCase):
    def test_walks_dicts_lists_and_scalars(self):
        text = tool_input_text({
            "a": "one",
            "b": ["two", {"c": "three"}],
            "d": 4,
            "e": None,
        })
        for expected in ("one", "two", "three"):
            self.assertIn(expected, text)

    def test_empty_input_is_empty_text(self):
        self.assertEqual(tool_input_text({}), "")


class TestLogRecord(unittest.TestCase):
    def test_record_carries_tool_name_and_a_bounded_subject(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "yolt.log"
            run_hook(
                {"tool_name": "Write",
                 "tool_input": {"file_path": "/tmp/ordinary.txt",
                                "content": "y" * 5000}},
                env={"YOLT_LOG_FILE": str(log)},
            )
            record = json.loads(log.read_text().strip().splitlines()[-1])
        self.assertEqual(record["tool_name"], "Write")
        # The payload is not the subject: a Write body can be a megabyte
        # and this log is append-only.
        self.assertIn("/tmp/ordinary.txt", record["command"])
        self.assertNotIn("yyyy", record["command"])

    def test_bash_records_still_say_bash(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "yolt.log"
            run_hook(
                {"tool_name": "Bash", "tool_input": {"command": "ls /tmp"}},
                env={"YOLT_LOG_FILE": str(log)},
            )
            record = json.loads(log.read_text().strip().splitlines()[-1])
        self.assertEqual(record["tool_name"], "Bash")
        self.assertEqual(record["decision"], "safe")


if __name__ == "__main__":
    unittest.main()
