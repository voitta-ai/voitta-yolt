"""End-to-end tests for the PreToolUse hook entry point.

Invokes `python3 hooks/yolt_analyzer.py --hook` as a subprocess, feeding a
simulated Claude Code hook payload on stdin, and asserts on the JSON
response emitted on stdout.

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
HOOKS_DIR = REPO_ROOT / "hooks"
sys.path.insert(0, str(HOOKS_DIR))

from yolt_analyzer import (  # noqa: E402
    extract_heredoc_script,
    extract_script_from_command,
)


class TestHeredocExtraction(unittest.TestCase):
    def test_simple_heredoc(self):
        cmd = "python3 <<EOF\nprint(1)\nEOF\n"
        self.assertEqual(extract_heredoc_script(cmd), "print(1)\n")

    def test_single_quoted_delimiter(self):
        cmd = "python3 <<'EOF'\nprint(1)\nEOF\n"
        self.assertEqual(extract_heredoc_script(cmd), "print(1)\n")

    def test_double_quoted_delimiter(self):
        cmd = 'python3 <<"EOF"\nprint(1)\nEOF\n'
        self.assertEqual(extract_heredoc_script(cmd), "print(1)\n")

    def test_tab_strip_form(self):
        cmd = "python3 <<-EOF\nprint(1)\nEOF\n"
        self.assertEqual(extract_heredoc_script(cmd), "print(1)\n")

    def test_no_heredoc(self):
        self.assertIsNone(extract_heredoc_script("python3 script.py"))


class TestExtractScriptFromCommand(unittest.TestCase):
    def test_dash_c_inline(self):
        kind, src = extract_script_from_command('python3 -c "print(1)"')
        self.assertEqual((kind, src), ("inline", "print(1)"))

    def test_heredoc_inline(self):
        kind, src = extract_script_from_command(
            "python3 <<EOF\nprint(1)\nEOF\n"
        )
        self.assertEqual(kind, "inline")
        self.assertIn("print(1)", src)

    def test_file_path(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        ) as f:
            f.write("print(1)\n")
            path = f.name
        try:
            kind, src = extract_script_from_command("python3 {}".format(path))
            self.assertEqual((kind, src), ("file", path))
        finally:
            os.unlink(path)


class HookSubprocess:
    """Helper to invoke yolt_analyzer.py --hook and parse the response."""

    @staticmethod
    def run(payload):
        result = subprocess.run(
            [sys.executable, str(HOOKS_DIR / "yolt_analyzer.py"), "--hook"],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result

    @staticmethod
    def run_bash(command):
        retval = HookSubprocess.run({
            "tool_name": "Bash",
            "tool_input": {"command": command},
        })
        return retval

    @staticmethod
    def response_of(result):
        """Parse the hook's JSON response, or return None for silent exits."""
        stdout = result.stdout.strip()
        if not stdout:
            retval = None
            return retval
        last_line = stdout.splitlines()[-1]
        retval = json.loads(last_line)
        return retval


class TestHookEndToEnd(unittest.TestCase):
    def _decision(self, command):
        result = HookSubprocess.run_bash(command)
        resp = HookSubprocess.response_of(result)
        if resp is None:
            retval = None
            return retval
        retval = resp["hookSpecificOutput"]["permissionDecision"]
        return retval

    def test_safe_ls_returns_allow(self):
        self.assertEqual(self._decision("ls /tmp"), "allow")

    def test_aws_describe_returns_allow(self):
        self.assertEqual(
            self._decision("aws ec2 describe-instances"), "allow"
        )

    def test_unsafe_rm_returns_ask(self):
        self.assertEqual(self._decision("rm -rf /tmp/foo"), "ask")

    def test_gh_api_post_returns_ask(self):
        self.assertEqual(
            self._decision("gh api -X POST /repos/x/y/issues"), "ask"
        )

    def test_unknown_command_exits_silently(self):
        # `None` means the hook produced no output; Claude Code then applies
        # its default (prompt the user).
        self.assertIsNone(self._decision("somecommand_unknown --flag"))

    def test_redirect_to_system_file_exits_silently(self):
        self.assertIsNone(self._decision("echo x > /etc/profile"))

    def test_compound_aws_loop_returns_allow(self):
        cmd = (
            'for svc in $(aws ecs list-services --cluster X); do '
            'aws ecs describe-services --cluster X --services "$svc"; '
            "done"
        )
        self.assertEqual(self._decision(cmd), "allow")

    def test_python3_dash_c_safe_returns_allow(self):
        self.assertEqual(
            self._decision('python3 -c "print(1+1)"'), "allow"
        )

    def test_python3_dash_c_destructive_returns_ask(self):
        self.assertEqual(
            self._decision(
                'python3 -c "import os; os.system(\\"rm -rf /tmp/x\\")"'
            ),
            "ask",
        )

    def test_heredoc_safe_returns_allow(self):
        cmd = 'python3 <<EOF\nimport os\nprint(os.listdir("/tmp"))\nEOF\n'
        self.assertEqual(self._decision(cmd), "allow")

    def test_heredoc_destructive_returns_ask(self):
        cmd = 'python3 <<EOF\nimport os\nos.system("rm -rf /tmp/x")\nEOF\n'
        self.assertEqual(self._decision(cmd), "ask")

    def test_python3_script_file_safe_returns_allow(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        ) as f:
            f.write("import json\nprint(json.dumps({'ok': True}))\n")
            path = f.name
        try:
            self.assertEqual(
                self._decision("python3 {}".format(path)), "allow"
            )
        finally:
            os.unlink(path)

    def test_python3_script_file_destructive_returns_ask(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        ) as f:
            f.write("import os\nos.system('rm -rf /tmp/x')\n")
            path = f.name
        try:
            self.assertEqual(
                self._decision("python3 {}".format(path)), "ask"
            )
        finally:
            os.unlink(path)

    def test_non_bash_tool_exits_silently(self):
        result = HookSubprocess.run({
            "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/foo"},
        })
        self.assertEqual(result.stdout.strip(), "")
        self.assertEqual(result.returncode, 0)

    def test_empty_command_exits_silently(self):
        result = HookSubprocess.run_bash("")
        self.assertEqual(result.stdout.strip(), "")
        self.assertEqual(result.returncode, 0)

    def test_malformed_stdin_exits_silently(self):
        result = subprocess.run(
            [sys.executable, str(HOOKS_DIR / "yolt_analyzer.py"), "--hook"],
            input="not valid json",
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.stdout.strip(), "")
        self.assertEqual(result.returncode, 0)

    def test_response_reason_includes_detail(self):
        result = HookSubprocess.run_bash("rm -rf /tmp/foo")
        resp = HookSubprocess.response_of(result)
        self.assertIsNotNone(resp)
        reason = resp["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("rm", reason)

    def test_heredoc_destructive_reason_includes_line_number(self):
        cmd = 'python3 <<EOF\nimport os\nos.system("rm -rf /tmp/x")\nEOF\n'
        result = HookSubprocess.run_bash(cmd)
        resp = HookSubprocess.response_of(result)
        self.assertIsNotNone(resp)
        reason = resp["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("Line 2", reason)
        self.assertIn("os.system", reason)


class TestHookAllowlistDiscovery(unittest.TestCase):
    """The hook reads the user's settings.json `permissions.allow` Bash()
    entries and uses them as a secondary upgrade pass for unknown atoms.
    Tests scope the lookup via the `cwd` field in the hook payload so
    they don't depend on the real test runner's home directory."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="yolt-hook-cwd-")
        self.cwd = Path(self._tmp)
        (self.cwd / ".claude").mkdir()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _write_settings(self, allow):
        path = self.cwd / ".claude" / "settings.json"
        path.write_text(json.dumps({"permissions": {"allow": allow}}))

    def _decision(self, command):
        result = HookSubprocess.run({
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "cwd": str(self.cwd),
        })
        resp = HookSubprocess.response_of(result)
        if resp is None:
            retval = None
            return retval
        retval = resp["hookSpecificOutput"]["permissionDecision"]
        return retval

    def test_unknown_atom_upgraded_via_cwd_settings(self):
        self._write_settings(["Bash(yolt_test_mycli *)"])
        self.assertEqual(self._decision("yolt_test_mycli foo bar"), "allow")

    def test_unknown_atom_without_match_stays_silent(self):
        self._write_settings(["Bash(yolt_test_othertool *)"])
        self.assertIsNone(self._decision("yolt_test_mycli foo bar"))

    def test_allowlist_does_not_override_unsafe(self):
        self._write_settings(["Bash(rm *)"])
        self.assertEqual(self._decision("rm -rf /tmp/foo"), "ask")


if __name__ == "__main__":
    unittest.main()
