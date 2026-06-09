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
        # SafetyAnalyzer reports findings as `L<line>:` in its reason field.
        self.assertIn("L2", reason)
        self.assertIn("os.system", reason)

    def test_git_push_reason_includes_allow_hint(self):
        result = HookSubprocess.run_bash(
            "git -C /tmp/wt-27 push -u origin feature/issue-27-find-write-flags"
        )
        resp = HookSubprocess.response_of(result)
        self.assertIsNotNone(resp)
        reason = resp["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("Bash(git -C * push -u origin feature/*)", reason)

    def test_gh_issue_create_reason_includes_allow_hint(self):
        result = HookSubprocess.run_bash(
            'gh issue create --title "x" --body "y"'
        )
        resp = HookSubprocess.response_of(result)
        self.assertIsNotNone(resp)
        reason = resp["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("Bash(gh issue create*)", reason)


class TestHookWhitelistDiscovery(unittest.TestCase):
    """The hook reads the user's settings.json `permissions.allow` Bash()
    entries and uses them as an explicit override for unknown and unsafe
    atoms.
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

    def test_whitelist_overrides_unsafe(self):
        self._write_settings(["Bash(git push origin feature/*)"])
        self.assertEqual(
            self._decision("git push origin feature/issue-35"),
            "allow",
        )


class TestBootstrapShell(unittest.TestCase):
    """The shell wrapper `pre-tool-use.sh` bootstraps tree-sitter deps on
    first run, then execs the Python analyzer. These tests exercise the
    bash bootstrap path without actually running pip — we point HOME at a
    fresh temp dir and verify that a marker appears after a successful
    run (deps are already importable in the test process), and that
    subsequent invocations skip the import probe entirely."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="yolt-bootstrap-")
        self.tmp = Path(self._tmp)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _run(self, command, env_overrides=None):
        env = dict(os.environ)
        env["HOME"] = str(self.tmp)
        env["YOLT_LOG_FILE"] = ""  # opt out of log noise for this class
        if env_overrides:
            env.update(env_overrides)
        return subprocess.run(
            [str(HOOKS_DIR / "pre-tool-use.sh")],
            input=json.dumps({
                "tool_name": "Bash",
                "tool_input": {"command": command},
            }),
            capture_output=True,
            text=True,
            timeout=60,
            env=env,
        )

    def test_first_run_creates_marker(self):
        result = self._run("ls /tmp")
        self.assertEqual(result.returncode, 0)
        cache = self.tmp / ".cache" / "yolt"
        markers = list(cache.glob("deps-installed-*"))
        self.assertEqual(len(markers), 1, "expected one marker file under {}".format(cache))

    def test_subsequent_run_keeps_same_marker(self):
        self._run("ls /tmp")
        self._run("ls /tmp")
        markers = list((self.tmp / ".cache" / "yolt").glob("deps-installed-*"))
        self.assertEqual(len(markers), 1)

    def test_hook_still_emits_decision_through_bootstrap(self):
        # Sanity: the bootstrap wrapper transparently passes through to
        # the analyzer's stdout.
        result = self._run("rm -rf /tmp/yolt-bootstrap-fake")
        self.assertEqual(result.returncode, 0)
        last = [l for l in result.stdout.splitlines() if l.strip()][-1]
        parsed = json.loads(last)
        self.assertEqual(
            parsed["hookSpecificOutput"]["permissionDecision"], "ask",
        )


class TestHookLogFile(unittest.TestCase):
    """When YOLT_LOG_FILE is set, the hook appends a JSON-line record per
    Bash invocation regardless of the eventual decision. Used for
    dogfooding and QA visibility."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="yolt-log-")
        self.tmp = Path(self._tmp)
        self.log_path = self.tmp / "yolt.log"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _run_with_log(self, command):
        env = dict(os.environ)
        env["YOLT_LOG_FILE"] = str(self.log_path)
        subprocess.run(
            [sys.executable, str(HOOKS_DIR / "yolt_analyzer.py"), "--hook"],
            input=json.dumps({
                "tool_name": "Bash",
                "tool_input": {"command": command},
            }),
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )

    def _records(self):
        if not self.log_path.exists():
            return []
        retval = []
        for line in self.log_path.read_text().splitlines():
            line = line.strip()
            if line:
                retval.append(json.loads(line))
        return retval

    def test_logs_safe_decision(self):
        self._run_with_log("ls /tmp")
        recs = self._records()
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["decision"], "safe")
        self.assertEqual(recs[0]["command"], "ls /tmp")
        self.assertIn("ts", recs[0])
        self.assertIn("ls", recs[0]["reason"])

    def test_logs_unsafe_decision(self):
        self._run_with_log("rm -rf /tmp/foo")
        recs = self._records()
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["decision"], "unsafe")
        self.assertEqual(recs[0]["command"], "rm -rf /tmp/foo")

    def test_logs_unknown_decision(self):
        self._run_with_log("somecommand_unknown_xyz --flag")
        recs = self._records()
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["decision"], "unknown")

    def test_appends_across_invocations(self):
        self._run_with_log("ls /tmp")
        self._run_with_log("rm -rf /tmp/foo")
        self._run_with_log("git status")
        recs = self._records()
        self.assertEqual(len(recs), 3)
        decisions = [r["decision"] for r in recs]
        self.assertEqual(decisions, ["safe", "unsafe", "safe"])

    def test_long_command_is_truncated(self):
        long_cmd = "echo " + ("x" * 1000)
        self._run_with_log(long_cmd)
        recs = self._records()
        self.assertEqual(len(recs), 1)
        self.assertLessEqual(len(recs[0]["command"]), 500)

    def test_default_log_path_used_when_env_unset(self):
        # When YOLT_LOG_FILE is unset, the hook writes to the default
        # path (~/.claude/yolt.log via $HOME). Redirect HOME so we can
        # observe the default-path write without polluting the real one.
        fake_home = self.tmp / "fake-home"
        fake_home.mkdir()
        env = dict(os.environ)
        env.pop("YOLT_LOG_FILE", None)
        env["HOME"] = str(fake_home)
        subprocess.run(
            [sys.executable, str(HOOKS_DIR / "yolt_analyzer.py"), "--hook"],
            input=json.dumps({
                "tool_name": "Bash",
                "tool_input": {"command": "ls /tmp"},
            }),
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )
        default_log = fake_home / ".claude" / "yolt.log"
        self.assertTrue(default_log.exists(), "default log path was not written")
        line = default_log.read_text().strip()
        record = json.loads(line)
        self.assertEqual(record["decision"], "safe")
        self.assertEqual(record["command"], "ls /tmp")

    def test_empty_string_opts_out_of_logging(self):
        # YOLT_LOG_FILE="" means the user explicitly opted out — no
        # log file, default or otherwise.
        fake_home = self.tmp / "fake-home"
        fake_home.mkdir()
        env = dict(os.environ)
        env["YOLT_LOG_FILE"] = ""
        env["HOME"] = str(fake_home)
        subprocess.run(
            [sys.executable, str(HOOKS_DIR / "yolt_analyzer.py"), "--hook"],
            input=json.dumps({
                "tool_name": "Bash",
                "tool_input": {"command": "ls /tmp"},
            }),
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )
        self.assertFalse((fake_home / ".claude" / "yolt.log").exists())
        self.assertFalse(self.log_path.exists())

    def test_log_rotates_when_size_exceeds_max(self):
        # Set the rotation threshold tiny (200 bytes) so a single fire
        # plus a pre-existing log overflows it. Verify the old log is
        # preserved as `<log>.old` and the new write goes to a fresh
        # `<log>`.
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path.write_text("x" * 500 + "\n")
        env = dict(os.environ)
        env["YOLT_LOG_FILE"] = str(self.log_path)
        env["YOLT_LOG_MAX_BYTES"] = "200"
        subprocess.run(
            [sys.executable, str(HOOKS_DIR / "yolt_analyzer.py"), "--hook"],
            input=json.dumps({
                "tool_name": "Bash",
                "tool_input": {"command": "ls /tmp"},
            }),
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )
        old_path = self.log_path.with_suffix(self.log_path.suffix + ".old")
        self.assertTrue(old_path.exists(), "rotated .old log was not created")
        self.assertIn("xxx", old_path.read_text())
        new_records = self._records()
        self.assertEqual(len(new_records), 1)
        self.assertEqual(new_records[0]["decision"], "safe")

    def test_log_does_not_rotate_below_threshold(self):
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path.write_text("small\n")
        env = dict(os.environ)
        env["YOLT_LOG_FILE"] = str(self.log_path)
        env["YOLT_LOG_MAX_BYTES"] = "10000"
        subprocess.run(
            [sys.executable, str(HOOKS_DIR / "yolt_analyzer.py"), "--hook"],
            input=json.dumps({
                "tool_name": "Bash",
                "tool_input": {"command": "ls /tmp"},
            }),
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )
        old_path = self.log_path.with_suffix(self.log_path.suffix + ".old")
        self.assertFalse(old_path.exists(), "log rotated below threshold")
        # Pre-existing line + the new record both present.
        contents = self.log_path.read_text()
        self.assertIn("small", contents)
        self.assertIn('"decision": "safe"', contents)

    def test_log_rotation_disabled_when_max_bytes_zero(self):
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        big = "x" * 10_000 + "\n"
        self.log_path.write_text(big)
        env = dict(os.environ)
        env["YOLT_LOG_FILE"] = str(self.log_path)
        env["YOLT_LOG_MAX_BYTES"] = "0"  # disable
        subprocess.run(
            [sys.executable, str(HOOKS_DIR / "yolt_analyzer.py"), "--hook"],
            input=json.dumps({
                "tool_name": "Bash",
                "tool_input": {"command": "ls /tmp"},
            }),
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )
        old_path = self.log_path.with_suffix(self.log_path.suffix + ".old")
        self.assertFalse(old_path.exists(), "log rotated despite max_bytes=0")

    def test_unwritable_log_path_does_not_break_hook(self):
        # If the log path is unwritable, the hook must still emit its
        # normal decision and exit cleanly. Logging is best-effort.
        env = dict(os.environ)
        env["YOLT_LOG_FILE"] = "/proc/cannot-write-here/yolt.log"
        result = subprocess.run(
            [sys.executable, str(HOOKS_DIR / "yolt_analyzer.py"), "--hook"],
            input=json.dumps({
                "tool_name": "Bash",
                "tool_input": {"command": "ls /tmp"},
            }),
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )
        self.assertEqual(result.returncode, 0)
        # Decision is still emitted on stdout.
        self.assertIn("hookSpecificOutput", result.stdout)


class TestHookMalformedShellOverride(unittest.TestCase):
    """If `~/.claude/yolt/shell.json` contains schema drift, the hook
    must exit silently (Claude Code falls through to its default prompt)
    and record the failure to the log so the user can diagnose."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="yolt-bad-override-")
        self.tmp = Path(self._tmp)
        self.fake_home = self.tmp / "home"
        (self.fake_home / ".claude" / "yolt").mkdir(parents=True)
        self.override_path = self.fake_home / ".claude" / "yolt" / "shell.json"
        self.log_path = self.tmp / "yolt.log"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _run(self, command):
        env = dict(os.environ)
        env["HOME"] = str(self.fake_home)
        env["YOLT_LOG_FILE"] = str(self.log_path)
        retval = subprocess.run(
            [sys.executable, str(HOOKS_DIR / "yolt_analyzer.py"), "--hook"],
            input=json.dumps({
                "tool_name": "Bash",
                "tool_input": {"command": command},
            }),
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )
        return retval

    def _records(self):
        if not self.log_path.exists():
            return []
        retval = []
        for line in self.log_path.read_text().splitlines():
            line = line.strip()
            if line:
                retval.append(json.loads(line))
        return retval

    def test_unknown_command_key_in_override_logs_rules_error(self):
        self.override_path.write_text(json.dumps({
            "commands": {"mycli": {"default": "safe", "phantom_key": []}},
        }))
        result = self._run("ls /tmp")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "")
        recs = self._records()
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["decision"], "rules-validation-error")
        self.assertIn("phantom_key", recs[0]["reason"])

    def test_unknown_nested_module_default_in_override_logs_rules_error(self):
        self.override_path.write_text(json.dumps({
            "interpreters": {
                "python3": {
                    "module_flag": "-m",
                    "nested_modules": {
                        "pip": {"default": "bogus"},
                    },
                },
            },
        }))
        result = self._run("ls /tmp")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "")
        recs = self._records()
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["decision"], "rules-validation-error")
        self.assertIn("bogus", recs[0]["reason"])


if __name__ == "__main__":
    unittest.main()
