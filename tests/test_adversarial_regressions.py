"""Adversarial false-allow regression catalogue.

Each test in this module pins one previously known false-allow
reproduction to its post-fix expected decision so a future refactor
cannot silently re-introduce it. New repros that surface in the wild
should be added here when their fix lands.

Every test goes through the same end-to-end path Claude Code uses in
production: `python3 hooks/yolt_analyzer.py --hook`, fed a synthetic
`PreToolUse` payload on stdin. The assertion is on the
`permissionDecision` value (`allow` / `ask`) or on a silent exit
(`None`) for inputs that intentionally fall through to Claude Code's
default-prompt path.

Catalogue layout:

- `TestIssue14ShellFalseAllows` -- `find -exec / -execdir / -ok /
  -okdir <cmd>` and `gh api --input <file>` repros (closes #15 via
  PR #19).
- `TestIssue16PythonImportAliases` -- aliased / renamed-import
  destructive call repros (closes #16 via PR #20).
- `TestIssue21PythonLocalShadowing` -- local shadow of an imported
  destructive alias must not suppress an outer unsafe call (closes
  #21 via PR #22).
- `TestIssue17NestedCliVerbs` -- nested-verb mutating CLIs that used
  to classify safe under the shallow top-level subcommand rule
  (closes #17 via PR #25), and the bare-read counterparts that must
  stay safe.
- `TestIssue27FindWriteFlags` -- `find -fprint / -fprintf / -fls /
  -fls0 FILE` repros (closes #27). Path argument was unchecked, so
  writes outside `safe_write_targets` classified safe. The fix
  routes the path through the same white list redirects use.
- `TestIssue28UnsafeWriteTargets` -- redirect / command writes to
  dotfile / config / startup paths (closes #28). The headline repro
  is `echo pwn > ~/.claude/settings.json`, which classified `allow`
  before the fix because `~/.claude/*` is a safe-write target even
  though settings.json can disable this hook. The deny list is
  checked before the safe list, so it now asks.

Run with:

    python3 -m unittest discover -v tests
    python3 -m unittest tests.test_adversarial_regressions -v
"""

import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
HOOKS_DIR = REPO_ROOT / "hooks"


class _Hook:
    """Run the hook entry point on a Bash command and return the decision."""

    @staticmethod
    def decision_for(command):
        result = subprocess.run(
            [sys.executable, str(HOOKS_DIR / "yolt_analyzer.py"), "--hook"],
            input=json.dumps({
                "tool_name": "Bash",
                "tool_input": {"command": command},
            }),
            capture_output=True,
            text=True,
            timeout=30,
        )
        stdout = result.stdout.strip()
        if not stdout:
            retval = None
            return retval
        last_line = stdout.splitlines()[-1]
        response = json.loads(last_line)
        retval = response["hookSpecificOutput"]["permissionDecision"]
        return retval


class TestIssue14ShellFalseAllows(unittest.TestCase):
    """Repros from #15 (subset of #14): shell-rule `unsafe_flag_value_prefix`.

    Before PR #19 the field was declared in `rules/shell.json` but
    not evaluated, so `find -exec rm {} \\;` and `gh api --input
    body.json` classified `safe`.
    """

    def test_find_exec_runs_destructive_command(self):
        self.assertEqual(
            _Hook.decision_for("find . -name '*.py' -exec rm {} \\;"),
            "ask",
        )

    def test_find_execdir_runs_destructive_command(self):
        self.assertEqual(
            _Hook.decision_for("find . -name '*.py' -execdir rm {} \\;"),
            "ask",
        )

    def test_find_ok_runs_destructive_command(self):
        self.assertEqual(
            _Hook.decision_for("find . -name '*.py' -ok rm {} \\;"),
            "ask",
        )

    def test_find_okdir_runs_destructive_command(self):
        self.assertEqual(
            _Hook.decision_for("find . -name '*.py' -okdir rm {} \\;"),
            "ask",
        )

    def test_gh_api_input_split_form(self):
        self.assertEqual(
            _Hook.decision_for("gh api /repos/x/y/issues --input body.json"),
            "ask",
        )

    def test_gh_api_input_inline_form(self):
        self.assertEqual(
            _Hook.decision_for("gh api /repos/x/y/issues --input=body.json"),
            "ask",
        )


class TestIssue16PythonImportAliases(unittest.TestCase):
    """Repros from #16: aliased imports must resolve to the underlying call.

    Before PR #20 the Python delegate matched call targets by surface
    name only, so `import os as x; x.system(...)` slipped past the
    `os.system` rule. Multi-line, heredoc, and semicolon-one-liner
    forms are all covered here so the same alias-resolution gap
    cannot reopen on any user-visible entry point.
    """

    @staticmethod
    def _decision_heredoc(snippet):
        cmd = "python3 <<'PYEOF'\n{}\nPYEOF\n".format(snippet)
        retval = _Hook.decision_for(cmd)
        return retval

    @staticmethod
    def _decision_dash_c(snippet):
        # Wrap the inline source in single quotes so the embedded
        # double quotes survive the shell parse. The grammar walker
        # hands the raw inline body to the Python AST delegate.
        cmd = "python3 -c '{}'".format(snippet)
        retval = _Hook.decision_for(cmd)
        return retval

    # Heredoc form (multi-line imports + call)

    def test_import_alias_os_system_heredoc(self):
        snippet = (
            "import os as x\n"
            'x.system("rm -rf /tmp/x")'
        )
        self.assertEqual(self._decision_heredoc(snippet), "ask")

    def test_from_import_unaliased_heredoc(self):
        snippet = (
            "from os import system\n"
            'system("rm -rf /tmp/x")'
        )
        self.assertEqual(self._decision_heredoc(snippet), "ask")

    def test_from_import_aliased_heredoc(self):
        snippet = (
            "from shutil import rmtree as wipe\n"
            'wipe("/tmp/x")'
        )
        self.assertEqual(self._decision_heredoc(snippet), "ask")

    # Semicolon one-liner via `python3 -c`. This is the exact
    # repro shape from the #16 issue body and the #30 review:
    # alias resolution must work when the binding and the call
    # are on the same source line.

    def test_import_alias_os_system_dash_c_semicolon(self):
        self.assertEqual(
            self._decision_dash_c(
                'import os as x; x.system(\"rm -rf /tmp/x\")'
            ),
            "ask",
        )

    def test_from_import_unaliased_dash_c_semicolon(self):
        self.assertEqual(
            self._decision_dash_c(
                'from os import system; system(\"rm -rf /tmp/x\")'
            ),
            "ask",
        )

    def test_from_import_aliased_dash_c_semicolon(self):
        self.assertEqual(
            self._decision_dash_c(
                'from shutil import rmtree as wipe; wipe(\"/tmp/x\")'
            ),
            "ask",
        )


class TestIssue21PythonLocalShadowing(unittest.TestCase):
    """Repros from #21: local rebinding must not suppress outer unsafe.

    Before PR #22 a local `os.system = lambda *_: None` inside a
    function body invalidated the module-level alias resolution and
    a sibling unsafe call elsewhere in the module was missed.
    """

    @staticmethod
    def _decision(snippet):
        cmd = "python3 <<'PYEOF'\n{}\nPYEOF\n".format(snippet)
        retval = _Hook.decision_for(cmd)
        return retval

    def test_function_local_shadow_does_not_suppress_outer(self):
        snippet = (
            "import os\n"
            "def f():\n"
            "    os = object()\n"
            "    return os\n"
            'os.system("rm -rf /tmp/x")\n'
        )
        self.assertEqual(self._decision(snippet), "ask")

    def test_class_body_shadow_does_not_suppress_outer(self):
        snippet = (
            "import os\n"
            "class C:\n"
            "    os = None\n"
            'os.system("rm -rf /tmp/x")\n'
        )
        self.assertEqual(self._decision(snippet), "ask")


class TestIssue17NestedCliVerbs(unittest.TestCase):
    """Repros from #17: nested mutating verbs in policy-driven CLIs.

    Before PR #25 the top-level rules said e.g. `docker image: safe`
    so `docker image rm alpine` classified safe. Path-aware nested
    classification now routes the mutating verb to `unsafe`, while
    the bare-read counterparts (`docker image ls`, `git tag -l`,
    ...) keep classifying `safe`.
    """

    # Unsafe nested verbs

    def test_docker_image_rm_is_unsafe(self):
        self.assertEqual(
            _Hook.decision_for("docker image rm alpine"), "ask"
        )

    def test_kubectl_config_set_context_is_unsafe(self):
        self.assertEqual(
            _Hook.decision_for("kubectl config set-context prod"),
            "ask",
        )

    def test_helm_repo_add_is_unsafe(self):
        self.assertEqual(
            _Hook.decision_for(
                "helm repo add foo https://charts.example.com"
            ),
            "ask",
        )

    def test_git_tag_create_is_not_safe(self):
        # `git tag <name>` creates a tag. Conservative fallback is
        # `unknown`, which surfaces as a silent exit (Claude Code
        # default-prompts).
        self.assertIn(
            _Hook.decision_for("git tag v1.2.3"),
            (None, "ask"),
        )

    def test_git_tag_delete_is_unsafe(self):
        self.assertEqual(
            _Hook.decision_for("git tag -d v1.2.3"), "ask"
        )

    # Bare reads that must remain safe

    def test_bare_git_tag_safe(self):
        self.assertEqual(_Hook.decision_for("git tag"), "allow")

    def test_git_tag_list_safe(self):
        self.assertEqual(_Hook.decision_for("git tag -l"), "allow")

    def test_docker_image_ls_safe(self):
        self.assertEqual(_Hook.decision_for("docker image ls"), "allow")

    def test_kubectl_config_view_safe(self):
        self.assertEqual(
            _Hook.decision_for("kubectl config view"), "allow"
        )

    def test_helm_repo_list_safe(self):
        self.assertEqual(_Hook.decision_for("helm repo list"), "allow")


class TestIssue27FindWriteFlags(unittest.TestCase):
    """Repros from #27: `find` write-action flags that take a path
    argument (`-fprint`, `-fprintf`, `-fls`, `-fls0`) classified `safe`
    before this fix because their path argument bypassed the redirect-
    based `safe_write_targets` check. After the fix the path argument
    routes through the same white list, so writes to `/tmp/...` stay
    safe but writes to `/etc/profile` / `/var/log/...` ask."""

    def test_fprint_to_etc_is_unsafe(self):
        self.assertEqual(
            _Hook.decision_for("find / -name '*' -fprint /etc/profile"),
            "ask",
        )

    def test_fprint_to_tmp_is_safe(self):
        self.assertEqual(
            _Hook.decision_for("find / -fprint /tmp/list.txt"),
            "allow",
        )

    def test_fprintf_to_etc_is_unsafe(self):
        self.assertEqual(
            _Hook.decision_for("find / -fprintf /etc/passwd '%p\\n'"),
            "ask",
        )

    def test_fprintf_to_tmp_is_safe(self):
        self.assertEqual(
            _Hook.decision_for("find / -fprintf /tmp/list.txt '%p\\n'"),
            "allow",
        )

    def test_fls_to_var_log_is_unsafe(self):
        self.assertEqual(
            _Hook.decision_for("find / -fls /var/log/x.log"),
            "ask",
        )

    def test_fls0_to_tmp_is_safe(self):
        self.assertEqual(
            _Hook.decision_for("find / -fls0 /tmp/list.bin"),
            "allow",
        )


class TestIssue28UnsafeWriteTargets(unittest.TestCase):
    """Repros from #28: writes to dotfile / config / startup paths.

    Before the fix a redirect to such a path classified `unknown` (the
    hook stayed silent, deferring to the default prompt) and -- worse --
    `~/.claude/settings.json` classified `allow`, because `~/.claude/*`
    is a safe-write target even though settings.json can disable the
    hook. After the fix the `unsafe_write_targets` deny list is consulted
    before the safe list, so these ask with a specific reason."""

    def test_settings_json_no_longer_auto_allowed(self):
        # The headline hole: a safe-write glob auto-allowed a write that
        # can neuter the hook. Must ask now.
        self.assertEqual(
            _Hook.decision_for("echo pwn > ~/.claude/settings.json"),
            "ask",
        )

    def test_settings_local_json_no_longer_auto_allowed(self):
        self.assertEqual(
            _Hook.decision_for("echo pwn > ~/.claude/settings.local.json"),
            "ask",
        )

    def test_other_claude_path_still_allowed(self):
        # The carve-out is settings.json only; the rest of ~/.claude/*
        # stays a safe-write target so legitimate cache writes don't ask.
        self.assertEqual(
            _Hook.decision_for("echo x > ~/.claude/cache.json"),
            "allow",
        )

    def test_redirect_to_bashrc_asks(self):
        # Was `unknown` (silent) before #28.
        self.assertEqual(
            _Hook.decision_for("echo x > ~/.bashrc"),
            "ask",
        )

    def test_append_to_authorized_keys_asks(self):
        self.assertEqual(
            _Hook.decision_for("echo pubkey >> ~/.ssh/authorized_keys"),
            "ask",
        )

    def test_cp_to_cron_dir_asks(self):
        self.assertEqual(
            _Hook.decision_for("cp payload /etc/cron.d/job"),
            "ask",
        )

    def test_dd_of_ssh_key_asks(self):
        self.assertEqual(
            _Hook.decision_for("dd if=/dev/zero of=~/.ssh/id_rsa"),
            "ask",
        )

    def test_redirect_to_tmp_still_allowed(self):
        # Control: a benign temp write is unaffected.
        self.assertEqual(
            _Hook.decision_for("echo x > /tmp/scratch.txt"),
            "allow",
        )


if __name__ == "__main__":
    unittest.main()
