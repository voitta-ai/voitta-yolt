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
    `os.system` rule.
    """

    @staticmethod
    def _decision(snippet):
        # Use a heredoc, not `python3 -c`, so the snippet keeps its
        # real newlines. The Python AST delegate's alias resolution
        # is shape-faithful — multi-line `import` then call — which
        # is the form the closing PR #20 verified end-to-end.
        cmd = "python3 <<'PYEOF'\n{}\nPYEOF\n".format(snippet)
        retval = _Hook.decision_for(cmd)
        return retval

    def test_import_alias_os_system(self):
        snippet = (
            "import os as x\n"
            'x.system("rm -rf /tmp/x")'
        )
        self.assertEqual(self._decision(snippet), "ask")

    def test_from_import_unaliased(self):
        snippet = (
            "from os import system\n"
            'system("rm -rf /tmp/x")'
        )
        self.assertEqual(self._decision(snippet), "ask")

    def test_from_import_aliased(self):
        snippet = (
            "from shutil import rmtree as wipe\n"
            'wipe("/tmp/x")'
        )
        self.assertEqual(self._decision(snippet), "ask")


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


if __name__ == "__main__":
    unittest.main()
