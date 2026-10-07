"""A literal subprocess argv is judged by the shell rules, and may at most
lower a refusal to `unknown` (host decides), never grant `safe`. Issue #162.

Every bypass here was found by adversarial probing of the first version of
the fix, which mapped "the shell rules did not call it unsafe" to `safe`.
Each must keep master's refusal.

    python3 -m unittest discover -v tests
"""

import sys
import textwrap
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
HOOKS_DIR = REPO_ROOT / "hooks"
sys.path.insert(0, str(HOOKS_DIR))

from rule_classifier import (  # noqa: E402
    DECISION_UNKNOWN,
    DECISION_UNSAFE,
    RuleClassifier,
    load_shell_rules,
)
from yolt_analyzer import SafetyAnalyzer, load_rules  # noqa: E402


PY_RULES = load_rules(REPO_ROOT / "rules")
SHELL_RULES = load_shell_rules(REPO_ROOT / "rules")


def _analyze(source):
    analyzer = SafetyAnalyzer(
        PY_RULES, argv_classify=RuleClassifier(SHELL_RULES).classify_tokens)
    retval = analyzer.analyze(textwrap.dedent(source))
    return retval


def _decision(source):
    classifier = RuleClassifier(
        SHELL_RULES,
        python_analyzer_factory=lambda: SafetyAnalyzer(
            PY_RULES,
            argv_classify=RuleClassifier(SHELL_RULES).classify_tokens),
    )
    decision, _ = classifier.classify_python_source(
        textwrap.dedent(source), "script.py")
    retval = decision
    return retval


class TestDelegatedIsUnresolvedNotSafe(unittest.TestCase):

    def test_literal_read_only_git_is_unknown(self):
        src = """
            import subprocess
            subprocess.run(["git", "rev-parse", "--short", "HEAD"])
        """
        result = _analyze(src)
        self.assertFalse(result["safe"])
        self.assertTrue(result["unresolved"])
        self.assertEqual(result["findings"], [])
        self.assertEqual(_decision(src), DECISION_UNKNOWN)

    def test_literal_tuple_argv_is_unknown(self):
        src = """
            import subprocess
            subprocess.check_output(("git", "diff", "--name-only", "origin/master"), text=True)
        """
        self.assertEqual(_decision(src), DECISION_UNKNOWN)

    def test_git_dash_c_after_subcommand_is_unknown(self):
        # `-c` after the subcommand is a log option, not config.
        src = """
            import subprocess
            subprocess.run(["git", "-C", "/repo", "log", "-c", "-1"])
        """
        self.assertEqual(_decision(src), DECISION_UNKNOWN)

    def test_shell_unsafe_argv_stays_unsafe(self):
        src = """
            import subprocess
            subprocess.run(["rm", "-rf", "build"])
        """
        self.assertEqual(_decision(src), DECISION_UNSAFE)

    def test_without_argv_classify_behaviour_is_unchanged(self):
        result = SafetyAnalyzer(PY_RULES).analyze(textwrap.dedent("""
            import subprocess
            subprocess.run(["git", "status"])
        """))
        self.assertFalse(result["safe"])
        self.assertNotIn("unresolved", result)
        self.assertEqual(len(result["findings"]), 1)


class TestBypassesKeepRefusal(unittest.TestCase):

    def assertUnsafe(self, src):
        self.assertEqual(_decision(src), DECISION_UNSAFE)

    def test_rebinding_subprocess_function(self):
        self.assertUnsafe("""
            import os, subprocess
            subprocess.run = os.system
            subprocess.run(["git", "status"])
        """)

    def test_aliasing_destructive_callable(self):
        self.assertUnsafe("""
            import os, subprocess
            str = os.remove
            subprocess.run(["git", "status"])
            str("important.txt")
        """)

    def test_putenv_before_read(self):
        self.assertUnsafe("""
            import os, subprocess
            os.putenv("GIT_EXTERNAL_DIFF", "/tmp/evil.sh")
            subprocess.run(["git", "diff"])
        """)

    def test_environ_assignment_before_read(self):
        self.assertUnsafe("""
            import os, subprocess
            os.environ["GIT_EXTERNAL_DIFF"] = "/tmp/evil.sh"
            subprocess.run(["git", "diff"])
        """)

    def test_environ_update_before_read(self):
        self.assertUnsafe("""
            import os, subprocess
            os.environ.update({"GIT_EXTERNAL_DIFF": "/tmp/evil.sh"})
            subprocess.run(["git", "diff"])
        """)

    def test_env_keyword(self):
        self.assertUnsafe("""
            import subprocess
            subprocess.run(["git", "diff"], env={"GIT_EXTERNAL_DIFF": "/tmp/evil.sh"})
        """)

    def test_preexec_fn_keyword(self):
        self.assertUnsafe("""
            import subprocess
            subprocess.run(["git", "status"], preexec_fn=print)
        """)

    def test_executable_keyword(self):
        self.assertUnsafe("""
            import subprocess
            subprocess.run(["git", "status"], executable="/bin/rm")
        """)

    def test_git_dash_c_config(self):
        self.assertUnsafe("""
            import subprocess
            subprocess.run(["git", "-c", "core.pager=rm -rf ~", "log"])
        """)

    def test_git_glued_dash_c_config(self):
        self.assertUnsafe("""
            import subprocess
            subprocess.run(["git", "-C", "/repo", "-ccore.fsmonitor=/tmp/x", "status"])
        """)

    def test_git_config_env(self):
        self.assertUnsafe("""
            import subprocess
            subprocess.run(["git", "--config-env=core.pager=PAGER", "log"])
        """)

    def test_git_exec_path(self):
        self.assertUnsafe("""
            import subprocess
            subprocess.run(["git", "--exec-path=/tmp/evil", "status"])
        """)

    def test_shell_true(self):
        self.assertUnsafe("""
            import subprocess
            subprocess.run(["rm -rf ~", "x"], shell=True)
        """)

    def test_double_star_kwargs(self):
        self.assertUnsafe("""
            import subprocess
            opts = {"shell": True}
            subprocess.run(["git", "status"], **opts)
        """)

    def test_starred_element_hides_flag(self):
        self.assertUnsafe("""
            import subprocess, sys
            extra = sys.argv[1:]
            subprocess.run(["git", "reset", *extra, "--hard"])
        """)

    def test_name_element(self):
        self.assertUnsafe("""
            import subprocess
            sub = "clean"
            subprocess.run(["git", sub, "-fdx"])
        """)

    def test_exec_in_module(self):
        self.assertUnsafe("""
            import subprocess
            exec("import subprocess, os; subprocess.run = os.system")
            subprocess.run(["git", "status"])
        """)

    def test_importlib_in_module(self):
        self.assertUnsafe("""
            import importlib, subprocess
            subprocess.run(["git", "status"])
        """)

    def test_os_system_string_is_not_delegated(self):
        self.assertUnsafe("""
            import os
            os.system("git status")
        """)


if __name__ == "__main__":
    unittest.main()
