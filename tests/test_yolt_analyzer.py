"""Unit tests for hooks/yolt_analyzer.py SafetyAnalyzer.

Focuses on the import-binding resolution layer added for issue #16:
calls written via aliases or `from`-imports must be normalized back to
their original dotted path before destructive-pattern matching.

Runs with stdlib unittest only - no tree-sitter dependency:

    python3 -m unittest discover -v tests
"""

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
HOOKS_DIR = REPO_ROOT / "hooks"
sys.path.insert(0, str(HOOKS_DIR))

from yolt_analyzer import SafetyAnalyzer, load_rules  # noqa: E402


def _fresh_analyzer():
    rules = load_rules(REPO_ROOT / "rules")
    retval = SafetyAnalyzer(rules)
    return retval


class TestImportAliasResolution(unittest.TestCase):
    """Verify that destructive calls reached through `import as`,
    `from import`, and `from import as` are matched against their
    original dotted-path rule patterns."""

    def _analyze(self, source):
        retval = _fresh_analyzer().analyze(source)
        return retval

    # --- Repros from issue #16 ---

    def test_import_alias_os_system_is_unsafe(self):
        result = self._analyze('import os as x\nx.system("rm -rf /tmp/x")')
        self.assertFalse(result["safe"], result)
        self.assertIn("os.system", result["reason"])

    def test_from_import_os_system_is_unsafe(self):
        result = self._analyze(
            'from os import system\nsystem("rm -rf /tmp/x")'
        )
        self.assertFalse(result["safe"], result)
        self.assertIn("os.system", result["reason"])

    def test_from_import_alias_shutil_rmtree_is_unsafe(self):
        result = self._analyze(
            'from shutil import rmtree as wipe\nwipe("/tmp/x")'
        )
        self.assertFalse(result["safe"], result)
        self.assertIn("shutil.rmtree", result["reason"])

    # --- Existing direct-call behavior preserved ---

    def test_direct_os_system_still_unsafe(self):
        result = self._analyze('import os\nos.system("rm -rf /tmp/x")')
        self.assertFalse(result["safe"], result)

    def test_direct_shutil_rmtree_still_unsafe(self):
        result = self._analyze('import shutil\nshutil.rmtree("/tmp/x")')
        self.assertFalse(result["safe"], result)

    # --- Safe forms stay safe ---

    def test_safe_json_dumps(self):
        result = self._analyze('import json\nprint(json.dumps({}))')
        self.assertTrue(result["safe"], result)

    def test_safe_alias_json_dumps(self):
        result = self._analyze('import json as j\nprint(j.dumps({}))')
        self.assertTrue(result["safe"], result)

    def test_safe_from_import_dumps(self):
        result = self._analyze('from json import dumps\nprint(dumps({}))')
        self.assertTrue(result["safe"], result)

    def test_safe_submodule_alias(self):
        # `import os.path as p; p.exists(...)` resolves to `os.path.exists`
        # which is not in any destructive pattern.
        result = self._analyze(
            'import os.path as p\nprint(p.exists("/etc/passwd"))'
        )
        self.assertTrue(result["safe"], result)

    def test_safe_requests_get(self):
        result = self._analyze(
            'from requests import get\nprint(get("https://x"))'
        )
        self.assertTrue(result["safe"], result)

    # --- Unresolved / out-of-scope boundary documentation ---

    def test_starred_import_does_not_bind_names(self):
        # `from os import *` makes the bound names unknowable statically.
        # We do NOT guess that `system` came from os; the call stays at
        # `system`, which is not a destructive pattern target on its own.
        # This documents a known under-detection that the issue scopes
        # out of this release.
        result = self._analyze('from os import *\nsystem("rm -rf /tmp/x")')
        self.assertTrue(result["safe"], result)

    def test_variable_rebinding_not_tracked(self):
        # Assigning a destructive callable to a new local name is out of
        # scope - we do not model arbitrary assignment. The call resolves
        # to `f` (not `os.system`), so it slips through. Documenting the
        # boundary so it is intentional.
        result = self._analyze(
            'import os\nf = os.system\nf("rm -rf /tmp/x")'
        )
        self.assertTrue(result["safe"], result)

    def test_unimported_call_target_unchanged(self):
        # Without an import, the name `os` is not in the alias table, so
        # the resolver leaves the call as `os.system`. The destructive
        # pattern matches the surface name. This preserves the pre-#16
        # behavior for callers that pass already-fully-qualified text.
        result = self._analyze('os.system("rm -rf /tmp/x")')
        self.assertFalse(result["safe"], result)

    def test_relative_import_not_bound(self):
        # `from . import x` cannot be resolved without package context;
        # the binding is intentionally skipped so we don't fabricate a
        # path. The call stays as `x.foo` and falls through to whatever
        # rules apply to the surface name.
        result = self._analyze('from . import x\nprint(x.foo())')
        self.assertTrue(result["safe"], result)

    # --- Alias-table state ---

    def test_alias_table_records_import_as(self):
        a = _fresh_analyzer()
        a.analyze("import os as x")
        self.assertEqual(a.alias_table.get("x"), "os")

    def test_alias_table_records_from_import(self):
        a = _fresh_analyzer()
        a.analyze("from os import system")
        self.assertEqual(a.alias_table.get("system"), "os.system")

    def test_alias_table_records_from_import_as(self):
        a = _fresh_analyzer()
        a.analyze("from shutil import rmtree as wipe")
        self.assertEqual(a.alias_table.get("wipe"), "shutil.rmtree")

    def test_alias_table_records_import_submodule_as(self):
        a = _fresh_analyzer()
        a.analyze("import os.path as p")
        self.assertEqual(a.alias_table.get("p"), "os.path")

    def test_alias_table_plain_import_binds_top_level(self):
        a = _fresh_analyzer()
        a.analyze("import os.path")
        # `import os.path` binds `os` (not `os.path`) in the local scope.
        self.assertEqual(a.alias_table.get("os"), "os")


class TestImportScopeAndOrder(unittest.TestCase):
    """Verify the alias table is built scope-aware and source-order
    independent: top-level imports apply to calls regardless of textual
    position; imports nested under control flow / dead branches do NOT
    apply; top-level rebinds drop their binding."""

    def _analyze(self, source):
        rules = load_rules(REPO_ROOT / "rules")
        retval = SafetyAnalyzer(rules).analyze(source)
        return retval

    # --- Source-order independence: PR #20 review item 1 ---

    def test_call_before_from_import_still_resolves(self):
        # Function defined before the matching import. Pre-pass collects
        # the import binding before traversal, so the in-function call
        # resolves through it.
        source = (
            "def f():\n"
            '    system("rm -rf /tmp/x")\n'
            "from os import system\n"
            "f()\n"
        )
        result = self._analyze(source)
        self.assertFalse(result["safe"], result)
        self.assertIn("os.system", result["reason"])

    def test_call_before_alias_import_still_resolves(self):
        source = (
            "def f():\n"
            '    x.system("rm -rf /tmp/x")\n'
            "import os as x\n"
            "f()\n"
        )
        result = self._analyze(source)
        self.assertFalse(result["safe"], result)
        self.assertIn("os.system", result["reason"])

    # --- Conditional / dead imports: PR #20 review item 2a ---

    def test_dead_if_false_import_does_not_bind(self):
        # Static `if False:` is a dead branch; we cannot prove it runs.
        # The binding must NOT be applied, so the later call stays at the
        # surface name `system` and is not flagged as `os.system`.
        source = (
            "if False:\n"
            "    from os import system\n"
            'system("hello")\n'
        )
        result = self._analyze(source)
        self.assertTrue(result["safe"], result)

    def test_conditional_import_inside_if_does_not_bind(self):
        source = (
            "if cond:\n"
            "    from os import system\n"
            'system("hello")\n'
        )
        result = self._analyze(source)
        self.assertTrue(result["safe"], result)

    def test_import_inside_try_does_not_bind(self):
        source = (
            "try:\n"
            "    from os import system\n"
            "except ImportError:\n"
            "    pass\n"
            'system("hello")\n'
        )
        result = self._analyze(source)
        self.assertTrue(result["safe"], result)

    def test_import_inside_function_does_not_bind_module_scope(self):
        # Module-level call below has no binding because the only import
        # lives inside `g`. Resolves to surface `system`, not destructive.
        source = (
            "def g():\n"
            "    from os import system\n"
            "    return system\n"
            'system("hello")\n'
        )
        result = self._analyze(source)
        self.assertTrue(result["safe"], result)

    # --- Top-level rebinding: PR #20 review item 2b ---

    def test_top_level_rebind_drops_binding(self):
        source = (
            "from os import system\n"
            "system = print\n"
            'system("hello")\n'
        )
        result = self._analyze(source)
        self.assertTrue(result["safe"], result)

    def test_top_level_rebind_inside_if_drops_binding(self):
        # Conditional top-level reassignment: we cannot prove which value
        # wins at runtime, so we drop the binding to be safe.
        source = (
            "from os import system\n"
            "if cond:\n"
            "    system = print\n"
            'system("hello")\n'
        )
        result = self._analyze(source)
        self.assertTrue(result["safe"], result)

    def test_top_level_for_target_drops_binding(self):
        # `for system in ...:` rebinds `system` at module scope.
        source = (
            "from os import system\n"
            "for system in []:\n"
            "    pass\n"
            'system("hello")\n'
        )
        result = self._analyze(source)
        self.assertTrue(result["safe"], result)

    def test_function_local_rebind_does_not_drop_module_binding(self):
        # Inside `f`, `system = print` introduces a function-scope name —
        # it must NOT invalidate the module-level binding. The module
        # call below remains a destructive `os.system`.
        source = (
            "from os import system\n"
            "def f():\n"
            "    system = print\n"
            "    return system\n"
            'system("rm -rf /tmp/x")\n'
        )
        result = self._analyze(source)
        self.assertFalse(result["safe"], result)
        self.assertIn("os.system", result["reason"])


if __name__ == "__main__":
    unittest.main()
