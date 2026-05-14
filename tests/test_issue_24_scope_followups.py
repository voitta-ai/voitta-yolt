"""Regression tests for issue #24 follow-ups to the scope-aware
import-alias resolver introduced in #20 / #22.

Two correctness gaps:

  1. `_scope_key_for_node` collided for multiple lambdas on a single
     line. The fix gives each scope a unique `(lineno, col_offset,
     name)` key and pairs the symtable walk with the AST walk so the
     key is reliably populated.

  2. `_collect_top_level_bindings` did not record `ast.NamedExpr`
     (walrus) targets at module scope. A walrus that rebinds an
     imported name at module scope therefore did not drop the import
     binding, and a subsequent call to that name was still rewritten
     to the import alias.
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


class TestLambdaSameLineKeyCollision(unittest.TestCase):
    """The repro from issue #24 section 1: two lambdas on the same
    line, one of which shadows an imported name via a parameter.
    Correct behavior is that lambda 1 (param `system=print`) is safe
    and lambda 2 (no shadow) resolves `system` to `os.system` and is
    flagged."""

    def test_same_line_lambdas_resolve_independently(self):
        source = (
            "from os import system\n"
            "a, b = lambda system=print: system('x'), lambda: system('y')\n"
        )
        result = _fresh_analyzer().analyze(source)
        self.assertFalse(result["safe"])
        self.assertEqual(len(result["findings"]), 1)
        finding = result["findings"][0]
        self.assertEqual(finding["call"], "os.system")
        self.assertEqual(finding["line"], 2)
        # Source line confirms it is the second lambda (no `system=print`
        # in its arglist) being flagged.
        self.assertIn("lambda: system('y')", finding["source_line"])

    def test_same_line_lambdas_reversed_shadowing(self):
        """Mirror image: lambda 2 has the shadowing param, lambda 1
        does not. Lambda 1 must be flagged."""
        source = (
            "from os import system\n"
            "a, b = lambda: system('x'), lambda system=print: system('y')\n"
        )
        result = _fresh_analyzer().analyze(source)
        self.assertFalse(result["safe"])
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["call"], "os.system")
        self.assertIn("lambda: system('x')", result["findings"][0]["source_line"])

    def test_three_lambdas_one_unshadowed(self):
        source = (
            "from os import system\n"
            "x = [lambda system=print: system('a'),"
            " lambda system=print: system('b'),"
            " lambda: system('c')]\n"
        )
        result = _fresh_analyzer().analyze(source)
        self.assertFalse(result["safe"])
        self.assertEqual(len(result["findings"]), 1)
        self.assertIn("lambda: system('c')", result["findings"][0]["source_line"])


class TestModuleScopeWalrusRebind(unittest.TestCase):
    """Issue #24 section 2: walrus at module scope (in or out of a
    comprehension) must drop a prior import binding so subsequent
    module-scope calls do not resolve through it."""

    def test_walrus_outside_comprehension(self):
        source = (
            "from os import system\n"
            "if (system := print):\n"
            "    pass\n"
            "system('hello')\n"
        )
        result = _fresh_analyzer().analyze(source)
        self.assertTrue(
            result["safe"],
            "walrus rebinding `system` should drop the os.system alias; "
            "found {}".format(result["findings"]),
        )

    def test_walrus_inside_list_comprehension(self):
        source = (
            "from os import system\n"
            "[s for s in [1, 2] if (system := print)]\n"
            "system('hello')\n"
        )
        result = _fresh_analyzer().analyze(source)
        self.assertTrue(
            result["safe"],
            "walrus inside list comprehension leaks to module scope "
            "(PEP 572) and must drop the os.system alias; "
            "found {}".format(result["findings"]),
        )

    def test_walrus_inside_generator_expression(self):
        source = (
            "from os import system\n"
            "list(s for s in [1, 2] if (system := print))\n"
            "system('hello')\n"
        )
        result = _fresh_analyzer().analyze(source)
        self.assertTrue(
            result["safe"],
            "walrus inside genexp leaks to module scope and must drop "
            "the os.system alias; found {}".format(result["findings"]),
        )

    def test_walrus_inside_lambda_body_does_not_leak_to_module(self):
        """Walrus inside a lambda body binds in the lambda's own scope,
        not in the enclosing module scope (lambdas are their own scope
        like functions). A subsequent module-scope call must still
        resolve through the import.

        Regression: an earlier fix recorded `ast.NamedExpr` drops by
        descending through every node `_walk_module_scope` visited,
        which traversed into `ast.Lambda` bodies and produced
        spurious module-scope drops."""
        source = (
            "from os import system\n"
            "x = lambda: (system := print)\n"
            "system('boom')\n"
        )
        result = _fresh_analyzer().analyze(source)
        self.assertFalse(
            result["safe"],
            "walrus inside lambda body must not leak to module scope; "
            "module-level call to `system` should still resolve to "
            "os.system. Got findings={}".format(result["findings"]),
        )
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["call"], "os.system")
        self.assertEqual(result["findings"][0]["line"], 3)

    def test_walrus_in_lambda_default_drops_module_binding(self):
        """Walrus in a lambda parameter default runs at definition
        time in the ENCLOSING scope (here module scope), so it must
        emit a module-scope drop event. A subsequent module-scope call
        to the rebound name should therefore not resolve through the
        original import.

        Regression-paired with
        `test_walrus_inside_lambda_body_does_not_leak_to_module`: the
        walker must descend into lambda defaults while still stopping
        at the lambda body."""
        source = (
            "from os import system\n"
            "f = lambda y=(system := print): y\n"
            "system('boom')\n"
        )
        result = _fresh_analyzer().analyze(source)
        self.assertTrue(
            result["safe"],
            "walrus in lambda default executes at definition time and "
            "rebinds `system` in module scope; line 3 should be safe. "
            "Got findings={}".format(result["findings"]),
        )

    def test_walrus_in_lambda_default_and_body_simultaneously(self):
        """Mixed case: a walrus in the lambda's default DOES leak to
        module scope, while a separate walrus in the lambda's body
        does NOT. After the lambda definition the module's `system`
        is `print`; calls to `system` are safe."""
        source = (
            "from os import system\n"
            "f = lambda y=(system := print): (system := y)\n"
            "system('boom')\n"
        )
        result = _fresh_analyzer().analyze(source)
        self.assertTrue(result["safe"])

    def test_walrus_inside_nested_lambda_body_does_not_leak(self):
        """Even a walrus reached through several layers of nesting
        inside a lambda body — here wrapped in a list literal — must
        not pollute the module-scope binding table."""
        source = (
            "from os import system\n"
            "f = lambda: [(system := print), 1]\n"
            "system('boom')\n"
        )
        result = _fresh_analyzer().analyze(source)
        self.assertFalse(result["safe"])
        self.assertEqual(result["findings"][0]["call"], "os.system")

    def test_call_before_walrus_still_resolves_to_import(self):
        """Position-aware: a call BEFORE the walrus rebind still
        resolves through the import. Drop applies only to later
        positions."""
        source = (
            "from os import system\n"
            "system('first')\n"
            "if (system := print):\n"
            "    pass\n"
            "system('second')\n"
        )
        result = _fresh_analyzer().analyze(source)
        self.assertFalse(result["safe"])
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["line"], 2)
        self.assertEqual(result["findings"][0]["call"], "os.system")


if __name__ == "__main__":
    unittest.main()
