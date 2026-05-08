"""Unit tests for hooks/rule_classifier.py.

The rule classifier owns argv-level rule lookup and settings I/O, with no
dependency on the bash grammar layer. End-to-end tests that involve actual
shell parsing live in test_grammar_classifier.py.

Runs with stdlib unittest:

    python3 -m unittest discover -v tests
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
HOOKS_DIR = REPO_ROOT / "hooks"
sys.path.insert(0, str(HOOKS_DIR))

from rule_classifier import (  # noqa: E402
    DECISION_SAFE,
    DECISION_UNKNOWN,
    DECISION_UNSAFE,
    aggregate_decisions,
    check_unsafe_flags,
    load_allow_patterns,
    match_allow_patterns,
    parse_aws_positionals,
)


class TestCheckUnsafeFlags(unittest.TestCase):
    def test_unsafe_flag_values_match(self):
        spec = {"unsafe_flag_values": {"-X": ["POST", "DELETE"]}}
        self.assertIsNotNone(check_unsafe_flags(["-X", "POST"], spec))

    def test_unsafe_flag_values_match_case_insensitive(self):
        spec = {"unsafe_flag_values": {"-X": ["POST"]}}
        self.assertIsNotNone(check_unsafe_flags(["-X", "post"], spec))

    def test_unsafe_flag_values_no_match_for_get(self):
        spec = {"unsafe_flag_values": {"-X": ["POST"]}}
        self.assertIsNone(check_unsafe_flags(["-X", "GET"], spec))

    def test_unsafe_flag_any_value_catches_d(self):
        spec = {"unsafe_flag_any_value": ["-d", "--data"]}
        self.assertIsNotNone(check_unsafe_flags(["-d", "foo=bar"], spec))

    def test_unsafe_flag_without_value(self):
        spec = {"unsafe_flags_without_value": ["-delete"]}
        self.assertIsNotNone(check_unsafe_flags(["-delete"], spec))

    def test_inline_equals_flag_value(self):
        spec = {"unsafe_flag_values": {"--method": ["POST"]}}
        self.assertIsNotNone(check_unsafe_flags(["--method=POST"], spec))

    def test_none_of_the_above(self):
        spec = {"unsafe_flag_values": {"-X": ["POST"]}}
        self.assertIsNone(check_unsafe_flags(["--foo", "bar"], spec))


class TestParseAwsPositionals(unittest.TestCase):
    def test_simple(self):
        svc, op, _ = parse_aws_positionals(["ec2", "describe-instances"])
        self.assertEqual((svc, op), ("ec2", "describe-instances"))

    def test_profile_and_region_stripped(self):
        svc, op, _ = parse_aws_positionals([
            "--profile", "prod",
            "--region", "us-east-1",
            "ec2", "describe-instances",
            "--no-cli-pager",
        ])
        self.assertEqual((svc, op), ("ec2", "describe-instances"))

    def test_no_cli_pager_is_valueless(self):
        svc, op, _ = parse_aws_positionals(["--no-cli-pager", "s3", "ls"])
        self.assertEqual((svc, op), ("s3", "ls"))


class TestAggregateDecisions(unittest.TestCase):
    def test_empty(self):
        d, _ = aggregate_decisions([])
        self.assertEqual(d, DECISION_SAFE)

    def test_all_safe(self):
        d, _ = aggregate_decisions([(DECISION_SAFE, "a"), (DECISION_SAFE, "b")])
        self.assertEqual(d, DECISION_SAFE)

    def test_any_unsafe_wins(self):
        d, _ = aggregate_decisions([(DECISION_SAFE, "a"), (DECISION_UNSAFE, "b")])
        self.assertEqual(d, DECISION_UNSAFE)

    def test_unknown_over_safe_but_not_over_unsafe(self):
        d, _ = aggregate_decisions([(DECISION_SAFE, "a"), (DECISION_UNKNOWN, "b")])
        self.assertEqual(d, DECISION_UNKNOWN)
        d, _ = aggregate_decisions([
            (DECISION_UNKNOWN, "a"),
            (DECISION_UNSAFE, "b"),
        ])
        self.assertEqual(d, DECISION_UNSAFE)


class TestLoadAllowPatterns(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="yolt-allow-")
        self.tmp = Path(self._tmp)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _write(self, name, data):
        path = self.tmp / name
        path.write_text(json.dumps(data))
        return path

    def test_extracts_bash_inner_patterns(self):
        path = self._write("settings.json", {
            "permissions": {
                "allow": [
                    "Bash(aws s3 ls*)",
                    "Bash(env)",
                    "Read",
                    "mcp__github__get_file_contents",
                ]
            }
        })
        patterns = load_allow_patterns([path])
        self.assertEqual(patterns, ["aws s3 ls*", "env"])

    def test_missing_file_skipped(self):
        patterns = load_allow_patterns([self.tmp / "does-not-exist.json"])
        self.assertEqual(patterns, [])

    def test_malformed_json_skipped(self):
        path = self.tmp / "broken.json"
        path.write_text("{not json")
        patterns = load_allow_patterns([path])
        self.assertEqual(patterns, [])

    def test_dedupes_across_files(self):
        a = self._write("a.json", {
            "permissions": {"allow": ["Bash(env)", "Bash(ls*)"]}
        })
        b = self._write("b.json", {
            "permissions": {"allow": ["Bash(ls*)", "Bash(cat*)"]}
        })
        patterns = load_allow_patterns([a, b])
        self.assertEqual(patterns, ["env", "ls*", "cat*"])

    def test_no_permissions_key(self):
        path = self._write("nop.json", {"env": {"FOO": "bar"}})
        patterns = load_allow_patterns([path])
        self.assertEqual(patterns, [])

    def test_empty_inner_pattern_skipped(self):
        path = self._write("empty.json", {
            "permissions": {"allow": ["Bash()", "Bash(  )", "Bash(env)"]}
        })
        patterns = load_allow_patterns([path])
        self.assertEqual(patterns, ["env"])


class TestMatchAllowPatterns(unittest.TestCase):
    def test_no_patterns_returns_none(self):
        self.assertIsNone(match_allow_patterns("aws s3 ls", []))

    def test_exact_match(self):
        self.assertEqual(match_allow_patterns("env", ["env"]), "env")

    def test_glob_prefix_match(self):
        self.assertEqual(
            match_allow_patterns("aws s3 ls --recursive s3://b/", ["aws s3 ls*"]),
            "aws s3 ls*",
        )

    def test_glob_with_internal_wildcard(self):
        self.assertEqual(
            match_allow_patterns("aws iam list-roles", ["aws * list*"]),
            "aws * list*",
        )

    def test_no_match_returns_none(self):
        self.assertIsNone(match_allow_patterns("rm -rf /", ["aws *", "ls*"]))

    def test_strips_whitespace(self):
        self.assertEqual(match_allow_patterns("  env  ", ["env"]), "env")


if __name__ == "__main__":
    unittest.main()
