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
    classify_sql_text,
    load_allow_patterns,
    load_shell_rules,
    match_allow_patterns,
    parse_aws_positionals,
    parse_sql_cli_argv,
    validate_shell_rules,
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

    def test_unsafe_flag_value_prefix_split_form(self):
        spec = {"unsafe_flag_value_prefix": {"--input": "*"}}
        result = check_unsafe_flags(["--input", "body.json"], spec)
        self.assertIsNotNone(result)
        self.assertIn("--input", result)
        self.assertIn("body.json", result)

    def test_unsafe_flag_value_prefix_inline_form(self):
        spec = {"unsafe_flag_value_prefix": {"--input": "*"}}
        result = check_unsafe_flags(["--input=body.json"], spec)
        self.assertIsNotNone(result)
        self.assertIn("body.json", result)

    def test_unsafe_flag_value_prefix_find_exec(self):
        spec = {
            "unsafe_flag_value_prefix": {
                "-exec": "*", "-execdir": "*", "-ok": "*", "-okdir": "*",
            },
        }
        self.assertIsNotNone(
            check_unsafe_flags(["-name", "*.py", "-exec", "rm", "{}", r"\;"], spec)
        )
        self.assertIsNotNone(
            check_unsafe_flags(["-execdir", "rm", "{}", r"\;"], spec)
        )
        self.assertIsNotNone(
            check_unsafe_flags(["-ok", "rm", "{}", r"\;"], spec)
        )
        self.assertIsNotNone(
            check_unsafe_flags(["-okdir", "rm", "{}", r"\;"], spec)
        )

    def test_unsafe_flag_value_prefix_no_value(self):
        # Flag at end of argv with no value following — no match.
        spec = {"unsafe_flag_value_prefix": {"--input": "*"}}
        self.assertIsNone(check_unsafe_flags(["--input"], spec))

    def test_unsafe_flag_value_prefix_narrow_pattern(self):
        # Glob narrower than `*` must still match the actual value.
        spec = {"unsafe_flag_value_prefix": {"--input": "body.*"}}
        self.assertIsNotNone(
            check_unsafe_flags(["--input", "body.json"], spec)
        )
        self.assertIsNone(
            check_unsafe_flags(["--input", "request.json"], spec)
        )


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


class TestClassifySqlText(unittest.TestCase):
    def test_simple_select_safe(self):
        d, _ = classify_sql_text("sqlite3", "SELECT * FROM foo")
        self.assertEqual(d, DECISION_SAFE)

    def test_select_with_subquery_safe(self):
        sql = (
            "SELECT sync_status, COALESCE(sync_error,'none') AS err, "
            "(SELECT count(*) FROM t WHERE path='x') AS n "
            "FROM s WHERE path='x';"
        )
        d, _ = classify_sql_text("sqlite3", sql)
        self.assertEqual(d, DECISION_SAFE)

    def test_with_cte_select_safe(self):
        d, _ = classify_sql_text(
            "psql",
            "WITH t AS (SELECT 1) SELECT * FROM t",
        )
        self.assertEqual(d, DECISION_SAFE)

    def test_insert_unsafe(self):
        d, _ = classify_sql_text("psql", "INSERT INTO t VALUES (1)")
        self.assertEqual(d, DECISION_UNSAFE)

    def test_update_unsafe(self):
        d, _ = classify_sql_text("mysql", "UPDATE t SET x = 1 WHERE id = 2")
        self.assertEqual(d, DECISION_UNSAFE)

    def test_delete_unsafe(self):
        d, _ = classify_sql_text("psql", "DELETE FROM t WHERE id = 1")
        self.assertEqual(d, DECISION_UNSAFE)

    def test_drop_unsafe(self):
        d, _ = classify_sql_text("sqlite3", "DROP TABLE foo")
        self.assertEqual(d, DECISION_UNSAFE)

    def test_create_unsafe(self):
        d, _ = classify_sql_text("psql", "CREATE TABLE t (id int)")
        self.assertEqual(d, DECISION_UNSAFE)

    def test_alter_unsafe(self):
        d, _ = classify_sql_text("psql", "ALTER TABLE t ADD COLUMN x int")
        self.assertEqual(d, DECISION_UNSAFE)

    def test_truncate_unsafe(self):
        d, _ = classify_sql_text("mysql", "TRUNCATE TABLE t")
        self.assertEqual(d, DECISION_UNSAFE)

    def test_with_cte_delete_unsafe(self):
        # CTE with mutating tail.
        d, _ = classify_sql_text(
            "psql",
            "WITH t AS (SELECT id FROM s) DELETE FROM s WHERE id IN (SELECT id FROM t)",
        )
        self.assertEqual(d, DECISION_UNSAFE)

    def test_delete_in_string_literal_safe(self):
        # The string literal is stripped before scanning.
        d, _ = classify_sql_text(
            "psql",
            "SELECT name FROM users WHERE label = 'DELETE FROM users'",
        )
        self.assertEqual(d, DECISION_SAFE)

    def test_delete_in_line_comment_does_not_flag(self):
        d, _ = classify_sql_text(
            "psql",
            "SELECT 1 -- DELETE FROM x\nFROM dual",
        )
        self.assertEqual(d, DECISION_SAFE)

    def test_delete_in_block_comment_does_not_flag(self):
        d, _ = classify_sql_text(
            "psql",
            "SELECT 1 /* DELETE FROM x */ FROM dual",
        )
        self.assertEqual(d, DECISION_SAFE)

    def test_multiple_statements_one_unsafe(self):
        d, _ = classify_sql_text(
            "psql",
            "SELECT 1; INSERT INTO t VALUES (1); SELECT 2;",
        )
        self.assertEqual(d, DECISION_UNSAFE)

    def test_explain_safe(self):
        d, _ = classify_sql_text("psql", "EXPLAIN SELECT * FROM t")
        self.assertEqual(d, DECISION_SAFE)

    def test_show_safe(self):
        d, _ = classify_sql_text("mysql", "SHOW TABLES")
        self.assertEqual(d, DECISION_SAFE)

    def test_describe_safe(self):
        d, _ = classify_sql_text("mysql", "DESCRIBE foo")
        self.assertEqual(d, DECISION_SAFE)

    def test_pragma_read_safe(self):
        d, _ = classify_sql_text("sqlite3", "PRAGMA table_info(foo)")
        self.assertEqual(d, DECISION_SAFE)

    def test_pragma_assignment_unsafe(self):
        d, _ = classify_sql_text("sqlite3", "PRAGMA journal_mode = WAL")
        self.assertEqual(d, DECISION_UNSAFE)

    def test_unknown_first_keyword(self):
        d, _ = classify_sql_text("psql", "BANANA FROM t")
        self.assertEqual(d, DECISION_UNKNOWN)

    def test_empty_sql_safe(self):
        d, _ = classify_sql_text("sqlite3", "")
        self.assertEqual(d, DECISION_SAFE)

    def test_sqlite_dot_tables_safe(self):
        d, _ = classify_sql_text("sqlite3", ".tables")
        self.assertEqual(d, DECISION_SAFE)

    def test_sqlite_dot_schema_safe(self):
        d, _ = classify_sql_text("sqlite3", ".schema foo")
        self.assertEqual(d, DECISION_SAFE)

    def test_sqlite_dot_import_unsafe(self):
        d, _ = classify_sql_text("sqlite3", ".import foo.csv mytable")
        self.assertEqual(d, DECISION_UNSAFE)

    def test_sqlite_dot_unknown_falls_through(self):
        d, _ = classify_sql_text("sqlite3", ".weirdcmd foo")
        self.assertEqual(d, DECISION_UNKNOWN)

    def test_select_with_single_quote_escape(self):
        # 'don''t' is a single-quoted string containing an escaped quote.
        d, _ = classify_sql_text(
            "psql",
            "SELECT 'don''t' FROM dual",
        )
        self.assertEqual(d, DECISION_SAFE)


class TestParseSqlCliArgv(unittest.TestCase):
    def test_sqlite3_positional_sql(self):
        spec = {"sql_positional_index": 1}
        sqls, file_in = parse_sql_cli_argv(
            ["/path/db.sqlite", "SELECT 1"], spec,
        )
        self.assertEqual(sqls, ["SELECT 1"])
        self.assertFalse(file_in)

    def test_sqlite3_interactive_no_sql(self):
        spec = {"sql_positional_index": 1}
        sqls, _ = parse_sql_cli_argv(["/path/db.sqlite"], spec)
        self.assertEqual(sqls, [])

    def test_psql_dash_c_flag(self):
        spec = {"sql_flags": ["-c", "--command"]}
        sqls, _ = parse_sql_cli_argv(
            ["-c", "SELECT 1", "mydb"], spec,
        )
        self.assertEqual(sqls, ["SELECT 1"])

    def test_mysql_dash_e_flag(self):
        spec = {"sql_flags": ["-e", "--execute"]}
        sqls, _ = parse_sql_cli_argv(
            ["-e", "SHOW TABLES", "mydb"], spec,
        )
        self.assertEqual(sqls, ["SHOW TABLES"])

    def test_long_flag_with_equals(self):
        spec = {"sql_flags": ["-e", "--execute"]}
        sqls, _ = parse_sql_cli_argv(
            ["--execute=SELECT 1"], spec,
        )
        self.assertEqual(sqls, ["SELECT 1"])

    def test_file_input_flag(self):
        spec = {"sql_file_flags": ["-f", "--file"]}
        _, file_in = parse_sql_cli_argv(["-f", "queries.sql"], spec)
        self.assertTrue(file_in)

    def test_valueless_flag_does_not_consume_positional(self):
        spec = {
            "sql_positional_index": 1,
            "valueless_flags": ["-batch"],
        }
        sqls, _ = parse_sql_cli_argv(
            ["-batch", "/path/db", "SELECT 1"], spec,
        )
        self.assertEqual(sqls, ["SELECT 1"])

    def test_short_flag_with_value_consumes_next(self):
        # `-cmd CMD` form (sqlite3): no `--`, takes a value.
        spec = {"sql_flags": ["-cmd"], "sql_positional_index": 1}
        sqls, _ = parse_sql_cli_argv(
            ["-cmd", "SELECT 1", "/path/db"], spec,
        )
        # `-cmd` captured as SQL flag; remaining positional[0] is the DB,
        # no positional[1].
        self.assertEqual(sqls, ["SELECT 1"])


class TestValidateShellRules(unittest.TestCase):
    def test_default_rules_validate_clean(self):
        rules = load_shell_rules(REPO_ROOT / "rules")
        errors = validate_shell_rules(rules)
        self.assertEqual(
            errors, [],
            "rules/shell.json has schema drift: {}".format(errors),
        )

    def test_unknown_top_level_key_flagged(self):
        errors = validate_shell_rules({"bogus_key": []})
        self.assertTrue(any("bogus_key" in e for e in errors), errors)

    def test_unknown_command_key_flagged(self):
        errors = validate_shell_rules({
            "commands": {"mycli": {"default": "safe", "made_up_flag": []}}
        })
        self.assertTrue(any("made_up_flag" in e for e in errors), errors)

    def test_unknown_default_flagged(self):
        errors = validate_shell_rules({
            "commands": {"mycli": {"default": "not-a-real-default"}}
        })
        self.assertTrue(
            any("not-a-real-default" in e for e in errors), errors,
        )

    def test_unknown_nested_subcommand_key_flagged(self):
        errors = validate_shell_rules({
            "commands": {
                "mycli": {
                    "default": "subcommand",
                    "nested_subcommand": {
                        "sub": {"default": "safe", "ghost_field": []},
                    },
                },
            },
        })
        self.assertTrue(any("ghost_field" in e for e in errors), errors)

    def test_unknown_service_override_key_flagged(self):
        errors = validate_shell_rules({
            "commands": {
                "aws": {
                    "default": "aws_cli",
                    "service_overrides": {
                        "s3": {"bogus": []},
                    },
                },
            },
        })
        self.assertTrue(any("bogus" in e for e in errors), errors)

    def test_unknown_interpreter_key_flagged(self):
        errors = validate_shell_rules({
            "interpreters": {
                "python3": {"inline_flag": "-c", "weird_field": []},
            },
        })
        self.assertTrue(any("weird_field" in e for e in errors), errors)

    def test_unknown_nested_module_key_flagged(self):
        errors = validate_shell_rules({
            "interpreters": {
                "python3": {
                    "module_flag": "-m",
                    "nested_modules": {
                        "pip": {"safe_subcommands": ["list"], "rogue": []},
                    },
                },
            },
        })
        self.assertTrue(any("rogue" in e for e in errors), errors)

    def test_nested_module_unknown_default_flagged(self):
        # `_classify_nested_module` only resolves "safe" and "unsafe"; any
        # other value silently degrades to `unknown` at classify time.
        errors = validate_shell_rules({
            "interpreters": {
                "python3": {
                    "module_flag": "-m",
                    "nested_modules": {
                        "pip": {"default": "bogus"},
                    },
                },
            },
        })
        self.assertTrue(
            any("bogus" in e and "default" in e for e in errors), errors,
        )

    def test_nested_module_safe_default_accepted(self):
        errors = validate_shell_rules({
            "interpreters": {
                "python3": {
                    "module_flag": "-m",
                    "nested_modules": {
                        "unittest": {"default": "safe"},
                    },
                },
            },
        })
        self.assertEqual(errors, [])

    def test_nested_module_unsafe_default_accepted(self):
        errors = validate_shell_rules({
            "interpreters": {
                "python3": {
                    "module_flag": "-m",
                    "nested_modules": {
                        "blah": {"default": "unsafe"},
                    },
                },
            },
        })
        self.assertEqual(errors, [])


class TestLoadShellRulesValidation(unittest.TestCase):
    """Verify validation is wired into `load_shell_rules` itself — the
    production load path used by the hook entry and CLI — not just into
    tests that call `validate_shell_rules` directly."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="yolt-shell-rules-")
        self.tmp = Path(self._tmp)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _write(self, name, data):
        path = self.tmp / name
        path.write_text(json.dumps(data))
        return path

    def test_real_rules_load_clean(self):
        # The bundled rules/shell.json must load through the validating
        # path without raising.
        rules = load_shell_rules(REPO_ROOT / "rules")
        self.assertIn("commands", rules)

    def test_malformed_default_raises(self):
        # Drop a malformed rules dir in place of the real one.
        rules_dir = self.tmp / "rules"
        rules_dir.mkdir()
        (rules_dir / "shell.json").write_text(json.dumps({
            "commands": {"mycli": {"default": "totally-made-up"}},
        }))
        from rule_classifier import ShellRulesValidationError
        with self.assertRaises(ShellRulesValidationError) as ctx:
            load_shell_rules(rules_dir)
        self.assertTrue(
            any("totally-made-up" in e for e in ctx.exception.errors),
            ctx.exception.errors,
        )

    def test_malformed_override_raises(self):
        # Real defaults are clean; the user override introduces drift.
        override = self._write("shell.json", {
            "commands": {"mycli": {"default": "safe", "phantom_key": []}},
        })
        from rule_classifier import ShellRulesValidationError
        with self.assertRaises(ShellRulesValidationError) as ctx:
            load_shell_rules(REPO_ROOT / "rules", user_overrides_path=override)
        self.assertTrue(
            any("phantom_key" in e for e in ctx.exception.errors),
            ctx.exception.errors,
        )

    def test_validate_false_bypasses_check(self):
        rules_dir = self.tmp / "rules"
        rules_dir.mkdir()
        (rules_dir / "shell.json").write_text(json.dumps({
            "commands": {"mycli": {"default": "totally-made-up"}},
        }))
        rules = load_shell_rules(rules_dir, validate=False)
        self.assertIn("commands", rules)


if __name__ == "__main__":
    unittest.main()
