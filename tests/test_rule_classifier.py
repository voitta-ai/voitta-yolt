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
    RuleClassifier,
    aggregate_decisions,
    check_unsafe_flags,
    classify_sql_text,
    extract_flag_value,
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

    # write_flag_value_targets: flag value is a write-target path,
    # decision routes through the top-level safe_write_targets white list.
    # Repros from issue #27 (find -fprint / -fprintf / -fls / -fls0).

    def test_write_flag_value_targets_unsafe_outside_allow(self):
        spec = {"write_flag_value_targets": ["-fprint"]}
        result = check_unsafe_flags(
            ["-fprint", "/etc/profile"], spec,
            safe_write_targets=["/tmp/*", "/dev/null"],
        )
        self.assertIsNotNone(result)
        self.assertIn("-fprint", result)
        self.assertIn("/etc/profile", result)

    def test_write_flag_value_targets_safe_in_allow(self):
        spec = {"write_flag_value_targets": ["-fprint"]}
        self.assertIsNone(check_unsafe_flags(
            ["-fprint", "/tmp/list.txt"], spec,
            safe_write_targets=["/tmp/*", "/dev/null"],
        ))

    def test_write_flag_value_targets_fprintf_first_arg_is_path(self):
        # -fprintf FILE FORMAT — only the FILE position is the write target.
        spec = {"write_flag_value_targets": ["-fprintf"]}
        self.assertIsNotNone(check_unsafe_flags(
            ["-fprintf", "/etc/passwd", "%p\n"], spec,
            safe_write_targets=["/tmp/*"],
        ))
        self.assertIsNone(check_unsafe_flags(
            ["-fprintf", "/tmp/out.txt", "%p\n"], spec,
            safe_write_targets=["/tmp/*"],
        ))

    def test_write_flag_value_targets_no_value(self):
        # Flag at end of argv with no following value — no match.
        spec = {"write_flag_value_targets": ["-fprint"]}
        self.assertIsNone(check_unsafe_flags(
            ["-fprint"], spec, safe_write_targets=["/tmp/*"],
        ))

    def test_write_flag_value_targets_empty_white_list_blocks_everything(self):
        # No safe_write_targets configured -> any value is unsafe.
        spec = {"write_flag_value_targets": ["-fprint"]}
        self.assertIsNotNone(check_unsafe_flags(
            ["-fprint", "/tmp/list.txt"], spec, safe_write_targets=[],
        ))
        self.assertIsNotNone(check_unsafe_flags(
            ["-fprint", "/tmp/list.txt"], spec, safe_write_targets=None,
        ))

    def test_write_flag_value_targets_home_expansion(self):
        spec = {"write_flag_value_targets": ["-fprint"]}
        # ~/.cache/* in white list matches user-supplied ~/.cache/foo.
        self.assertIsNone(check_unsafe_flags(
            ["-fprint", "~/.cache/list.txt"], spec,
            safe_write_targets=["~/.cache/*"],
        ))

    def test_write_flag_value_targets_inline_equals_form(self):
        # find doesn't use --flag=value but the parser supports it
        # uniformly; cover for consistency with other flag families.
        spec = {"write_flag_value_targets": ["--out"]}
        self.assertIsNotNone(check_unsafe_flags(
            ["--out=/etc/profile"], spec, safe_write_targets=["/tmp/*"],
        ))
        self.assertIsNone(check_unsafe_flags(
            ["--out=/tmp/out.txt"], spec, safe_write_targets=["/tmp/*"],
        ))


class TestUnsafeWriteTargetArgs(unittest.TestCase):
    """Deny-list routing of write-target arguments (issue #28).

    `unsafe_write_targets` upgrades the *reason* for a protected-path
    write. The flag-value path is checked deny-first (before the safe
    white list); positional and `value=` prefix targets consult only the
    deny list, since the commands carrying them are already
    `default: unsafe`."""

    DENY = ["~/.bashrc", "~/.ssh/id_*", "/etc/*"]

    def test_flag_value_deny_takes_priority_over_safe(self):
        # A deny match wins even if the same path were on the safe list.
        spec = {"write_flag_value_targets": ["-t"]}
        result = check_unsafe_flags(
            ["-t", "/etc/foo"], spec,
            safe_write_targets=["/etc/*"],
            unsafe_write_targets=self.DENY,
        )
        self.assertIsNotNone(result)
        self.assertIn("/etc/foo", result)
        self.assertIn("protected path", result)

    def test_flag_value_non_deny_falls_through_to_safe_check(self):
        # Not on the deny list and on the safe list -> not flagged here.
        spec = {"write_flag_value_targets": ["-t"]}
        self.assertIsNone(check_unsafe_flags(
            ["-t", "/tmp/x"], spec,
            safe_write_targets=["/tmp/*"],
            unsafe_write_targets=self.DENY,
        ))

    def test_value_prefix_target_deny(self):
        # dd of=PATH.
        spec = {"write_value_prefix_targets": ["of="]}
        result = check_unsafe_flags(
            ["if=/dev/zero", "of=~/.ssh/id_rsa"], spec,
            unsafe_write_targets=self.DENY,
        )
        self.assertIsNotNone(result)
        self.assertIn("~/.ssh/id_rsa", result)

    def test_value_prefix_read_source_not_flagged(self):
        # if= is the read source; only of= is a write target.
        spec = {"write_value_prefix_targets": ["of="]}
        self.assertIsNone(check_unsafe_flags(
            ["if=~/.bashrc", "of=/var/data"], spec,
            unsafe_write_targets=self.DENY,
        ))

    def test_last_positional_deny(self):
        # cp SRC DST -> DST is the last positional.
        spec = {"write_target_last_positional": True}
        result = check_unsafe_flags(
            ["a", "/etc/cron.d/job"], spec,
            unsafe_write_targets=self.DENY,
        )
        self.assertIsNotNone(result)
        self.assertIn("/etc/cron.d/job", result)

    def test_last_positional_source_not_flagged(self):
        # Reading a deny path while writing a benign dest is not flagged
        # by the deny scan (cp ~/.bashrc /tmp/x).
        spec = {"write_target_last_positional": True}
        self.assertIsNone(check_unsafe_flags(
            ["~/.bashrc", "/tmp/x"], spec,
            unsafe_write_targets=self.DENY,
        ))

    def test_all_positional_deny_any_match(self):
        # tee FILE... -> every positional is a write target.
        spec = {"write_target_all_positional": True}
        result = check_unsafe_flags(
            ["-a", "/tmp/log", "~/.bashrc"], spec,
            unsafe_write_targets=self.DENY,
        )
        self.assertIsNotNone(result)
        self.assertIn("~/.bashrc", result)

    def test_no_deny_list_is_noop(self):
        # Without a deny list the new scan does nothing (the command
        # default still applies upstream).
        spec = {"write_target_last_positional": True}
        self.assertIsNone(check_unsafe_flags(
            ["a", "/etc/cron.d/job"], spec, unsafe_write_targets=None,
        ))


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


class TestExtractFlagValue(unittest.TestCase):
    def test_space_form(self):
        v = extract_flag_value(["--sql", "SELECT 1", "--db", "x"], "--sql")
        self.assertEqual(v, "SELECT 1")

    def test_equals_form(self):
        v = extract_flag_value(["--query-string=SELECT 1"], "--query-string")
        self.assertEqual(v, "SELECT 1")

    def test_equals_form_value_with_equals(self):
        v = extract_flag_value(["--sql=SET x = 1"], "--sql")
        self.assertEqual(v, "SET x = 1")

    def test_absent(self):
        self.assertIsNone(extract_flag_value(["--db", "x"], "--sql"))

    def test_flag_last_token_no_value(self):
        self.assertIsNone(extract_flag_value(["--db", "x", "--sql"], "--sql"))


class TestAwsSqlPayloadFlags(unittest.TestCase):
    """Payload scanning of SQL-carrying aws flags (issue #29). The verb
    decision is a floor: start-*/execute-* stay unsafe unless an override
    marks the op safe, after which the SQL governs. timestream-query query
    (verb -> unknown) is refined by its payload out of the box."""

    @classmethod
    def setUpClass(cls):
        rules = load_shell_rules(REPO_ROOT / "rules")
        cls.clf = RuleClassifier(rules)
        cls.spec = rules["commands"]["aws"]

        # A second classifier whose rules mark athena start-query-execution
        # safe (the override the issue's narrowing use case relies on).
        ov_rules = json.loads(json.dumps(rules))
        ov_aws = ov_rules["commands"]["aws"]
        ov_aws["service_overrides"].setdefault("athena", {})[
            "extra_safe_patterns"
        ] = ["start-query-execution"]
        cls.clf_override = RuleClassifier(ov_rules)
        cls.spec_override = ov_aws

    def test_timestream_select_safe(self):
        d, _ = self.clf.classify_aws(
            ["timestream-query", "query", "--query-string", "SELECT * FROM t"],
            self.spec,
        )
        self.assertEqual(d, DECISION_SAFE)

    def test_timestream_delete_unsafe(self):
        d, _ = self.clf.classify_aws(
            ["timestream-query", "query", "--query-string", "DELETE FROM t"],
            self.spec,
        )
        self.assertEqual(d, DECISION_UNSAFE)

    def test_timestream_missing_flag_unknown(self):
        # verb -> unknown and no payload to scan -> stays unknown.
        d, _ = self.clf.classify_aws(
            ["timestream-query", "query"], self.spec,
        )
        self.assertEqual(d, DECISION_UNKNOWN)

    def test_athena_select_no_override_is_unsafe_floor(self):
        # start-* is a write verb; without an override the payload cannot
        # weaken it.
        d, _ = self.clf.classify_aws(
            ["athena", "start-query-execution", "--query-string", "SELECT 1"],
            self.spec,
        )
        self.assertEqual(d, DECISION_UNSAFE)

    def test_rds_data_select_no_override_is_unsafe_floor(self):
        d, _ = self.clf.classify_aws(
            ["rds-data", "execute-statement", "--sql", "SELECT 1"],
            self.spec,
        )
        self.assertEqual(d, DECISION_UNSAFE)

    def test_redshift_data_equals_form_select_no_override_unsafe(self):
        d, _ = self.clf.classify_aws(
            ["redshift-data", "execute-statement", "--sql=SELECT 1"],
            self.spec,
        )
        self.assertEqual(d, DECISION_UNSAFE)

    def test_athena_select_with_safe_override_is_safe(self):
        d, _ = self.clf_override.classify_aws(
            ["athena", "start-query-execution", "--query-string", "SELECT 1"],
            self.spec_override,
        )
        self.assertEqual(d, DECISION_SAFE)

    def test_athena_drop_with_safe_override_still_unsafe(self):
        d, _ = self.clf_override.classify_aws(
            ["athena", "start-query-execution",
             "--query-string", "DROP TABLE t"],
            self.spec_override,
        )
        self.assertEqual(d, DECISION_UNSAFE)

    def test_athena_unclassifiable_with_safe_override_is_unknown(self):
        # A safe override does not blanket-allow SQL the scanner cannot read.
        d, _ = self.clf_override.classify_aws(
            ["athena", "start-query-execution",
             "--query-string", "FROBNICATE x"],
            self.spec_override,
        )
        self.assertEqual(d, DECISION_UNKNOWN)

    def test_athena_missing_flag_with_safe_override_is_unknown(self):
        # A registered SQL op with a safe override but no --query-string must
        # NOT inherit the blanket-safe verb decision: the payload is
        # unscannable, so it downgrades to unknown rather than safe.
        d, _ = self.clf_override.classify_aws(
            ["athena", "start-query-execution"],
            self.spec_override,
        )
        self.assertEqual(d, DECISION_UNKNOWN)

    def test_athena_cli_input_json_with_safe_override_is_unknown(self):
        # Alternate input form (--cli-input-json) carries the SQL off the
        # scanned flag; a safe override must not blanket-allow it.
        d, _ = self.clf_override.classify_aws(
            ["athena", "start-query-execution",
             "--cli-input-json", '{"QueryString": "DROP TABLE t"}'],
            self.spec_override,
        )
        self.assertEqual(d, DECISION_UNKNOWN)

    def test_unregistered_operation_untouched(self):
        # An aws op with no registry entry keeps its plain verb decision.
        d, _ = self.clf.classify_aws(
            ["ec2", "describe-instances"], self.spec,
        )
        self.assertEqual(d, DECISION_SAFE)


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


class TestSqlFunctionSideEffects(unittest.TestCase):
    """Issue #26: side-effecting functions called from inside a read-looking
    statement must not classify safe just because the first keyword is
    SELECT/WITH/etc."""

    def test_pg_terminate_backend_unsafe(self):
        d, _ = classify_sql_text("psql", "SELECT pg_terminate_backend(12345)")
        self.assertEqual(d, DECISION_UNSAFE)

    def test_pg_cancel_backend_unsafe(self):
        d, _ = classify_sql_text("psql", "SELECT pg_cancel_backend(12345)")
        self.assertEqual(d, DECISION_UNSAFE)

    def test_pg_read_file_unsafe(self):
        d, _ = classify_sql_text("psql", "SELECT pg_read_file('/etc/passwd')")
        self.assertEqual(d, DECISION_UNSAFE)

    def test_pg_sleep_unsafe(self):
        d, _ = classify_sql_text("psql", "SELECT pg_sleep(1e9)")
        self.assertEqual(d, DECISION_UNSAFE)

    def test_nextval_unsafe(self):
        d, _ = classify_sql_text("psql", "SELECT nextval('s')")
        self.assertEqual(d, DECISION_UNSAFE)

    def test_setval_unsafe(self):
        d, _ = classify_sql_text("psql", "SELECT setval('s', 1)")
        self.assertEqual(d, DECISION_UNSAFE)

    def test_dblink_exec_unsafe(self):
        d, _ = classify_sql_text(
            "psql", "SELECT dblink_exec('conn', 'DROP TABLE t')")
        self.assertEqual(d, DECISION_UNSAFE)

    def test_set_config_unsafe(self):
        d, _ = classify_sql_text(
            "psql", "SELECT set_config('search_path', 'evil', false)")
        self.assertEqual(d, DECISION_UNSAFE)

    def test_pg_unknown_system_function_unsafe(self):
        # pg_* prefix is denied unless on the read-only allowlist.
        d, _ = classify_sql_text("psql", "SELECT pg_switch_wal()")
        self.assertEqual(d, DECISION_UNSAFE)

    def test_pg_database_size_safe(self):
        d, _ = classify_sql_text("psql", "SELECT pg_database_size('db')")
        self.assertEqual(d, DECISION_SAFE)

    def test_pg_relation_size_safe(self):
        d, _ = classify_sql_text("psql", "SELECT pg_relation_size('t')")
        self.assertEqual(d, DECISION_SAFE)

    def test_pg_get_prefix_safe(self):
        d, _ = classify_sql_text("psql", "SELECT pg_get_constraintdef(1)")
        self.assertEqual(d, DECISION_SAFE)

    def test_pg_typeof_safe(self):
        d, _ = classify_sql_text("psql", "SELECT pg_typeof(1)")
        self.assertEqual(d, DECISION_SAFE)

    def test_do_block_unsafe(self):
        # DO is now a mutating keyword; the anonymous block can side-effect.
        d, _ = classify_sql_text(
            "psql",
            "DO $$ BEGIN PERFORM pg_terminate_backend(0); END $$",
        )
        self.assertEqual(d, DECISION_UNSAFE)

    def test_mysql_get_lock_unsafe(self):
        d, _ = classify_sql_text("mysql", "SELECT GET_LOCK('x', 9999)")
        self.assertEqual(d, DECISION_UNSAFE)

    def test_mysql_sleep_unsafe(self):
        d, _ = classify_sql_text("mysql", "SELECT SLEEP(1e9)")
        self.assertEqual(d, DECISION_UNSAFE)

    def test_mysql_benchmark_unsafe(self):
        d, _ = classify_sql_text("mysql", "SELECT BENCHMARK(1e9, MD5('x'))")
        self.assertEqual(d, DECISION_UNSAFE)

    def test_mysql_load_file_unsafe(self):
        d, _ = classify_sql_text("mysql", "SELECT LOAD_FILE('/etc/passwd')")
        self.assertEqual(d, DECISION_UNSAFE)

    def test_mysql_into_outfile_unsafe(self):
        d, _ = classify_sql_text(
            "mysql", "SELECT * FROM t INTO OUTFILE '/tmp/x'")
        self.assertEqual(d, DECISION_UNSAFE)

    def test_mysql_into_dumpfile_unsafe(self):
        d, _ = classify_sql_text(
            "mysql", "SELECT * FROM t INTO DUMPFILE '/tmp/x'")
        self.assertEqual(d, DECISION_UNSAFE)

    def test_mariadb_sleep_unsafe(self):
        d, _ = classify_sql_text("mariadb", "SELECT SLEEP(99)")
        self.assertEqual(d, DECISION_UNSAFE)

    def test_sqlite_load_extension_unsafe(self):
        d, _ = classify_sql_text(
            "sqlite3", "SELECT load_extension('/path/to/evil.so')")
        self.assertEqual(d, DECISION_UNSAFE)

    def test_sqlite_randomblob_unsafe(self):
        d, _ = classify_sql_text("sqlite3", "SELECT randomblob(1099511627776)")
        self.assertEqual(d, DECISION_UNSAFE)

    def test_explain_analyze_insert_unsafe(self):
        # Postgres EXPLAIN ANALYZE executes the wrapped DML.
        d, _ = classify_sql_text(
            "psql", "EXPLAIN ANALYZE INSERT INTO t VALUES (1)")
        self.assertEqual(d, DECISION_UNSAFE)

    def test_with_cte_delete_returning_unsafe(self):
        # DML in a CTE; scanner is not gated on the first keyword only.
        d, _ = classify_sql_text(
            "psql",
            "WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d",
        )
        self.assertEqual(d, DECISION_UNSAFE)

    def test_function_name_in_literal_stays_safe(self):
        # A denied function name inside a string literal is stripped first.
        d, _ = classify_sql_text(
            "psql", "SELECT name FROM users WHERE note = 'pg_sleep(9)'")
        self.assertEqual(d, DECISION_SAFE)

    def test_function_name_in_dollar_quote_stays_safe(self):
        # Postgres dollar-quoted string literal is stripped before scanning.
        d, _ = classify_sql_text("psql", "SELECT $$pg_sleep(9)$$")
        self.assertEqual(d, DECISION_SAFE)

    def test_function_name_in_tagged_dollar_quote_stays_safe(self):
        d, _ = classify_sql_text("psql", "SELECT $tag$pg_sleep(9)$tag$")
        self.assertEqual(d, DECISION_SAFE)

    def test_outfile_column_name_safe(self):
        # Bare OUTFILE/DUMPFILE without INTO context is a plain identifier.
        d, _ = classify_sql_text("mysql", "SELECT outfile FROM t")
        self.assertEqual(d, DECISION_SAFE)

    def test_dumpfile_column_name_safe(self):
        d, _ = classify_sql_text("mysql", "SELECT dumpfile FROM t")
        self.assertEqual(d, DECISION_SAFE)

    def test_from_outfile_table_name_safe(self):
        d, _ = classify_sql_text("mysql", "SELECT * FROM outfile")
        self.assertEqual(d, DECISION_SAFE)

    def test_plain_select_still_safe(self):
        d, _ = classify_sql_text("psql", "SELECT * FROM users WHERE id = 1")
        self.assertEqual(d, DECISION_SAFE)

    def test_count_function_safe(self):
        # Ordinary aggregate functions are not on any deny list.
        d, _ = classify_sql_text("mysql", "SELECT COUNT(*) FROM t")
        self.assertEqual(d, DECISION_SAFE)

    def test_dialect_param_overrides_cli_lookup(self):
        # A synthetic cmd_name (payload scanning of cloud-API flags) is not a
        # known SQL CLI, so the explicit dialect routes function detection.
        cmd = "aws athena start-query-execution"
        d, _ = classify_sql_text(
            cmd, "SELECT load_extension('x')", dialect="sqlite")
        self.assertEqual(d, DECISION_UNSAFE)

    def test_dialect_none_skips_function_scan(self):
        # Without a resolvable dialect the function scanner is a no-op, so a
        # SELECT-shaped statement classifies safe on the keyword scan alone.
        cmd = "aws athena start-query-execution"
        d, _ = classify_sql_text(cmd, "SELECT load_extension('x')")
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

    def test_unknown_sql_payload_flag_key_flagged(self):
        errors = validate_shell_rules({
            "commands": {
                "aws": {
                    "default": "aws_cli",
                    "sql_payload_flags": {
                        "athena start-query-execution": {
                            "flag": "--query-string", "ghost": 1,
                        },
                    },
                },
            },
        })
        self.assertTrue(any("ghost" in e for e in errors), errors)

    def test_sql_payload_flag_missing_flag_flagged(self):
        errors = validate_shell_rules({
            "commands": {
                "aws": {
                    "default": "aws_cli",
                    "sql_payload_flags": {
                        "athena start-query-execution": {"dialect": "presto"},
                    },
                },
            },
        })
        self.assertTrue(any("missing 'flag'" in e for e in errors), errors)

    def test_sql_payload_flag_note_key_allowed(self):
        # Underscore-prefixed meta keys are skipped, not treated as entries.
        errors = validate_shell_rules({
            "commands": {
                "aws": {
                    "default": "aws_cli",
                    "sql_payload_flags": {
                        "_note": "doc string, not an entry",
                        "athena start-query-execution": {
                            "flag": "--query-string",
                        },
                    },
                },
            },
        })
        self.assertEqual(errors, [])

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
