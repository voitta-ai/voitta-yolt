"""Unit tests for hooks/shell_classifier.py.

Runs with stdlib unittest (no external dependencies, matching the project's
zero-dependency design principle):

    python3 -m unittest discover -v tests
"""

import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
HOOKS_DIR = REPO_ROOT / "hooks"
sys.path.insert(0, str(HOOKS_DIR))

from shell_classifier import (  # noqa: E402
    DECISION_SAFE,
    DECISION_UNKNOWN,
    DECISION_UNSAFE,
    ShellClassifier,
    SUBSTITUTION_PLACEHOLDER,
    aggregate_decisions,
    check_unsafe_flags,
    extract_substitutions,
    load_shell_rules,
    parse_aws_positionals,
    split_top_level,
    strip_leading_keywords_and_assignments,
    strip_redirections,
)
from yolt_analyzer import SafetyAnalyzer, load_rules as load_py_rules  # noqa: E402


def _make_classifier():
    shell_rules = load_shell_rules(REPO_ROOT / "rules")
    py_rules = load_py_rules(REPO_ROOT / "rules")

    def _factory():
        retval = SafetyAnalyzer(py_rules)
        return retval

    retval = ShellClassifier(shell_rules, python_analyzer_factory=_factory)
    return retval


# Keyword set mirroring rules/shell.json#shell_keywords, used by stripper tests.
KEYWORDS = {
    "if", "then", "else", "elif", "fi",
    "for", "while", "until", "do", "done",
    "case", "esac", "in", "select",
    "function", "time", "coproc",
    "!", "{", "}", "(", ")",
}


class TestExtractSubstitutions(unittest.TestCase):
    def test_no_substitution(self):
        out, subs = extract_substitutions("ls /tmp")
        self.assertEqual(out, "ls /tmp")
        self.assertEqual(subs, [])

    def test_single_dollar_paren(self):
        out, subs = extract_substitutions("echo $(date)")
        self.assertIn(SUBSTITUTION_PLACEHOLDER, out)
        self.assertEqual(subs, ["date"])

    def test_backtick(self):
        out, subs = extract_substitutions("echo `date`")
        self.assertIn(SUBSTITUTION_PLACEHOLDER, out)
        self.assertEqual(subs, ["date"])

    def test_nested_substitution(self):
        out, subs = extract_substitutions("echo $(foo $(bar))")
        self.assertEqual(len(subs), 2)
        self.assertIn("bar", subs)

    def test_substitution_inside_double_quote_expanded(self):
        out, subs = extract_substitutions('echo "prefix $(date) suffix"')
        self.assertEqual(subs, ["date"])
        self.assertIn(SUBSTITUTION_PLACEHOLDER, out)

    def test_substitution_inside_single_quote_is_literal(self):
        out, subs = extract_substitutions("echo 'literal $(date)'")
        self.assertEqual(subs, [])
        self.assertEqual(out, "echo 'literal $(date)'")

    def test_unmatched_paren_passes_through(self):
        out, subs = extract_substitutions("echo $(incomplete")
        self.assertEqual(subs, [])
        self.assertIn("$(incomplete", out)


class TestSplitTopLevel(unittest.TestCase):
    def test_semicolon(self):
        self.assertEqual(split_top_level("ls; pwd"), ["ls", "pwd"])

    def test_double_ampersand(self):
        self.assertEqual(split_top_level("ls && pwd"), ["ls", "pwd"])

    def test_double_pipe(self):
        self.assertEqual(split_top_level("ls || pwd"), ["ls", "pwd"])

    def test_single_pipe(self):
        self.assertEqual(split_top_level("ls | grep foo"), ["ls", "grep foo"])

    def test_newline_splits(self):
        self.assertEqual(split_top_level("ls\npwd"), ["ls", "pwd"])

    def test_background_ampersand(self):
        self.assertEqual(split_top_level("ls & pwd"), ["ls", "pwd"])

    def test_quoted_separators_not_split(self):
        self.assertEqual(
            split_top_level('echo "a && b" || pwd'),
            ['echo "a && b"', "pwd"],
        )

    def test_single_quoted_separators_not_split(self):
        self.assertEqual(
            split_top_level("echo 'a; b; c' && pwd"),
            ["echo 'a; b; c'", "pwd"],
        )

    def test_double_semicolon_collapses(self):
        # Case-arm ;; produces an empty segment which is filtered out.
        self.assertEqual(split_top_level("ls ;; pwd"), ["ls", "pwd"])


class TestStripRedirections(unittest.TestCase):
    def test_standalone_output_to_file_marked_as_write(self):
        tokens, writes = strip_redirections(["ls", ">", "file.txt"])
        self.assertEqual(tokens, ["ls"])
        self.assertTrue(writes)

    def test_standalone_output_to_dev_null_not_write(self):
        tokens, writes = strip_redirections(["ls", ">", "/dev/null"])
        self.assertEqual(tokens, ["ls"])
        self.assertFalse(writes)

    def test_attached_stderr_to_dev_null_not_write(self):
        tokens, writes = strip_redirections(["aws", "describe", "2>/dev/null"])
        self.assertEqual(tokens, ["aws", "describe"])
        self.assertFalse(writes)

    def test_attached_stderr_to_file_marked_as_write(self):
        tokens, writes = strip_redirections(["aws", "describe", "2>/tmp/err.log"])
        self.assertEqual(tokens, ["aws", "describe"])
        self.assertTrue(writes)

    def test_fd_duplicate_not_write(self):
        tokens, writes = strip_redirections(["cmd", "2>&1"])
        self.assertEqual(tokens, ["cmd"])
        self.assertFalse(writes)

    def test_stdin_redirection_not_write(self):
        tokens, writes = strip_redirections(["cat", "<", "input.txt"])
        self.assertEqual(tokens, ["cat"])
        self.assertFalse(writes)

    def test_append_to_file_marked_as_write(self):
        tokens, writes = strip_redirections(["echo", "x", ">>", "/var/log/app.log"])
        self.assertEqual(tokens, ["echo", "x"])
        self.assertTrue(writes)

    def test_amp_gt_all_to_file_marked_as_write(self):
        tokens, writes = strip_redirections(["cmd", "&>/tmp/out.log"])
        self.assertEqual(tokens, ["cmd"])
        self.assertTrue(writes)


class TestStripLeadingKeywords(unittest.TestCase):
    def test_no_keywords(self):
        tokens, wl = strip_leading_keywords_and_assignments(["ls", "/tmp"], KEYWORDS)
        self.assertEqual(tokens, ["ls", "/tmp"])
        self.assertFalse(wl)

    def test_for_var_in_marks_word_list(self):
        tokens, wl = strip_leading_keywords_and_assignments(
            ["for", "x", "in", "a", "b", "c"], KEYWORDS
        )
        self.assertEqual(tokens, ["a", "b", "c"])
        self.assertTrue(wl)

    def test_for_var_implicit_consumes_two(self):
        tokens, wl = strip_leading_keywords_and_assignments(["for", "x"], KEYWORDS)
        self.assertEqual(tokens, [])

    def test_case_word_in_strips_three(self):
        tokens, wl = strip_leading_keywords_and_assignments(
            ["case", "$x", "in"], KEYWORDS
        )
        self.assertEqual(tokens, [])

    def test_case_pattern_arm_dropped(self):
        tokens, wl = strip_leading_keywords_and_assignments(["a)", "ls"], KEYWORDS)
        self.assertEqual(tokens, ["ls"])

    def test_wildcard_pattern_arm_dropped(self):
        tokens, wl = strip_leading_keywords_and_assignments(["*)", "ls"], KEYWORDS)
        self.assertEqual(tokens, ["ls"])

    def test_env_assignment_chain(self):
        tokens, wl = strip_leading_keywords_and_assignments(
            ["FOO=bar", "BAZ=qux", "ls"], KEYWORDS
        )
        self.assertEqual(tokens, ["ls"])

    def test_if_then_stripped(self):
        tokens, wl = strip_leading_keywords_and_assignments(["if", "ls"], KEYWORDS)
        self.assertEqual(tokens, ["ls"])

    def test_negation_drop(self):
        tokens, wl = strip_leading_keywords_and_assignments(
            ["!", "rm", "-rf"], KEYWORDS
        )
        self.assertEqual(tokens, ["rm", "-rf"])


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


class TestClassifyScenarios(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.clf = _make_classifier()

    def assertDecision(self, command, expected):
        decision, reason = self.clf.classify(command)
        self.assertEqual(
            decision, expected,
            "{!r}: got {}, reason={}".format(command, decision, reason),
        )

    # --- Safe cases ---
    def test_ls_safe(self):
        self.assertDecision("ls /tmp", DECISION_SAFE)

    def test_aws_describe(self):
        self.assertDecision("aws ec2 describe-instances", DECISION_SAFE)

    def test_aws_describe_with_profile_flags(self):
        self.assertDecision(
            "aws --profile prod --region us-east-1 ec2 describe-instances --no-cli-pager",
            DECISION_SAFE,
        )

    def test_aws_s3_ls(self):
        self.assertDecision("aws s3 ls", DECISION_SAFE)

    def test_aws_logs_start_query_is_service_override_safe(self):
        self.assertDecision(
            'aws logs start-query --log-group-name X --query-string "fields @timestamp"',
            DECISION_SAFE,
        )

    def test_compound_for_loop_all_reads(self):
        self.assertDecision(
            'for svc in $(aws ecs list-services --cluster X); do '
            'aws ecs describe-services --cluster X --services "$svc"; '
            "done",
            DECISION_SAFE,
        )

    def test_gh_api_default_get(self):
        self.assertDecision("gh api /repos/x/y/issues", DECISION_SAFE)

    def test_curl_default_get(self):
        self.assertDecision("curl https://api.example.com/users", DECISION_SAFE)

    def test_kubectl_get_pods(self):
        self.assertDecision("kubectl get pods -A", DECISION_SAFE)

    def test_python3_c_inline_safe(self):
        self.assertDecision('python3 -c "print(1+1)"', DECISION_SAFE)

    def test_bash_c_inline_safe(self):
        self.assertDecision('bash -c "ls /tmp"', DECISION_SAFE)

    def test_time_wrapper(self):
        self.assertDecision("time aws ec2 describe-instances", DECISION_SAFE)

    def test_xargs_wraps_cat(self):
        self.assertDecision("echo foo | xargs cat", DECISION_SAFE)

    def test_redirect_to_dev_null_is_safe(self):
        self.assertDecision(
            "aws ec2 describe-instances > /dev/null", DECISION_SAFE
        )

    def test_stderr_to_dev_null_piped_to_jq_is_safe(self):
        self.assertDecision(
            "aws ec2 describe-instances 2>/dev/null | jq .",
            DECISION_SAFE,
        )

    def test_git_status(self):
        self.assertDecision("git status", DECISION_SAFE)

    def test_terraform_plan(self):
        self.assertDecision("terraform plan", DECISION_SAFE)

    def test_terraform_state_list_nested(self):
        self.assertDecision("terraform state list", DECISION_SAFE)

    def test_find_without_delete(self):
        self.assertDecision("find . -name '*.py'", DECISION_SAFE)

    def test_sed_without_inplace(self):
        self.assertDecision("sed 's/a/b/' file.txt", DECISION_SAFE)

    def test_double_bracket_test(self):
        self.assertDecision("[[ -d /tmp ]] && ls /tmp", DECISION_SAFE)

    def test_single_bracket_test(self):
        self.assertDecision("[ -d /tmp ] && ls /tmp", DECISION_SAFE)

    def test_command_group_safe(self):
        self.assertDecision("{ ls /tmp; echo done; }", DECISION_SAFE)

    def test_env_var_prefix_then_safe(self):
        self.assertDecision("FOO=bar BAZ=qux aws s3 ls", DECISION_SAFE)

    def test_case_all_reads(self):
        self.assertDecision(
            'case "$x" in a) ls ;; b) cat /etc/passwd ;; esac',
            DECISION_SAFE,
        )

    def test_if_then_safe_body(self):
        self.assertDecision(
            "if aws ec2 describe-instances; then echo ok; fi",
            DECISION_SAFE,
        )

    # --- Unsafe cases ---
    def test_rm_unsafe(self):
        self.assertDecision("rm -rf /tmp/foo", DECISION_UNSAFE)

    def test_aws_terminate_unsafe(self):
        self.assertDecision(
            "aws ec2 terminate-instances --instance-ids i-abc",
            DECISION_UNSAFE,
        )

    def test_aws_s3_rm_unsafe(self):
        self.assertDecision("aws s3 rm s3://bucket/key", DECISION_UNSAFE)

    def test_gh_api_post_unsafe(self):
        self.assertDecision(
            "gh api -X POST /repos/x/y/issues", DECISION_UNSAFE
        )

    def test_gh_api_field_unsafe(self):
        self.assertDecision(
            "gh api /repos/x/y/issues -f title=bug", DECISION_UNSAFE
        )

    def test_curl_post_unsafe(self):
        self.assertDecision(
            "curl -X POST https://api.example.com/users -d bar",
            DECISION_UNSAFE,
        )

    def test_curl_data_flag_unsafe(self):
        self.assertDecision(
            "curl --data foo=bar https://api.example.com/users",
            DECISION_UNSAFE,
        )

    def test_kubectl_exec_unsafe(self):
        self.assertDecision(
            "kubectl exec -it pod -- bash", DECISION_UNSAFE
        )

    def test_git_push_unsafe(self):
        self.assertDecision("git push origin main", DECISION_UNSAFE)

    def test_terraform_apply_unsafe(self):
        self.assertDecision("terraform apply", DECISION_UNSAFE)

    def test_terraform_state_rm_unsafe(self):
        self.assertDecision("terraform state rm foo.bar", DECISION_UNSAFE)

    def test_find_delete_unsafe(self):
        self.assertDecision("find . -name '*.py' -delete", DECISION_UNSAFE)

    def test_sed_inplace_unsafe(self):
        self.assertDecision("sed -i 's/a/b/' file.txt", DECISION_UNSAFE)

    def test_python3_c_os_system_unsafe(self):
        self.assertDecision(
            'python3 -c "import os; os.system(\\"rm -rf /\\")"',
            DECISION_UNSAFE,
        )

    def test_bash_c_rm_unsafe(self):
        self.assertDecision('bash -c "rm -rf /etc"', DECISION_UNSAFE)

    def test_xargs_wraps_rm_unsafe(self):
        self.assertDecision("echo foo | xargs rm", DECISION_UNSAFE)

    def test_compound_with_rm_unsafe(self):
        self.assertDecision("ls /tmp && rm -rf /etc", DECISION_UNSAFE)

    def test_case_has_rm_unsafe(self):
        self.assertDecision(
            'case "$x" in a) ls ;; b) rm /tmp/foo ;; esac',
            DECISION_UNSAFE,
        )

    def test_negated_rm_still_unsafe(self):
        self.assertDecision("! rm -rf /tmp/foo", DECISION_UNSAFE)

    # --- Unknown fall-throughs ---
    def test_unknown_command_is_unknown(self):
        self.assertDecision(
            "somecommand_unknown --flag", DECISION_UNKNOWN
        )

    def test_redirect_write_to_file_is_unknown(self):
        self.assertDecision(
            "aws ec2 describe-instances > out.json", DECISION_UNKNOWN
        )

    def test_echo_to_system_file_is_unknown(self):
        # `echo` alone is safe, but the classifier must not allow
        # `echo x > /etc/profile` to ride on that classification.
        self.assertDecision("echo x > /etc/profile", DECISION_UNKNOWN)


class TestClassifierCLI(unittest.TestCase):
    """The shell_classifier.py module is also runnable as a standalone CLI."""

    def _run_cli(self, command):
        script = REPO_ROOT / "hooks" / "shell_classifier.py"
        result = subprocess.run(
            [sys.executable, str(script), command],
            capture_output=True,
            text=True,
            timeout=30,
        )
        retval = json.loads(result.stdout)
        return retval

    def test_cli_reports_safe(self):
        out = self._run_cli("ls /tmp")
        self.assertEqual(out["decision"], "safe")

    def test_cli_reports_unsafe(self):
        out = self._run_cli("rm -rf /tmp/foo")
        self.assertEqual(out["decision"], "unsafe")

    def test_cli_reports_unknown(self):
        out = self._run_cli("somecommand_unknown --flag")
        self.assertEqual(out["decision"], "unknown")


if __name__ == "__main__":
    unittest.main()
