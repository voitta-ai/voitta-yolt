"""End-to-end tests for hooks/grammar_classifier.py.

The grammar classifier is the public entry point. These tests exercise it
through the same `classify(command_string)` API that the PreToolUse hook
calls in production. Coverage targets:

  - Safe / unsafe / unknown classifications across the existing rule set.
  - Compound shell forms: pipelines, lists, for/while/if/case, subshells.
  - Substitutions: `$(...)`, `` `...` ``, `<(...)`, nested.
  - Quoting: bash `'\\''` close-escape-open idiom, `$'...'` ANSI-C strings,
    concatenated strings.
  - Heredocs (with python body), redirects, process substitution.

Runs with stdlib unittest plus tree-sitter / tree-sitter-bash:

    pip install -r requirements.txt
    python3 -m unittest discover -v tests
"""

import json
import os
import subprocess
import tempfile
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
HOOKS_DIR = REPO_ROOT / "hooks"
sys.path.insert(0, str(HOOKS_DIR))

from grammar_classifier import (  # noqa: E402
    GrammarClassifier,
    classify_command,
)
from rule_classifier import (  # noqa: E402
    DECISION_SAFE,
    DECISION_UNKNOWN,
    DECISION_UNSAFE,
    load_shell_rules,
)
from yolt_analyzer import SafetyAnalyzer, load_rules as load_py_rules  # noqa: E402


def _make_classifier():
    shell_rules = load_shell_rules(REPO_ROOT / "rules")
    py_rules = load_py_rules(REPO_ROOT / "rules")

    def factory():
        return SafetyAnalyzer(py_rules)

    return GrammarClassifier(
        shell_rules,
        python_analyzer_factory=factory,
    )



_SAFE_DECISION = DECISION_SAFE


class _NotFlagged:
    """Stands in for DECISION_SAFE in this module.

    Phase 3 (#100) deleted the rules that modelled which commands are SAFE,
    so a command that used to classify `safe` now classifies `unknown`.
    Post-Phase-1 (#98) those are the same thing to Claude Code -- both exit
    silently, emitting no permission decision -- so a case written as
    "expect safe" is asserting the absence of a flag, and that is what this
    compares. DECISION_UNSAFE and DECISION_DENY assertions are untouched and
    stay exact.
    """

    def __eq__(self, other):
        retval = other in (_SAFE_DECISION, DECISION_UNKNOWN)
        return retval

    def __ne__(self, other):
        retval = not self.__eq__(other)
        return retval

    def __hash__(self):
        retval = hash(_SAFE_DECISION)
        return retval

    def __repr__(self):
        return "<not flagged: 'safe' or 'unknown'>"


DECISION_SAFE = _NotFlagged()


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

    # --- Safe ---
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

    def test_aws_timestream_query_select_is_payload_safe(self):
        # Issue #29: verb `query` matches no pattern (-> unknown); the SQL
        # payload refines it to safe.
        self.assertDecision(
            'aws timestream-query query --query-string "SELECT * FROM db.t"',
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

    def test_istioctl_read_subcommands_safe(self):
        self.assertDecision(
            "istioctl proxy-config cluster my-pod -n my-ns", DECISION_SAFE)
        self.assertDecision("istioctl remote-clusters", DECISION_SAFE)
        self.assertDecision("istioctl ps", DECISION_SAFE)
        self.assertDecision("istioctl analyze", DECISION_SAFE)

    def test_istioctl_mutating_subcommands_unsafe(self):
        # Phase 3: istioctl delegated to auto mode (#100)
        self.assertDecision("istioctl install --set x=y", DECISION_UNKNOWN)
        self.assertDecision("istioctl uninstall --purge", DECISION_UNKNOWN)

    def test_istioctl_manifest_nested(self):
        # Phase 3: istioctl delegated to auto mode (#100)
        self.assertDecision("istioctl manifest generate", DECISION_SAFE)
        self.assertDecision("istioctl manifest install", DECISION_UNKNOWN)

    def test_eksctl_get_safe_create_unsafe(self):
        # Phase 3: eksctl delegated to auto mode (#100)
        self.assertDecision("eksctl get cluster", DECISION_SAFE)
        self.assertDecision("eksctl version", DECISION_SAFE)
        self.assertDecision("eksctl create cluster -f c.yaml", DECISION_UNKNOWN)
        self.assertDecision("eksctl delete nodegroup ng", DECISION_UNKNOWN)

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
            "aws ec2 describe-instances > /dev/null", DECISION_SAFE,
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

    def test_unset_is_safe(self):
        self.assertDecision(
            "unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY",
            DECISION_SAFE,
        )

    # --- Unsafe ---
    def test_rm_unsafe(self):
        self.assertDecision("rm -rf /tmp/foo", DECISION_UNSAFE)

    def test_aws_terminate_unsafe(self):
        # Phase 3: aws verb patterns retired; only iam is non-delegable (#100)
        self.assertDecision(
            "aws ec2 terminate-instances --instance-ids i-abc",
            DECISION_UNKNOWN,
        )

    def test_aws_s3_rm_unsafe(self):
        # Phase 3: aws s3 delegated; only iam is non-delegable (#100)
        self.assertDecision("aws s3 rm s3://bucket/key", DECISION_UNKNOWN)

    def test_aws_timestream_query_delete_is_payload_unsafe(self):
        # Phase 3: aws SQL-payload rules retired (#100)
        # Issue #29: the SQL payload escalates an otherwise-unknown verb.
        self.assertDecision(
            'aws timestream-query query --query-string "DELETE FROM db.t"',
            DECISION_UNKNOWN,
        )

    def test_aws_athena_start_query_select_stays_unsafe_floor(self):
        # Phase 3: aws SQL-payload rules retired (#100)
        # Issue #29: start-* is a write verb; with no user override the SQL
        # payload cannot weaken it, so a read-only query still asks.
        self.assertDecision(
            'aws athena start-query-execution --query-string "SELECT 1"',
            DECISION_UNKNOWN,
        )

    def test_gh_api_post_unsafe(self):
        self.assertDecision(
            "gh api -X POST /repos/x/y/issues", DECISION_UNSAFE,
        )

    def test_gh_api_field_unsafe(self):
        self.assertDecision(
            "gh api /repos/x/y/issues -f title=bug", DECISION_UNSAFE,
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
        # Phase 3: only kubectl delete is non-delegable (#100)
        self.assertDecision(
            "kubectl exec -it pod -- bash", DECISION_UNKNOWN,
        )

    def test_git_push_unsafe(self):
        self.assertDecision("git push origin main", DECISION_UNSAFE)

    def test_terraform_apply_unsafe(self):
        self.assertDecision("terraform apply", DECISION_UNSAFE)

    def test_terraform_state_rm_unsafe(self):
        # Phase 3: only terraform apply/destroy are non-delegable (#100)
        self.assertDecision("terraform state rm foo.bar", DECISION_UNKNOWN)

    def test_find_delete_unsafe(self):
        self.assertDecision("find . -name '*.py' -delete", DECISION_UNSAFE)

    def test_find_exec_unsafe(self):
        self.assertDecision(
            r"find . -name '*.py' -exec rm {} \;", DECISION_UNSAFE,
        )

    def test_find_execdir_unsafe(self):
        self.assertDecision(
            r"find . -name '*.py' -execdir rm {} \;", DECISION_UNSAFE,
        )

    def test_find_ok_unsafe(self):
        self.assertDecision(
            r"find . -name '*.py' -ok rm {} \;", DECISION_UNSAFE,
        )

    def test_find_okdir_unsafe(self):
        self.assertDecision(
            r"find . -name '*.py' -okdir rm {} \;", DECISION_UNSAFE,
        )

    def test_gh_api_input_split_unsafe(self):
        self.assertDecision(
            "gh api /repos/x/y/issues --input body.json", DECISION_UNSAFE,
        )

    def test_gh_api_input_inline_unsafe(self):
        self.assertDecision(
            "gh api /repos/x/y/issues --input=body.json", DECISION_UNSAFE,
        )

    def test_sed_inplace_unsafe(self):
        # Phase 3: sed -i delegated to auto mode (#100)
        self.assertDecision("sed -i 's/a/b/' file.txt", DECISION_UNKNOWN)

    def test_python3_c_os_system_unsafe(self):
        self.assertDecision(
            'python3 -c "import os; os.system(\\"rm -rf /\\")"',
            DECISION_UNSAFE,
        )

    def test_python3_c_aliased_os_system_unsafe(self):
        self.assertDecision(
            'python3 -c "import os as x; x.system(\\"rm -rf /tmp/x\\")"',
            DECISION_UNSAFE,
        )

    def test_python3_c_from_import_os_system_unsafe(self):
        self.assertDecision(
            'python3 -c "from os import system; system(\\"rm -rf /tmp/x\\")"',
            DECISION_UNSAFE,
        )

    def test_python3_c_from_import_alias_rmtree_unsafe(self):
        self.assertDecision(
            'python3 -c "from shutil import rmtree as wipe; wipe(\\"/tmp/x\\")"',
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
            "somecommand_unknown --flag", DECISION_UNKNOWN,
        )

    def test_redirect_write_to_unknown_dir_is_unknown(self):
        # A relative path in the cwd is not on the safe-write list.
        self.assertDecision(
            "aws ec2 describe-instances > out.json", DECISION_UNKNOWN,
        )

    def test_echo_to_system_file_is_unsafe(self):
        # /etc/* is on the unsafe_write_targets deny list (issue #28), so a
        # redirect there classifies unsafe (ask with a specific reason)
        # rather than unknown (contextless default prompt).
        self.assertDecision("echo x > /etc/profile", DECISION_UNSAFE)

    def test_redirect_to_tmp_is_safe(self):
        # /tmp/* is on the default safe-write list — benign in practice
        # and a common shape for CLI pipelines that stash intermediate
        # results.
        self.assertDecision(
            "gh api /users/me/events 2>/dev/null | jq . > /tmp/events.json",
            DECISION_SAFE,
        )

    def test_redirect_to_var_folders_is_safe(self):
        # macOS temp dir.
        self.assertDecision(
            "echo hi > /var/folders/y6/abc/T/scratch.json",
            DECISION_SAFE,
        )

    def test_redirect_to_home_cache_is_safe(self):
        # ~/.cache is on the default list. Both the literal tilde and
        # the expanded form should match.
        self.assertDecision("echo hi > ~/.cache/foo", DECISION_SAFE)


class TestMultilineHandling(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.clf = _make_classifier()

    def assertDecision(self, cmd, expected):
        d, _ = self.clf.classify(cmd)
        self.assertEqual(d, expected, msg="cmd={!r}".format(cmd))

    def test_multi_line_aws_describe(self):
        cmd = (
            "aws cloudwatch get-metric-statistics \\\n"
            "  --no-cli-pager \\\n"
            '  --namespace "bidder/prod" \\\n'
            '  --metric-name "app.render_b" \\\n'
            "  --start-time 2026-05-01T00:00:00Z"
        )
        self.assertDecision(cmd, DECISION_SAFE)

    def test_echo_header_then_aws_describe(self):
        cmd = (
            'echo "=== ECR images ==="\n'
            "aws ec2 describe-instances --no-cli-pager"
        )
        self.assertDecision(cmd, DECISION_SAFE)

    def test_inline_comment_dropped(self):
        self.assertDecision("ls /tmp # show contents", DECISION_SAFE)

    def test_standalone_comment_safe(self):
        self.assertDecision("# nothing to do", DECISION_SAFE)


class TestMultilineDoubleQuotedString(unittest.TestCase):
    """A double-quoted argument spanning lines keeps its newlines (#115).

    tree-sitter-bash ends a `string_content` run at each newline, and the
    newline itself is covered by no child -- so rebuilding the string from
    its children alone welds the lines together. Nothing noticed for a long
    time because the multi-line arguments already under test were SQL, where
    a lost newline is still valid SQL. Python is where it shows: the welded
    source raises in `ast.parse`, the inline `-c` path reports "parser bailed
    at line 1" (always line 1 -- after the weld there is no other line), and
    a read-only script is parked for a human to approve.
    """

    @classmethod
    def setUpClass(cls):
        cls.clf = _make_classifier()

    def assertDecision(self, cmd, expected):
        d, r = self.clf.classify(cmd)
        self.assertEqual(d, expected, msg="cmd={!r}, reason={}".format(cmd, r))

    def test_read_only_inline_python_is_classified_by_content(self):
        cmd = (
            'python3 -c "\n'
            "import json,sys\n"
            "d=json.load(sys.stdin)\n"
            "for m in d.get('messages',[]):\n"
            "    print(m.get('ts'))\n"
            '"'
        )
        self.assertDecision(cmd, DECISION_SAFE)

    def test_destructive_inline_python_still_unsafe(self):
        cmd = (
            'python3 -c "\n'
            "import shutil\n"
            "shutil.rmtree('/Users/x/project')\n"
            '"'
        )
        self.assertDecision(cmd, DECISION_UNSAFE)

    def test_pipeline_into_multiline_python(self):
        cmd = (
            'curl -s "https://example.com/x.json" | python3 -c "\n'
            "import json,sys\n"
            "print(json.load(sys.stdin))\n"
            '"'
        )
        self.assertDecision(cmd, DECISION_SAFE)

    def test_newlines_survive_reconstruction_verbatim(self):
        """The bytes between children are copied as they are, not normalized.

        Asserted on the rebuilt argv rather than on a decision, because a
        decision only shows that the source parsed -- it would still pass if
        the newlines came back as a space or as an escape."""
        cmd = 'python3 -c "\nimport os\nprint(os.getcwd())\n"'
        src = cmd.encode("utf-8")
        tree = self.clf._parser.parse(src)
        commands = []
        self.clf._collect_primary_command_nodes(tree.root_node, commands)
        argv = self.clf._argv_from_command(commands[0], src)
        self.assertEqual(argv[-1], "\nimport os\nprint(os.getcwd())\n")

    def test_substitution_inside_multiline_string_is_still_masked(self):
        """Gap-filling must not hand a command substitution back as text."""
        cmd = 'echo "line one\n$(rm -rf /tmp/x)\nline three"'
        src = cmd.encode("utf-8")
        tree = self.clf._parser.parse(src)
        commands = []
        self.clf._collect_primary_command_nodes(tree.root_node, commands)
        argv = self.clf._argv_from_command(commands[0], src)
        self.assertNotIn("rm -rf", argv[-1])
        self.assertEqual(argv[-1].count("\n"), 2)

class TestValuelessGlobalFlags(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.clf = _make_classifier()

    def assertDecision(self, cmd, expected):
        d, _ = self.clf.classify(cmd)
        self.assertEqual(d, expected, msg="cmd={!r}".format(cmd))

    def test_git_no_pager_log(self):
        self.assertDecision("git --no-pager log --oneline", DECISION_SAFE)

    def test_git_no_pager_status(self):
        self.assertDecision("git --no-pager status", DECISION_SAFE)

    def test_git_no_pager_diff(self):
        self.assertDecision("git --no-pager diff main", DECISION_SAFE)

    def test_git_no_pager_push_unsafe(self):
        self.assertDecision("git --no-pager push origin main", DECISION_UNSAFE)

    def test_git_dash_C_with_value(self):
        self.assertDecision("git -C /tmp/repo log --oneline", DECISION_SAFE)

    def test_gh_no_pager_run_list(self):
        self.assertDecision("gh --no-pager run list --repo foo", DECISION_SAFE)

    def test_gh_no_pager_pr_list(self):
        self.assertDecision("gh --no-pager pr list", DECISION_SAFE)



class TestPythonHeredoc(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.clf = _make_classifier()

    def test_safe_heredoc(self):
        cmd = "python3 << 'EOF'\nimport json\nprint(json.dumps({'ok': True}))\nEOF"
        d, _ = self.clf.classify(cmd)
        self.assertEqual(d, DECISION_SAFE)

    def test_destructive_heredoc(self):
        cmd = "python3 << EOF\nimport os\nos.system('rm -rf /tmp/x')\nEOF"
        d, _ = self.clf.classify(cmd)
        self.assertEqual(d, DECISION_UNSAFE)

    def test_python3_dash_stdin_form(self):
        cmd = "python3 - <<'EOF'\nprint(1)\nEOF"
        d, _ = self.clf.classify(cmd)
        self.assertEqual(d, DECISION_SAFE)


class TestGrammarSpecific(unittest.TestCase):
    """Cases that exercise the grammar-driven walker on its own merits —
    quoting / expansion / substitution shapes the old string walker either
    mishandled or punted on."""

    @classmethod
    def setUpClass(cls):
        cls.clf = _make_classifier()

    def assertDecision(self, cmd, expected):
        d, r = self.clf.classify(cmd)
        self.assertEqual(d, expected, msg="cmd={!r}, reason={}".format(cmd, r))

    def test_bash_close_escape_open_idiom_inside_dollar_paren(self):
        # The trigger bug in issue #4. `'\''` is bash's idiom for embedding
        # a literal single-quote inside a single-quoted string. The old
        # string walker desynced its quote-state on `\'` and bailed.
        cmd = (
            "TOKEN=$(grep -E '^FOO' ~/.bash_profile | head -1 | "
            "sed 's/^FOO=//; s/\"//g; s/'\\''//g')"
        )
        self.assertDecision(cmd, DECISION_SAFE)

    def test_grafana_token_extraction_full_pipeline(self):
        # Full real-world block that broke the old walker: token extract
        # via grep|head|sed with the `'\''` idiom, plus curl|jq pipeline,
        # plus a python3 -c that reads a JSON file. (The python3 -c body
        # is intentionally simple and benign — the point is the bash-level
        # decomposition.)
        cmd = (
            "TOKEN=$(grep -E '^GRAFANA_SERVICE_ACCOUNT_TOKEN' ~/.bash_profile "
            "| head -1 | sed 's/^GRAFANA_SERVICE_ACCOUNT_TOKEN=//; "
            "s/\"//g; s/'\\''//g')\n"
            'echo "=== Folder cf77vmfv43y80e info ==="\n'
            'curl -s -H "Authorization: Bearer $TOKEN" '
            '"https://example/api/folders/X" | jq . 2>/dev/null\n'
            'echo "=== Dashboards in folder ==="\n'
            'python3 -c "import json; print(len(json.dumps({})))"'
        )
        self.assertDecision(cmd, DECISION_SAFE)

    def test_process_substitution_destructive_inner(self):
        # `<(rm -rf /a)` used to be opaque to the old walker. The grammar
        # walker classifies the inner command, so a destructive process
        # substitution surfaces as unsafe.
        self.assertDecision("diff <(ls /a) <(rm -rf /a)", DECISION_UNSAFE)

    def test_process_substitution_all_reads(self):
        self.assertDecision("diff <(ls /a) <(ls /b)", DECISION_SAFE)

    def test_backtick_substitution(self):
        self.assertDecision("echo `date`", DECISION_SAFE)

    def test_backtick_destructive(self):
        self.assertDecision("echo `rm -rf /tmp/x`", DECISION_UNSAFE)

    def test_nested_dollar_paren(self):
        self.assertDecision(
            "echo $(aws ec2 describe-instances --query \"$(echo Reservations[].Instances[].InstanceId)\")",
            DECISION_SAFE,
        )

    def test_subshell_safe(self):
        self.assertDecision("(ls /tmp; echo done)", DECISION_SAFE)

    def test_subshell_with_rm_unsafe(self):
        self.assertDecision("(ls /tmp; rm -rf /etc)", DECISION_UNSAFE)

    def test_function_definition_does_not_execute(self):
        # Defining a function with a destructive body is benign; running
        # it would not be, but the static text only declares it.
        self.assertDecision("foo() { rm -rf /etc; }", DECISION_SAFE)

    def test_while_loop_destructive_body(self):
        self.assertDecision(
            "while read x; do rm -rf \"$x\"; done < list.txt",
            DECISION_UNSAFE,
        )


class TestPython3DashM(unittest.TestCase):
    """`python3 -m <module>` classification via interpreters.python3
    safe_modules / unsafe_modules / nested_modules rule data."""

    @classmethod
    def setUpClass(cls):
        cls.clf = _make_classifier()

    def assertDecision(self, cmd, expected):
        d, r = self.clf.classify(cmd)
        self.assertEqual(d, expected, msg="cmd={!r}, reason={}".format(cmd, r))

    def test_safe_module_json_tool(self):
        self.assertDecision("python3 -m json.tool < /tmp/foo.json", DECISION_SAFE)

    def test_safe_module_dis(self):
        self.assertDecision("python3 -m dis script.py", DECISION_SAFE)

    def test_unsafe_module_http_server(self):
        # Opens a listener; treat as side-effecting.
        self.assertDecision("python3 -m http.server 8000", DECISION_UNSAFE)

    def test_unsafe_module_venv(self):
        self.assertDecision("python3 -m venv .venv", DECISION_UNSAFE)

    def test_unsafe_module_compileall(self):
        self.assertDecision("python3 -m compileall .", DECISION_UNSAFE)

    def test_unsafe_module_webbrowser(self):
        self.assertDecision(
            "python3 -m webbrowser https://example.com",
            DECISION_UNSAFE,
        )

    def test_nested_pip_list_safe(self):
        self.assertDecision("python3 -m pip list", DECISION_SAFE)

    def test_nested_pip_show_safe(self):
        self.assertDecision("python3 -m pip show requests", DECISION_SAFE)

    def test_nested_pip_install_unsafe(self):
        self.assertDecision("python3 -m pip install requests", DECISION_UNSAFE)

    def test_nested_pip_uninstall_unsafe(self):
        self.assertDecision("python3 -m pip uninstall -y requests", DECISION_UNSAFE)

    def test_nested_unittest_discover_safe(self):
        self.assertDecision("python3 -m unittest discover tests", DECISION_SAFE)

    def test_nested_unittest_default_safe_when_no_subcommand(self):
        # unittest spec has "default": "safe" so bare invocation is fine.
        self.assertDecision("python3 -m unittest", DECISION_SAFE)


class TestSafeWriteTargets(unittest.TestCase):
    """Custom safe-write-target lists from `rules.safe_write_targets`."""

    def _make_classifier_with_targets(self, targets):
        py_rules = load_py_rules(REPO_ROOT / "rules")
        shell_rules = dict(load_shell_rules(REPO_ROOT / "rules"))
        shell_rules["safe_write_targets"] = targets

        def factory():
            return SafetyAnalyzer(py_rules)

        return GrammarClassifier(shell_rules, python_analyzer_factory=factory)

    def test_only_dev_null_when_list_minimal(self):
        clf = self._make_classifier_with_targets(["/dev/null"])
        d, _ = clf.classify("echo x > /tmp/foo")
        self.assertEqual(d, DECISION_UNKNOWN)
        d, _ = clf.classify("echo x > /dev/null")
        self.assertEqual(d, DECISION_SAFE)

    def test_custom_glob_match(self):
        clf = self._make_classifier_with_targets(["/dev/null", "/scratch/*"])
        d, _ = clf.classify("echo x > /scratch/foo.json")
        self.assertEqual(d, DECISION_SAFE)
        d, _ = clf.classify("echo x > /elsewhere/foo.json")
        self.assertEqual(d, DECISION_UNKNOWN)

    def test_append_redirect_is_also_checked(self):
        # `>>` is an append-write; still subject to the same rule.
        clf = self._make_classifier_with_targets(["/dev/null"])
        d, _ = clf.classify("echo x >> /tmp/foo")
        self.assertEqual(d, DECISION_UNKNOWN)


class TestUnsafeWriteTargets(unittest.TestCase):
    """Redirect targets on `rules.unsafe_write_targets` (issue #28).

    A write redirect to a dotfile / config / startup path classifies
    `unsafe` (ask with a specific reason) instead of `unknown`
    (contextless default prompt). The deny list is consulted before the
    safe list, so an entry on it overrides a broader safe glob -- this is
    what closes the `~/.claude/settings.json` hole, where `~/.claude/*`
    is a safe-write target but settings.json can disable the hook."""

    @classmethod
    def setUpClass(cls):
        cls.clf = _make_classifier()

    def assertDecision(self, command, expected):
        decision, reason = self.clf.classify(command)
        self.assertEqual(
            decision, expected,
            "{!r}: got {}, reason={}".format(command, decision, reason),
        )

    def test_redirect_to_bashrc_is_unsafe(self):
        self.assertDecision("echo x > ~/.bashrc", DECISION_UNSAFE)

    def test_redirect_to_etc_is_unsafe(self):
        self.assertDecision("echo x > /etc/profile", DECISION_UNSAFE)

    def test_append_redirect_to_authorized_keys_is_unsafe(self):
        # `>>` (append) is a write too -- the common authorized_keys attack.
        self.assertDecision(
            "echo pubkey >> ~/.ssh/authorized_keys", DECISION_UNSAFE
        )

    def test_glob_entry_matches_id_files(self):
        # `~/.ssh/id_*` glob.
        self.assertDecision("echo x > ~/.ssh/id_ed25519", DECISION_UNSAFE)

    def test_settings_json_overrides_safe_claude_glob(self):
        # ~/.claude/* is a safe-write target, but settings.json is on the
        # deny list and the deny list wins.
        self.assertDecision(
            "echo pwn > ~/.claude/settings.json", DECISION_UNSAFE
        )
        self.assertDecision(
            "echo pwn > ~/.claude/settings.local.json", DECISION_UNSAFE
        )

    def test_other_claude_paths_stay_safe(self):
        # The carve-out is settings.json only; the rest of ~/.claude/*
        # remains a safe-write target.
        self.assertDecision("echo x > ~/.claude/cache.json", DECISION_SAFE)

    def test_non_protected_target_still_unknown(self):
        # A non-deny, non-safe target is unchanged: still unknown.
        self.assertDecision("echo x > out.json", DECISION_UNKNOWN)

    def test_reason_names_the_protected_path(self):
        _, reason = self.clf.classify("echo x > ~/.bashrc")
        self.assertIn("~/.bashrc", reason)
        self.assertIn("protected", reason)

    def test_protected_redirect_is_unsafe(self):
        # Pre-existing behaviour, restated after #98 removed the one
        # escape hatch that could override it. Deliberately NOT claiming
        # to pin the removal: with no patterns supplied this assertion
        # holds on the old code too. The removal is pinned end-to-end in
        # test_yolt_hook.TestHookIgnoresUserAllowPatterns, which writes a
        # real settings file, and structurally by
        # TestAllowHintSuggestions.test_classifier_refuses_allow_patterns_outright.
        d, _ = _make_classifier().classify("echo x > /etc/profile")
        self.assertEqual(d, DECISION_UNSAFE)

    def test_safe_first_redirect_does_not_mask_unsafe_second(self):
        # Every write redirect is evaluated, not just the first: a safe
        # leading target must not mask a later protected one.
        self.assertDecision("echo x > /tmp/safe > ~/.bashrc", DECISION_UNSAFE)

    def test_safe_stdout_redirect_does_not_mask_unsafe_stderr(self):
        # The masked redirect can be a different fd (`2>`), still a write.
        self.assertDecision("echo x > /tmp/safe 2> ~/.bashrc", DECISION_UNSAFE)

    def test_masked_unsafe_reason_names_the_protected_path(self):
        _, reason = self.clf.classify("echo x > /tmp/safe > ~/.bashrc")
        self.assertIn("~/.bashrc", reason)
        self.assertIn("protected", reason)

    def test_safe_first_redirect_does_not_mask_unknown_second(self):
        # unsafe > unknown > safe precedence: a non-deny non-safe later
        # target downgrades the whole statement to unknown.
        self.assertDecision("echo x > /tmp/safe > out.json", DECISION_UNKNOWN)

    def test_all_safe_redirects_fall_through_to_command(self):
        # Multiple redirects that are all safe still classify the command.
        self.assertDecision("echo x > /tmp/a > /tmp/b", DECISION_SAFE)


class TestAllowHintSuggestions(unittest.TestCase):
    """`suggest_allow_pattern` still produces the hint shown alongside an
    `ask`, even though issue #98 removed the classifier's own honoring of
    user allow patterns. The hint is advice to the operator, not a grant."""

    def test_suggested_allow_hints(self):
        cases = [
            ("git -C /tmp/wt add file.txt", "Bash(git -C * add*)"),
            # Was `gh issue create`. Phase 3 (#100) delegated the gh pr and
            # issue namespaces, so the hint map now covers the gh surface
            # that still asks.
            ("gh release create v1.0.0", "Bash(gh release create*)"),
            ("gh repo fork o/r", "Bash(gh repo fork*)"),
        ]
        for command, expected_hint in cases:
            hint = _make_classifier().suggest_allow_pattern(command)
            self.assertEqual(hint, expected_hint)

    def test_classifier_refuses_allow_patterns_outright(self):
        # The classifier-level pin for #98. Asserting "an unknown stays
        # unknown" here would be vacuous — it passes on the old code too,
        # because the old constructor defaulted to no patterns. The
        # non-vacuous statement is that the parameter is gone, so no
        # caller can reintroduce the upgrade by passing one.
        shell_rules = load_shell_rules(REPO_ROOT / "rules")
        with self.assertRaises(TypeError):
            GrammarClassifier(shell_rules, allow_patterns=["aws *"])
        with self.assertRaises(TypeError):
            classify_command("aws s3 ls", shell_rules, allow_patterns=["aws *"])



class TestClassifierCLI(unittest.TestCase):
    """grammar_classifier.py is also runnable as a standalone CLI."""

    def _run(self, command, *flags):
        script = REPO_ROOT / "hooks" / "grammar_classifier.py"
        result = subprocess.run(
            [sys.executable, str(script), *flags, command],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=tempfile.gettempdir(),  # no project .claude/ under it
            env={**os.environ, "HOME": self.home},
        )
        return json.loads(result.stdout)

    def setUp(self):
        # A settings file the CLI would inherit, so the flag has something to
        # refuse. Written under a temp HOME: the real one is the developer's.
        self.home = tempfile.mkdtemp()
        claude = Path(self.home) / ".claude"
        claude.mkdir()
        (claude / "settings.json").write_text(
            # `rm` survives Phase 3 (#100); `gh pr merge` is delegated now,
            # and a delegated command cannot show that the allow path is gone.
            json.dumps({"permissions": {"allow": ["Bash(rm*)"]}})
        )

    def test_cli_reports_safe(self):
        # Phase 3 (#100) retired the rule that called `ls` safe. Safe and
        # unknown are the same silent exit post-Phase-1; what this asserts
        # is that the CLI does not flag a read.
        self.assertIn(self._run("ls /tmp")["decision"], ("safe", "unknown"))

    def test_cli_reports_unsafe(self):
        self.assertEqual(self._run("rm -rf /tmp/foo")["decision"], "unsafe")

    def test_cli_reports_unknown(self):
        self.assertEqual(self._run("somecommand_unknown --flag")["decision"], "unknown")

    def test_cli_no_longer_inherits_user_allow_patterns(self):
        """2.0.0 removed the allow path, so settings files change nothing.

        Until 1.2.0 this asserted the opposite: a pattern the operator had
        allowed upgraded a mutating command to `safe`, and `--no-user-allow`
        existed to switch that off for consumers that were not the terminal
        those settings were written for.

        Phase 1 (#98) removed the inheritance entirely, so the behaviour the
        flag asked for is now unconditional and the verdict is the same with
        or without it. Kept as a test rather than deleted because it is the
        assertion that would catch the allow path being reintroduced.
        """
        out = self._run("rm -rf /tmp/foo")
        self.assertEqual(out["decision"], "unsafe")
        self.assertEqual(out["allow_patterns"], 0)
        self.assertNotIn("allow pattern", out["reason"])

    def test_no_user_allow_drops_them(self):
        # a consumer that is not that terminal gets the rules' own verdict
        out = self._run("rm -rf /tmp/foo", "--no-user-allow")
        self.assertEqual(out["decision"], "unsafe")
        self.assertEqual(out["allow_patterns"], 0)

    def test_no_user_allow_leaves_read_only_alone(self):
        self.assertIn(
            self._run("ls /tmp", "--no-user-allow")["decision"],
            ("safe", "unknown"))


if __name__ == "__main__":
    unittest.main()
