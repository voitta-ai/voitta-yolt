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
  - User allowlist upgrade (and never-weakens-unsafe invariant).

Runs with stdlib unittest plus tree-sitter / tree-sitter-bash:

    pip install -r requirements.txt
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

from grammar_classifier import GrammarClassifier  # noqa: E402
from rule_classifier import (  # noqa: E402
    DECISION_SAFE,
    DECISION_UNKNOWN,
    DECISION_UNSAFE,
    load_shell_rules,
)
from yolt_analyzer import SafetyAnalyzer, load_rules as load_py_rules  # noqa: E402


def _make_classifier(allow_patterns=None):
    shell_rules = load_shell_rules(REPO_ROOT / "rules")
    py_rules = load_py_rules(REPO_ROOT / "rules")

    def factory():
        return SafetyAnalyzer(py_rules)

    return GrammarClassifier(
        shell_rules,
        python_analyzer_factory=factory,
        allow_patterns=allow_patterns or [],
    )


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
        self.assertDecision(
            "aws ec2 terminate-instances --instance-ids i-abc",
            DECISION_UNSAFE,
        )

    def test_aws_s3_rm_unsafe(self):
        self.assertDecision("aws s3 rm s3://bucket/key", DECISION_UNSAFE)

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
        self.assertDecision(
            "kubectl exec -it pod -- bash", DECISION_UNSAFE,
        )

    def test_git_push_unsafe(self):
        self.assertDecision("git push origin main", DECISION_UNSAFE)

    def test_terraform_apply_unsafe(self):
        self.assertDecision("terraform apply", DECISION_UNSAFE)

    def test_terraform_state_rm_unsafe(self):
        self.assertDecision("terraform state rm foo.bar", DECISION_UNSAFE)

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
        self.assertDecision("sed -i 's/a/b/' file.txt", DECISION_UNSAFE)

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

    def test_echo_to_system_file_is_unknown(self):
        self.assertDecision("echo x > /etc/profile", DECISION_UNKNOWN)

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


class TestNestedSubcommandPaths(unittest.TestCase):
    """Issue #17: path-aware classification for nested mutating verbs that
    previously stopped at the first subcommand and were treated as safe."""

    @classmethod
    def setUpClass(cls):
        cls.clf = _make_classifier()

    def assertDecision(self, cmd, expected):
        d, r = self.clf.classify(cmd)
        self.assertEqual(
            d, expected,
            "cmd={!r}: got {}, reason={}".format(cmd, d, r),
        )

    # --- Acceptance criteria from issue #17 ---

    def test_git_tag_create_not_safe(self):
        # 'git tag v1.2.3' creates a lightweight tag. Was silently safe.
        d, _ = self.clf.classify("git tag v1.2.3")
        self.assertNotEqual(d, DECISION_SAFE)

    def test_docker_image_rm_unsafe(self):
        self.assertDecision("docker image rm alpine", DECISION_UNSAFE)

    def test_kubectl_config_set_context_unsafe(self):
        self.assertDecision("kubectl config set-context prod", DECISION_UNSAFE)

    def test_helm_repo_add_unsafe(self):
        self.assertDecision(
            "helm repo add foo https://example.com",
            DECISION_UNSAFE,
        )

    # --- git tag: positional means create, flag-based deletes/annotates ---

    def test_git_tag_bare_lists_safe(self):
        self.assertDecision("git tag", DECISION_SAFE)

    def test_git_tag_dash_l_lists_safe(self):
        self.assertDecision("git tag -l", DECISION_SAFE)

    def test_git_tag_delete_unsafe(self):
        self.assertDecision("git tag -d v1.2.3", DECISION_UNSAFE)

    def test_git_tag_annotated_unsafe(self):
        d, _ = self.clf.classify('git tag -a v1.2.3 -m "release"')
        self.assertEqual(d, DECISION_UNSAFE)

    # --- docker.image / container / volume / network / system ---

    def test_docker_image_ls_safe(self):
        self.assertDecision("docker image ls", DECISION_SAFE)

    def test_docker_image_prune_unsafe(self):
        self.assertDecision("docker image prune", DECISION_UNSAFE)

    def test_docker_container_ls_safe(self):
        self.assertDecision("docker container ls", DECISION_SAFE)

    def test_docker_container_rm_unsafe(self):
        self.assertDecision("docker container rm myctr", DECISION_UNSAFE)

    def test_docker_volume_create_unsafe(self):
        self.assertDecision("docker volume create vol1", DECISION_UNSAFE)

    def test_docker_volume_ls_safe(self):
        self.assertDecision("docker volume ls", DECISION_SAFE)

    def test_docker_network_connect_unsafe(self):
        self.assertDecision(
            "docker network connect bridge myctr", DECISION_UNSAFE,
        )

    def test_docker_system_prune_unsafe(self):
        self.assertDecision("docker system prune", DECISION_UNSAFE)

    def test_docker_system_df_safe(self):
        self.assertDecision("docker system df", DECISION_SAFE)

    def test_bare_docker_image_no_longer_silently_safe(self):
        # Was safe pre-issue-17. Now a partially-modeled namespace without
        # a sub-subcommand should not auto-allow.
        d, _ = self.clf.classify("docker image")
        self.assertNotEqual(d, DECISION_SAFE)

    # --- kubectl.config ---

    def test_kubectl_config_view_safe(self):
        self.assertDecision("kubectl config view", DECISION_SAFE)

    def test_kubectl_config_use_context_unsafe(self):
        self.assertDecision(
            "kubectl config use-context prod", DECISION_UNSAFE,
        )

    def test_kubectl_config_delete_context_unsafe(self):
        self.assertDecision(
            "kubectl config delete-context prod", DECISION_UNSAFE,
        )

    # --- helm.repo ---

    def test_helm_repo_list_safe(self):
        self.assertDecision("helm repo list", DECISION_SAFE)

    def test_helm_repo_update_safe(self):
        self.assertDecision("helm repo update", DECISION_SAFE)

    def test_helm_repo_remove_unsafe(self):
        self.assertDecision("helm repo remove foo", DECISION_UNSAFE)


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


class TestClassifierAllowPatterns(unittest.TestCase):
    """Allowlist upgrades unknowns to safe but never weakens unsafe."""

    def test_unknown_command_upgraded_to_safe(self):
        clf = _make_classifier(allow_patterns=["mycli *"])
        d, r = clf.classify("mycli foo --bar")
        self.assertEqual(d, DECISION_SAFE)
        self.assertIn("mycli *", r)

    def test_unknown_aws_op_upgraded(self):
        clf = _make_classifier(allow_patterns=["aws * weird-op*"])
        d, _ = clf.classify("aws ec2 weird-op --flag")
        self.assertEqual(d, DECISION_SAFE)

    def test_unsafe_not_weakened_by_allowlist(self):
        clf = _make_classifier(allow_patterns=["aws *"])
        d, _ = clf.classify("aws iam delete-user --user-name foo")
        self.assertEqual(d, DECISION_UNSAFE)

    def test_unsafe_in_compound_not_weakened(self):
        clf = _make_classifier(allow_patterns=["aws *", "rm *"])
        d, _ = clf.classify("aws s3 ls && rm -rf /etc")
        self.assertEqual(d, DECISION_UNSAFE)

    def test_no_allowlist_match_stays_unknown(self):
        clf = _make_classifier(allow_patterns=["aws *"])
        d, _ = clf.classify("somecommand_unknown")
        self.assertEqual(d, DECISION_UNKNOWN)

    def test_decomposed_atoms_match_allowlist(self):
        # The outer `for` wrapper would not match `Bash(aws s3 ls*)`, but
        # the grammar walker classifies each iteration body separately.
        clf = _make_classifier(allow_patterns=["aws s3 ls*"])
        d, _ = clf.classify("for b in foo bar; do aws s3 ls s3://$b/; done")
        self.assertEqual(d, DECISION_SAFE)

    def test_writes_to_file_upgraded_when_allowlisted(self):
        clf = _make_classifier(allow_patterns=["echo *"])
        d, _ = clf.classify("echo x > /etc/profile")
        self.assertEqual(d, DECISION_SAFE)

    def test_empty_allow_patterns_unchanged_behavior(self):
        clf = _make_classifier(allow_patterns=[])
        d, _ = clf.classify("somecommand_unknown")
        self.assertEqual(d, DECISION_UNKNOWN)


class TestSqlCli(unittest.TestCase):
    """SQL clients: sqlite3 / psql / mysql / mariadb / duckdb. The argv
    walker extracts SQL and the SQL keyword scan decides safe vs unsafe."""

    @classmethod
    def setUpClass(cls):
        cls.clf = _make_classifier()

    def assertDecision(self, cmd, expected):
        d, r = self.clf.classify(cmd)
        self.assertEqual(d, expected, msg="cmd={!r}, reason={}".format(cmd, r))

    # sqlite3 positional SQL
    def test_sqlite3_select_safe(self):
        self.assertDecision(
            'sqlite3 /tmp/db.sqlite "SELECT * FROM foo"',
            DECISION_SAFE,
        )

    def test_sqlite3_multiline_select_safe(self):
        cmd = (
            'sqlite3 /Users/x/voitta.db "SELECT sync_status,\n'
            "COALESCE(sync_error,'none') AS err, "
            "(SELECT count(*) FROM llm_tldr_indexed_files WHERE\n"
            "folder_path='vrag-test-4') AS tldr_rows "
            "FROM folder_sync_sources WHERE folder_path='vrag-test-4';\""
        )
        self.assertDecision(cmd, DECISION_SAFE)

    def test_sqlite3_drop_unsafe(self):
        self.assertDecision(
            "sqlite3 /tmp/db.sqlite 'DROP TABLE foo'",
            DECISION_UNSAFE,
        )

    def test_sqlite3_insert_unsafe(self):
        self.assertDecision(
            "sqlite3 /tmp/db.sqlite 'INSERT INTO foo VALUES (1)'",
            DECISION_UNSAFE,
        )

    def test_sqlite3_interactive_is_unknown(self):
        # Bare invocation drops the user into a REPL — no SQL to analyze.
        self.assertDecision("sqlite3 /tmp/db.sqlite", DECISION_UNKNOWN)

    def test_sqlite3_dot_tables_safe(self):
        self.assertDecision(
            "sqlite3 /tmp/db.sqlite '.tables'",
            DECISION_SAFE,
        )

    def test_sqlite3_dot_import_unsafe(self):
        self.assertDecision(
            "sqlite3 /tmp/db.sqlite '.import foo.csv mytable'",
            DECISION_UNSAFE,
        )

    def test_sqlite3_cmd_flag(self):
        self.assertDecision(
            'sqlite3 -cmd "SELECT 1" /tmp/db.sqlite',
            DECISION_SAFE,
        )

    def test_sqlite3_readonly_flag_does_not_eat_positional(self):
        # -readonly is valueless; it must not consume /tmp/db.sqlite.
        self.assertDecision(
            'sqlite3 -readonly /tmp/db.sqlite "SELECT 1"',
            DECISION_SAFE,
        )

    # psql -c
    def test_psql_dash_c_select_safe(self):
        self.assertDecision(
            'psql -c "SELECT 1" mydb',
            DECISION_SAFE,
        )

    def test_psql_dash_c_delete_unsafe(self):
        self.assertDecision(
            'psql -c "DELETE FROM users WHERE id = 1" mydb',
            DECISION_UNSAFE,
        )

    def test_psql_command_long_form(self):
        self.assertDecision(
            'psql --command "SELECT now()" mydb',
            DECISION_SAFE,
        )

    def test_psql_dash_f_file_is_unknown(self):
        # File contents are opaque to a static checker.
        self.assertDecision(
            "psql -f queries.sql mydb",
            DECISION_UNKNOWN,
        )

    def test_psql_bare_dbname_is_unknown(self):
        self.assertDecision("psql mydb", DECISION_UNKNOWN)

    # mysql -e
    def test_mysql_dash_e_select_safe(self):
        self.assertDecision(
            'mysql -e "SELECT VERSION()" mydb',
            DECISION_SAFE,
        )

    def test_mysql_dash_e_drop_unsafe(self):
        self.assertDecision(
            'mysql -e "DROP TABLE foo" mydb',
            DECISION_UNSAFE,
        )

    def test_mysql_execute_equals_form(self):
        self.assertDecision(
            'mysql --execute=SHOW DATABASES',
            DECISION_SAFE,
        )

    # SQL injected via $(...) substitution — placeholders preserve safety.
    def test_sqlite3_with_substitution_in_select(self):
        self.assertDecision(
            'sqlite3 /tmp/db "SELECT * FROM t WHERE id = $(echo 1)"',
            DECISION_SAFE,
        )

    # Compound: SELECT then mutating substitution.
    def test_sqlite3_with_destructive_substitution(self):
        # The outer SQL is SELECT (safe), but the substitution runs `rm`.
        self.assertDecision(
            'sqlite3 /tmp/db "SELECT $(rm -rf /tmp/x)"',
            DECISION_UNSAFE,
        )


class TestClassifierCLI(unittest.TestCase):
    """grammar_classifier.py is also runnable as a standalone CLI."""

    def _run(self, command):
        script = REPO_ROOT / "hooks" / "grammar_classifier.py"
        result = subprocess.run(
            [sys.executable, str(script), command],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return json.loads(result.stdout)

    def test_cli_reports_safe(self):
        self.assertEqual(self._run("ls /tmp")["decision"], "safe")

    def test_cli_reports_unsafe(self):
        self.assertEqual(self._run("rm -rf /tmp/foo")["decision"], "unsafe")

    def test_cli_reports_unknown(self):
        self.assertEqual(self._run("somecommand_unknown --flag")["decision"], "unknown")


if __name__ == "__main__":
    unittest.main()
