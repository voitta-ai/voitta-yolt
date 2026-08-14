"""Tests for credential redaction in YOLT's own logs (issue #84).

Runs with stdlib unittest only:

    python3 -m unittest discover -v tests
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "hooks"))

from secret_redact import find_secrets, redact  # noqa: E402

# Synthetic values only - shaped like the real thing, valid nowhere.
FAKE_GH_TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0" * 2
FAKE_GH_PAT = "github_pat_" + "11ABCDEFG0" * 3
FAKE_GITLAB = "glpat-" + "xY3zAb9QrS7tUv1W"
FAKE_SLACK = "xoxb-1234567890-1234567890123-" + "AbCdEf1234567890AbCdEf12"
FAKE_SLACK_APP = "xapp-1-A01BCDEFGHI-1234567890123-" + "abcdef1234567890"
FAKE_AWS_ID = "AKIAIOSFODNN7EXAMPLE"
FAKE_API_KEY = "sk-ant-api03-" + "aB3dE6gH9jK2mN5pQ8sT1vW4"


class RedactStructuredTests(unittest.TestCase):
    """Self-identifying prefixes are matched whole, wherever they sit."""

    def assert_scrubbed(self, command, secret, kind):
        out = redact(command)
        self.assertNotIn(secret, out,
                         "{} survived redaction".format(kind))
        self.assertIn("[REDACTED:{}]".format(kind), out)

    def test_github_token(self):
        self.assert_scrubbed(
            'curl -H "Authorization: token {}" https://api.github.com'.format(
                FAKE_GH_TOKEN),
            FAKE_GH_TOKEN, "github-token")

    def test_github_pat(self):
        self.assert_scrubbed(
            "gh auth login --with-token <<< {}".format(FAKE_GH_PAT),
            FAKE_GH_PAT, "github-pat")

    def test_gitlab_token(self):
        self.assert_scrubbed(
            "glab auth login -t {}".format(FAKE_GITLAB),
            FAKE_GITLAB, "gitlab-token")

    def test_slack_bot_token(self):
        self.assert_scrubbed(
            "curl -d token={} https://slack.com/api/auth.test".format(
                FAKE_SLACK),
            FAKE_SLACK, "slack-token")

    def test_slack_app_token(self):
        self.assert_scrubbed(
            "export SLACK_APP={}".format(FAKE_SLACK_APP),
            FAKE_SLACK_APP, "slack-app-token")

    def test_aws_access_key_id(self):
        self.assert_scrubbed(
            "aws configure set aws_access_key_id {}".format(FAKE_AWS_ID),
            FAKE_AWS_ID, "aws-access-key-id")

    def test_api_key_prefix(self):
        self.assert_scrubbed(
            'curl -H "x-api-key: {}" https://api.anthropic.com'.format(
                FAKE_API_KEY),
            FAKE_API_KEY, "api-key")

    def test_private_key_block(self):
        pem = ("-----BEGIN RSA PRIVATE KEY-----\n"
               "MIIEowIBAAKCAQEAxfake1\nMIIEowIBAAKCAQEAxfake2\n"
               "-----END RSA PRIVATE KEY-----")
        out = redact("echo '{}' > id_rsa".format(pem))
        self.assertNotIn("MIIEowIBAAKCAQEAxfake1", out)
        self.assertIn("[REDACTED:private-key]", out)

    def test_url_credentials_keep_host(self):
        out = redact("psql postgres://appuser:hunter2ismypassword@db.internal/prod")
        self.assertNotIn("hunter2ismypassword", out)
        self.assertIn("[REDACTED:url-credentials]", out)
        # The parts that make the record useful survive.
        self.assertIn("appuser", out)
        self.assertIn("db.internal/prod", out)


class RedactAssignmentShapeTests(unittest.TestCase):
    """Value-only redaction, gated on the value looking like a literal."""

    def test_generic_header_value(self):
        secret = "9f3c1a7e42b8d05e6c1f9a7b3d2e8c40"
        out = redact('curl -H "X-Api-Key: {}" https://service/endpoint'.format(
            secret))
        self.assertNotIn(secret, out)
        self.assertIn("X-Api-Key", out)
        self.assertIn("https://service/endpoint", out)

    def test_generic_flag_value(self):
        secret = "7d1e4b90c3a25f68d4e7b1c093a56f28"
        out = redact("deploy --token {} --region us-east-1".format(secret))
        self.assertNotIn(secret, out)
        self.assertIn("--token", out)
        self.assertIn("--region us-east-1", out)

    def test_env_assignment(self):
        secret = "e81f5c27b940a63de5f2c8194b7a0d36"
        out = redact('SERVICE_TOKEN="{}" ./run.sh'.format(secret))
        self.assertNotIn(secret, out)
        self.assertIn("SERVICE_TOKEN", out)
        self.assertIn("./run.sh", out)

    def test_shell_expansion_not_flagged(self):
        # The recommended form: the secret never enters argv.
        for command in (
            'curl -H "X-Api-Key: $API_KEY" https://service/endpoint',
            "deploy --token ${DEPLOY_TOKEN_FOR_PRODUCTION}",
            'gh auth login --with-token "$(cat /run/secrets/gh_token_value)"',
        ):
            self.assertEqual(redact(command), command, command)

    def test_ordinary_names_not_flagged(self):
        for command in (
            "deploy --token some-resource-name",
            "aws s3 ls s3://my-bucket-2024/",
            "kubectl get secret app-credentials -n default",
            "terraform apply -var access_key_id=aws_iam_access_key.ci.id",
        ):
            self.assertEqual(redact(command), command, command)


class FindSecretsTests(unittest.TestCase):

    def test_reports_shape_and_position_only(self):
        command = "gh auth login --with-token {}".format(FAKE_GH_TOKEN)
        spans = find_secrets(command)
        self.assertEqual(len(spans), 1)
        start, end, kind = spans[0]
        self.assertEqual(kind, "github-token")
        self.assertEqual(command[start:end], FAKE_GH_TOKEN)
        # Nothing in the report itself carries the value.
        self.assertNotIn(FAKE_GH_TOKEN, repr((start, end, kind)))

    def test_overlapping_matches_collapse(self):
        # Both header-value and github-token match here; one span wins.
        command = 'curl -H "Authorization: Bearer {}" https://x'.format(
            FAKE_GH_TOKEN)
        self.assertEqual(len(find_secrets(command)), 1)

    def test_multiple_distinct_secrets(self):
        command = "AWS_KEY={} gh auth login --with-token {}".format(
            FAKE_AWS_ID, FAKE_GH_TOKEN)
        kinds = [k for _, _, k in find_secrets(command)]
        self.assertEqual(len(kinds), 2)
        out = redact(command)
        self.assertNotIn(FAKE_AWS_ID, out)
        self.assertNotIn(FAKE_GH_TOKEN, out)

    def test_clean_command_untouched(self):
        command = "git --no-pager log --oneline -20"
        self.assertEqual(find_secrets(command), [])
        self.assertEqual(redact(command), command)

    def test_empty_input(self):
        self.assertEqual(redact(""), "")
        self.assertEqual(redact(None), None)


class LogWritingTests(unittest.TestCase):
    """End-to-end: the bytes that hit disk carry no credential.

    This is the actual bug in #84 - unit-level redaction is only half the
    claim, the other half is that both hook entry points call it.
    """

    def run_hook(self, flag, command, env_key, log_path):
        env = dict(os.environ)
        env[env_key] = str(log_path)
        env["PYTHONPATH"] = str(REPO_ROOT / "hooks")
        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "permission_mode": "default",
        }
        subprocess.run(
            [sys.executable, str(REPO_ROOT / "hooks" / "yolt_analyzer.py"), flag],
            input=json.dumps(payload), capture_output=True, text=True,
            env=env, timeout=60,
        )

    def assert_log_clean(self, flag, env_key):
        command = 'curl -H "Authorization: Bearer {}" https://api.github.com'.format(
            FAKE_GH_TOKEN)
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "yolt-test.log"
            self.run_hook(flag, command, env_key, log_path)
            self.assertTrue(log_path.exists(),
                            "{} wrote no log".format(flag))
            written = log_path.read_text()
            self.assertNotIn(FAKE_GH_TOKEN, written)
            self.assertIn("REDACTED", written)
            # Still a usable record: the command shape survives.
            self.assertIn("curl", written)

    def test_decision_log_redacts(self):
        self.assert_log_clean("--hook", "YOLT_LOG_FILE")

    def test_ran_log_redacts(self):
        self.assert_log_clean("--ran-hook", "YOLT_RAN_LOG_FILE")


if __name__ == "__main__":
    unittest.main()
