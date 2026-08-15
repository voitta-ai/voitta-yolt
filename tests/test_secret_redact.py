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


class BypassRegressionTests(unittest.TestCase):
    """Shapes that survived redaction during adversarial review.

    Each of these was a verified bypass: the credential reached the log
    in plaintext. Keep them failing-if-broken.
    """

    def assert_redacted(self, command):
        self.assertNotEqual(redact(command), command,
                            "credential survived: {}".format(command))

    def test_aws_secret_access_key_has_no_prefix_of_its_own(self):
        # Only the surrounding context identifies it, unlike AKIA/ASIA.
        self.assert_redacted(
            "aws configure set aws_secret_access_key "
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

    def test_curl_basic_auth(self):
        for flag in ("-u", "--user"):
            self.assert_redacted(
                "curl {} admin:s3cr3tP4ssw0rdVeryLong123 "
                "https://api.example.com".format(flag))

    def test_curl_basic_auth_keeps_the_account(self):
        out = redact("curl -u admin:s3cr3tP4ssw0rdVeryLong123 https://x")
        self.assertNotIn("s3cr3tP4ssw0rdVeryLong123", out)
        self.assertIn("admin", out)

    def test_password_in_query_string(self):
        self.assert_redacted(
            'curl "https://api.example.com/login'
            '?password=hunter2VeryLongPassword99"')

    def test_token_in_later_query_param(self):
        self.assert_redacted(
            'curl "https://x/api?page=2'
            '&access_token=8f14e45fceea167a5a36dedd4bea2543"')

    def test_sixteen_char_token(self):
        # The old 20-char floor let common token lengths through.
        self.assert_redacted("deploy --token a1b2c3d4e5f6g7h8")

    def test_long_value_without_digits(self):
        # An all-hex key can contain no digits; an all-alpha base62 token
        # is ordinary. Both used to be dismissed as "reads like a name".
        self.assert_redacted(
            "deploy --token deadbeefcafebabedeadbeefcafebabe")
        self.assert_redacted(
            "deploy --token abcdefghijklmnopqrstuvwxyzABCDEF")

    def test_url_encoded_value(self):
        self.assert_redacted("deploy --token abc%123def%456ghi%789jkl")

    def test_bare_secretish_word_then_value(self):
        self.assert_redacted(
            "oauth2 client_secret 8f14e45fceea167a5a36dedd4bea2543")


class BareEnvNameTests(unittest.TestCase):
    """Issue #90: every keyword in `_SECRETISH_NAME` failed to match itself.

    The pattern required at least one character *before* the keyword, so
    `GH_TOKEN=` matched and bare `TOKEN=` did not. The existing corpus
    only used prefixed names, which is precisely what hid it — so this
    exercises each keyword standalone.
    """

    VALUE = "9f3c1a7e42b8d05e6c1f9a7b3d2e8c40"
    KEYWORDS = [
        "TOKEN", "PASSWORD", "PASSWD", "SECRET", "APIKEY", "API_KEY",
        "ACCESS_KEY", "SECRET_KEY", "CREDENTIAL", "CREDENTIALS",
    ]

    def test_each_keyword_matches_standalone(self):
        for keyword in self.KEYWORDS:
            command = "{}={} ./deploy.sh".format(keyword, self.VALUE)
            self.assertNotIn(self.VALUE, redact(command), command)

    def test_lowercase_forms(self):
        for keyword in ("token", "password", "secret"):
            command = "{}={} ./deploy.sh".format(keyword, self.VALUE)
            self.assertNotIn(self.VALUE, redact(command), command)

    def test_prefixed_forms_still_work(self):
        for keyword in ("GH_TOKEN", "DB_PASSWORD", "MYTOKEN", "X_API_KEY"):
            command = "{}={} ./deploy.sh".format(keyword, self.VALUE)
            self.assertNotIn(self.VALUE, redact(command), command)


class OverlapClippingTests(unittest.TestCase):
    """Issue #90: a span starting inside its predecessor but ending
    beyond it was dropped entirely rather than clipped, leaving the
    uncovered tail in cleartext next to a marker that made the record
    read as handled."""

    def test_run_on_pem_after_a_flag_value(self):
        command = ("ssh-add --password abc123def456ghi789"
                   "-----BEGIN RSA PRIVATE KEY-----\n"
                   "BODYSECRETMATERIAL\n"
                   "-----END RSA PRIVATE KEY-----")
        out = redact(command)
        self.assertNotIn("BODYSECRETMATERIAL", out)
        self.assertNotIn("abc123def456ghi789", out)

    def test_clipped_spans_are_contiguous_and_ordered(self):
        command = ("ssh-add --password abc123def456ghi789"
                   "-----BEGIN RSA PRIVATE KEY-----\n"
                   "BODY\n-----END RSA PRIVATE KEY-----")
        spans = find_secrets(command)
        self.assertGreater(len(spans), 1)
        for (s1, e1, _), (s2, e2, _) in zip(spans, spans[1:]):
            self.assertLessEqual(e1, s2, "spans overlap after clipping")
            self.assertLess(s2, e2, "empty span emitted")

    def test_fully_contained_span_still_collapses(self):
        # The original behaviour for containment must not regress: one
        # span, not two.
        command = 'curl -H "Authorization: Bearer {}" https://x'.format(
            FAKE_GH_TOKEN)
        self.assertEqual(len(find_secrets(command)), 1)


class ValueGuardTests(unittest.TestCase):
    """Issue #92: the guard's character allow-list ran backwards.

    It excluded `! @ # , & { }` and space, so the more punctuation a
    password had - the more entropy - the likelier it was to be dismissed
    as "not secret-shaped". Now a deny-list: only shell expansions are
    rejected outright.
    """

    def assert_redacted(self, command):
        self.assertNotEqual(redact(command), command,
                            "credential survived: {}".format(command))

    def test_passwords_with_punctuation(self):
        for value in ("Tr0ub4dor&3!SuperLongPassword",
                      "MyP@ssw0rd!VeryLongIndeed2024",
                      "Str0ngP#ssword!LongEnough2024",
                      "{9f3c1a7e42b8d05e6c1f9a7b3d2e8c40}",
                      "user,pass,SuperSecretTokenValue123"):
            self.assert_redacted(
                'deploy --token "{}" --env prod'.format(value))

    def test_quoted_multiword_passphrase(self):
        # An unquoted capture stopped at the first space, redacting
        # `correct` and leaving the rest of the passphrase in cleartext.
        out = redact('deploy --password "correct horse battery staple"')
        self.assertNotIn("horse battery staple", out)

    def test_long_values_without_a_digit(self):
        # _LONG_VALUE_LEN lowered 32 -> 24; both of these sat in the gap.
        self.assert_redacted("deploy --token deadbeefcafebabedeadbeef")
        self.assert_redacted("deploy --token CORRECTHORSEBATTERYSTAPLEXYZZY")

    def test_shell_expansions_still_rejected(self):
        for command in ("deploy --token $DEPLOY_TOKEN_FOR_PRODUCTION",
                        "deploy --token ${DEPLOY_TOKEN_FOR_PRODUCTION}",
                        'deploy --token "$(fetch-secret --name prod-token)"'):
            self.assertEqual(redact(command), command, command)

    def test_long_ordinary_words_are_not_redacted(self):
        """Length alone is the wrong discriminator; alphabet is the right one.

        An earlier round set `_LONG_VALUE_LEN` to 24 to catch
        `deadbeefcafebabedeadbeef` (24 hex, no digits) and concluded that
        the resulting over-redaction of ordinary long words was
        unavoidable, since a passphrase and an English word are
        structurally the same string.

        They are — but that was the wrong axis. 24 is exactly the band
        where hyphenated resource names live. Raising the bound to 28 and
        adding a separate all-hex rule separates the cases cleanly,
        because the hex value was never about *length*: it was about
        being drawn from an alphabet nobody names things in.
        """
        for command in ("deploy --secret ThisIsAVeryLongDescription",
                        "app --auth-token authenticationprovidername",
                        "deploy --token production-deployment-approval"):
            self.assertEqual(redact(command), command, command)

    def test_hex_blobs_are_caught_regardless_of_length_band(self):
        for value in ("deadbeefcafebabedeadbeef",
                      "9f3c1a7e42b8d05e6c1f9a7b3d2e8c40",
                      "ABCDEF0123456789ABCDEF01"):
            command = "deploy --token {}".format(value)
            self.assertNotIn(value, redact(command), value)

    def test_long_passphrases_still_caught(self):
        for value in ("CORRECTHORSEBATTERYSTAPLEXYZZY",
                      "abcdefghijklmnopqrstuvwxyzABCDEF"):
            command = "deploy --token {}".format(value)
            self.assertNotIn(value, redact(command), value)


class VendorPrefixTests(unittest.TestCase):
    """Issue #92: `sk-` was hyphen-only, and several common vendor
    prefixes plus bare JWTs had no pattern at all."""

    def assert_redacted(self, value):
        command = "deploy {}".format(value)
        self.assertNotIn(value, redact(command), value)

    def test_stripe_underscore_separator(self):
        self.assert_redacted("sk_live_51H8vXyZaBcDeFgHiJkLmNoPqRsTu")
        self.assert_redacted("rk_live_51H8vXyZaBcDeFgHiJkLmNoPqRsTu")

    def test_other_vendor_prefixes(self):
        # Suffix lengths are the real formats: npm 36, HuggingFace 34,
        # Docker 24+. The earlier fixtures were short of them, which is
        # how a `{16,}` pattern loose enough to match `npm_config_*`
        # looked correct.
        self.assert_redacted("dckr_pat_AbCdEfGhIjKlMnOpQrStUvWx")
        self.assert_redacted("npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789")
        self.assert_redacted("hf_AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGh")

    def test_google_api_key(self):
        self.assert_redacted("AIzaSyD-1234567890abcdefghijklmnopqrs")

    def test_bare_jwt(self):
        # Previously caught only behind an Authorization header.
        self.assert_redacted(
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0."
            "abcdefghijklmnopqrstuvwxyz123456")

    def test_hyphen_form_still_works(self):
        self.assert_redacted("sk-ant-api03-aB3dE6gH9jK2mN5pQ8sT1vW4")


class IdempotenceTests(unittest.TestCase):
    """Issue #89: patterns matched inside the module's own markers, so a
    second pass rewrote its own output. That made "re-scan and expect
    zero hits" useless for verifying a retro-scrub of existing logs."""

    PROBES = [
        'curl -H "Authorization: Bearer {}" https://x'.format(FAKE_GH_TOKEN),
        "psql postgres://u:hunter2ismypassword@h/db",
        "TOKEN=9f3c1a7e42b8d05e6c1f9a7b3d2e8c40 ./x",
        "curl -u admin:s3cr3tP4ssw0rdVeryLong123 https://x",
        "deploy sk_live_51H8vXyZaBcDeFgHiJkLmNoPqRsTu",
        'deploy --token "Tr0ub4dor&3!SuperLongPassword" --env prod',
        ("ssh-add --password abc123def456ghi789"
         "-----BEGIN RSA PRIVATE KEY-----\nB\n"
         "-----END RSA PRIVATE KEY-----"),
    ]

    def test_redact_is_idempotent(self):
        for probe in self.PROBES:
            once = redact(probe)
            self.assertEqual(once, redact(once), probe)
            self.assertEqual(once, redact(redact(once)), probe)

    def test_rescan_of_redacted_text_is_clean(self):
        """The property that makes verifying a scrub possible at all."""
        for probe in self.PROBES:
            once = redact(probe)
            leftovers = [
                (s, e, k) for s, e, k in find_secrets(once)
                if not once[s:e].startswith("[REDACTED:")
            ]
            self.assertEqual(leftovers, [], probe)

    def test_a_real_secret_beside_a_marker_is_still_caught(self):
        # The skip is character-level, not "overlaps a marker", so
        # adjacency must not create a blind spot.
        text = "TOKEN=[REDACTED:api-key]{}".format(FAKE_GH_TOKEN)
        self.assertNotIn(FAKE_GH_TOKEN, redact(text))

    def test_span_that_swallows_a_marker_does_not_re_redact(self):
        """The case that kept `redact` non-idempotent.

        A bare `flag-value` capture swallows an existing marker plus its
        surrounding structure, and the whole span is not marker-covered,
        so it was redacted again on the second pass. Now the residue is
        judged with the markers removed: if what is left is not itself
        secret-shaped, the sensitive part is already handled.
        """
        for command in ("--token https://u:p@h/",
                        "SECRET=https://u:p@h/",
                        "curl -u bob:https://a:b@c/"):
            once = redact(command)
            self.assertEqual(once, redact(once), command)

    def test_a_value_wrapped_in_marker_syntax_is_still_redacted(self):
        """`[a-z0-9-]+` is also the shape of a lowercase-hex key, so a
        permissive marker pattern let a wrapped value pass as its own
        marker. The kind list is a closed enum; the pattern pins it."""
        for command in (
            "TOKEN=[REDACTED:9f3c1a7e42b8d05e6c1f9a7b3d2e8c40] ./run.sh",
            "deploy --token [REDACTED:deadbeefcafebabedeadbeef]",
        ):
            self.assertNotEqual(redact(command), command, command)

    def test_marker_pattern_tracks_the_kind_tables(self):
        """Built from the tables, so adding a kind cannot silently break
        idempotence."""
        import secret_redact
        kinds = ({k for k, _, _ in secret_redact._STRUCTURED_PATTERNS}
                 | {k for k, _, _ in secret_redact._ASSIGNMENT_PATTERNS})
        for kind in kinds:
            self.assertTrue(
                secret_redact._MARKER_RE.fullmatch(
                    "[REDACTED:{}]".format(kind)),
                "marker pattern misses kind {}".format(kind))


class VendorPrefixPrecisionTests(unittest.TestCase):
    """The vendor prefixes are *structured* patterns, so they bypass the
    value guard entirely - there is no length or entropy gate behind
    them. A loose prefix therefore has no safety net, and `npm_` with a
    permissive suffix matched npm's own environment variables."""

    def test_npm_environment_variables_are_not_tokens(self):
        for command in (
            "env | grep npm_config_registry_https_proxy",
            "echo $npm_package_dependencies_typescript",
            "export npm_lifecycle_script_prepublish_only=1",
        ):
            self.assertEqual(redact(command), command, command)

    def test_huggingface_cache_paths_are_not_tokens(self):
        command = "aws s3 ls s3://my-bucket/hf_datasets_cache_directory/"
        self.assertEqual(redact(command), command)

    def test_underscore_form_requires_the_stripe_segment(self):
        # `rk_`/`sk_` without live/test is an ordinary identifier.
        self.assertEqual(
            redact("docker build -t rk_analytics_pipeline_worker:latest ."),
            "docker build -t rk_analytics_pipeline_worker:latest .")
        self.assertNotEqual(
            redact("deploy sk_live_51H8vXyZaBcDeFgHiJkLmNoPqRsTu"),
            "deploy sk_live_51H8vXyZaBcDeFgHiJkLmNoPqRsTu")

    def test_real_vendor_tokens_at_their_real_lengths(self):
        for value in ("npm_" + "a" * 36, "hf_" + "b" * 34,
                      "dckr_pat_" + "c" * 24):
            command = "deploy {}".format(value)
            self.assertNotIn(value, redact(command), value)


class AuthFlagTests(unittest.TestCase):
    """`--auth <mode>` is the common shape and almost never carries a
    literal, so a bare `auth` in the flag list produced more false
    positives than every other flag word combined."""

    def test_auth_mode_values_are_left_alone(self):
        for command in (
            "helm install app ./chart --auth kubernetes-service-account",
            "kafka --auth SASL_SSL,SCRAM-SHA-512,PLAINTEXT",
            "deploy --auth serviceaccount-workload-identity",
        ):
            self.assertEqual(redact(command), command, command)

    def test_auth_token_still_matches(self):
        for flag in ("--auth-token", "--authtoken", "--auth_token"):
            command = "deploy {} 9f3c1a7e42b8d05e6c1f9a7b3d2e8c40".format(flag)
            self.assertNotIn("9f3c1a7e42b8d05e6c1f9a7b3d2e8c40",
                             redact(command), flag)


class FalsePositiveCorpusTests(unittest.TestCase):
    """Ordinary commands that must survive redaction byte-for-byte.

    Widening the matcher is only safe while this stays green - a
    redactor that mangles normal commands makes the log useless and
    gets the whole feature turned off.
    """

    CLEAN = [
        "deploy --token some-resource-name",
        "deploy --token $DEPLOY_TOKEN_FOR_PRODUCTION",
        "aws s3 ls s3://my-bucket-2024/",
        "aws secretsmanager get-secret-value --secret-id prod/db/credentials-v2",
        "kubectl get secret app-credentials -n default",
        "mkdir -p /var/log/myapp/2024/01/backups",
        "docker run -u 1000:1000 alpine",
        "git checkout a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
        "curl https://api.example.com/v1/users?page=2&limit=100",
        "terraform apply -var access_key_id=aws_iam_access_key.ci.id",
        "python3 -m pytest tests/test_secret_redact.py -v",
        "ssh -i ~/.ssh/id_ed25519 user@host.example.com",
        'curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com',
        'find . -name "*.log" -mtime +30 -delete',
        "aws configure set region us-east-1",
        "helm upgrade myapp ./chart --set image.tag=v1.2.3-rc4",
        'psql -h db.internal -U appuser -d production -c "select 1"',
        # Added when the guard moved from allow-list to deny-list (#92):
        # dropping the character class is the change most likely to start
        # matching ordinary arguments, so the corpus grew with it.
        "echo TOKENIZER=simple >> config.env",
        "make TOKEN_LIMIT=4096 build",
        "git commit -m 'fix: token=abc parsing in the lexer'",
        "curl -u ci-bot:$GITHUB_TOKEN https://api.github.com",
        "deploy --secret-key-file /etc/app/config/production.key.json",
        "vault read secret/data/app-config-production-v2",
        "kubectl describe pod my-app-deployment-7d4b8c9f5-x2m9k",
        "npm install --save-dev @types/node-fetch",
        "gh pr view 94 --repo voitta-ai/voitta-yolt --json body",
        "docker build -t registry.example.com/team/app:sha-abc1234 .",
        "aws ecs update-service --service my-service --force-new-deployment",
        "./deploy --token ${DEPLOY_TOKEN}",
        "grep -rn 'password' src/ --include='*.py'",
    ]

    def test_ordinary_commands_untouched(self):
        for command in self.CLEAN:
            self.assertEqual(redact(command), command, command)


class PerformanceTests(unittest.TestCase):
    """The matcher runs on every Bash call, so a pathological command
    must not stall the hook."""

    def test_pathological_inputs_stay_fast(self):
        import time
        for command in (
            "echo " + "a" * 100000,
            # Unterminated PEM header + bulk: exercises the `.*?` with re.S.
            "echo '-----BEGIN RSA PRIVATE KEY-----" + "A" * 100000,
            " ".join(["--token abc"] * 5000),
        ):
            start = time.perf_counter()
            find_secrets(command)
            elapsed = time.perf_counter() - start
            self.assertLess(elapsed, 1.0,
                            "find_secrets took {:.2f}s".format(elapsed))

    def test_many_unterminated_pem_headers(self):
        """Issue #92: the `.*?` with re.S was O(n^2) in unterminated
        BEGIN markers - 800 of them across 4MB measured at 7.7s. Without
        a terminator after a BEGIN no match is possible, so it's skipped."""
        import time
        command = "echo '-----BEGIN RSA PRIVATE KEY-----" * 800 + "A" * 5000
        start = time.perf_counter()
        find_secrets(command)
        self.assertLess(time.perf_counter() - start, 1.0)

    def test_a_leading_end_marker_does_not_disarm_the_guard(self):
        """Testing for `-----END` anywhere was the wrong question: a
        single one *before* every BEGIN restored the full quadratic cost
        (8.3s on 4MB). The terminator has to follow a BEGIN."""
        import time
        command = ("-----END RSA PRIVATE KEY----- "
                   + ("-----BEGIN RSA PRIVATE KEY-----" + "M" * 5000) * 400)
        start = time.perf_counter()
        find_secrets(command)
        elapsed = time.perf_counter() - start
        self.assertLess(elapsed, 2.0,
                        "quadratic path reachable: {:.1f}s".format(elapsed))

    def test_a_real_pem_is_still_matched(self):
        """The short-circuit must not cost a genuine key."""
        command = ("echo '-----BEGIN RSA PRIVATE KEY-----\n"
                   "BODYSECRETMATERIAL\n"
                   "-----END RSA PRIVATE KEY-----'")
        self.assertNotIn("BODYSECRETMATERIAL", redact(command))


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

    def test_redactor_failure_writes_nothing_and_does_not_raise(self):
        """A bug in the redactor must cost a log line, not the session -
        and must never fall back to writing the raw command."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "ya_failclosed", REPO_ROOT / "hooks" / "yolt_analyzer.py")
        analyzer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(analyzer)

        def exploding_redact(text):
            raise ValueError("simulated redactor bug")

        analyzer.redact = exploding_redact
        command = "curl -H 'X-Api-Key: {}' https://x".format(FAKE_GH_TOKEN)
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "yolt.log"
            os.environ["YOLT_LOG_FILE"] = str(log_path)
            os.environ["YOLT_RAN_LOG_FILE"] = str(log_path)
            try:
                # Must not propagate.
                analyzer._log_hook_decision(
                    command, "safe", "reason", "default", None)
                analyzer._log_ran_command(command)
            finally:
                os.environ.pop("YOLT_LOG_FILE", None)
                os.environ.pop("YOLT_RAN_LOG_FILE", None)
            # Fail closed: the record is built before it is written, so a
            # raising redactor writes nothing rather than the raw command.
            written = log_path.read_text() if log_path.exists() else ""
            self.assertNotIn(FAKE_GH_TOKEN, written)


if __name__ == "__main__":
    unittest.main()
