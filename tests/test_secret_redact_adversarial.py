"""Adversarial credential shapes from voitta-ai/voitta-yolt#165.

Values are assembled at runtime so no token-shaped literal is committed.
Positives must be redacted; negatives must survive untouched.
"""
import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "hooks"))
from secret_redact import redact  # noqa: E402

A = "abcdefgh"
B = "ijklmnop"
L32 = "A" * 20 + "b3C9" * 3
SK = "a1B2" * 12
HEX40 = "0123456789abcdef" * 2 + "01234567"
JWT_SIG = A + B


def _jwt(header_b64, payload_b64):
    return "{}.{}.{}".format(header_b64, payload_b64, JWT_SIG)


POSITIVES = [
    ("quoted-json-key", '{"OPENAI_API_TOKEN": "%s"}' % L32),
    ("quoted-spaces", '"password": "correct horse battery staple"'),
    ("quoted-escaped-quote", 'token = "%s\\"%s"' % (A, B)),
    ("quoted-parens", 'token = "abc(def)ghij"'),
    ("short-quoted-double", 'API_TOKEN = "1234567"'),
    ("short-quoted-single", "password: 'hunter2hunter2'"),
    ("unquoted-letters", "password=correcthorsebatterystaple"),
    ("unquoted-punct-at", "password=p@ssword123"),
    ("unquoted-punct-bang", "password=%s!%s" % (A, B)),
    ("short-bearer", "Authorization: Bearer %s" % A),
    ("jwt-payload-e30", _jwt("eyJhbGciOiJIUzI1NiJ9", "e30")),
    ("jwt-header-eyA", _jwt("eyAiYWxnIjoiSFMyNTYiIH0", "eyJzdWIiOiIxIn0")),
    ("sk-underscored", "_sk-%s_" % SK),
    ("hex-blob", "secret=%s" % HEX40),
    ("colon-env", "API_KEY: %s" % L32),
]

NEGATIVES = [
    "sk-configuration-management-placeholder",
    "sk-configuration-V2-placeholder",
    "task-sk-configuration-management-placeholder",
    "token=response.access_token();x=1",
    "git log --oneline -5",
    "--token $MY_TOKEN",
    "--token ${MY_TOKEN}",
    "kubectl get secret my-service-auth-token-dev",
    "echo API key env var is MY_SERVICE_API_KEY",
    "password=$(op read op://vault/item/password)",
]


class TestAdversarialShapes(unittest.TestCase):
    def test_positives_redacted(self):
        leaks = [n for n, c in POSITIVES if redact(c) == c]
        self.assertEqual(leaks, [], "shapes left in cleartext: %s" % leaks)

    def test_negatives_untouched(self):
        mangled = [c for c in NEGATIVES if redact(c) != c]
        self.assertEqual(mangled, [], "ordinary text mangled: %s" % mangled)

    def test_idempotent(self):
        for _, c in POSITIVES:
            once = redact(c)
            self.assertEqual(redact(once), once, "not idempotent: %r" % c)


if __name__ == "__main__":
    unittest.main()
