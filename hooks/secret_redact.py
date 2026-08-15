#!/usr/bin/env python3
"""Credential detection and redaction for command strings.

YOLT sees every Bash command and writes it to two append-only logs under
`~/.claude/`. Credentials routinely appear on command lines (headers,
`--token` flags, connection strings), so without this the logs become an
unswept plaintext credential store. See issue #84.

Scope note: a command line is not prose. It is short and structured, and
secrets in it appear in known shapes, so prefix matching is accurate here
in a way it is not across a transcript.

Two match families:

  - Structured prefixes (`ghp_`, `AKIA`, `xoxb-`, PEM blocks, ...) —
    self-identifying, matched whole.
  - Assignment shapes (`--token X`, `Authorization: X`, `FOO_TOKEN=X`) —
    only the *value* is redacted, and only when it looks like a literal
    secret rather than a shell expansion or an ordinary resource name.
    Keeping the flag and the key name preserves the command *shape*,
    which is what `yolt_review.py` actually mines.

Nothing here ever emits, logs or returns the matched value: a
secret-detector that writes secrets into its own diagnostics is the same
bug one layer down. `find_secrets` reports shape and position only.

Known limits, so nobody mistakes this for a guarantee
-----------------------------------------------------
This is best-effort. It removes the shapes below, not "all credentials".
A value with no self-identifying prefix and no secret-ish context around
it is indistinguishable from an ordinary argument, and is not caught:

  - `mysql -pSECRET` and friends. Deliberately skipped: a `-p` rule
    cannot be told apart from `mkdir -p /var/log/app/2024/01`, and a
    matcher that mangles ordinary commands gets switched off, which
    protects nothing.
  - A bare positional secret: `./deploy s3cr3tvalue00000000`.
  - Credentials inside a file the command merely references.

When adding a shape, add it to the false-positive corpus in
`tests/test_secret_redact.py` too - widening is only safe while that
stays green.

Zero external dependencies - stdlib only.
"""

import re


# (kind, pattern, group). Group 0 means "redact the whole match"; a
# positive group redacts just that capture and leaves the rest intact.
_STRUCTURED_PATTERNS = [
    ("private-key", re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"
        r".*?"
        r"-----END [A-Z0-9 ]*PRIVATE KEY-----", re.S), 0),
    ("github-pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{16,}"), 0),
    ("github-token", re.compile(r"\bgh[posru]_[A-Za-z0-9]{16,}"), 0),
    ("gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9_\-]{16,}"), 0),
    ("slack-app-token", re.compile(r"\bxapp-[0-9]-[A-Za-z0-9\-]{10,}"), 0),
    ("slack-token", re.compile(r"\bxox[baprse]-[A-Za-z0-9\-]{10,}"), 0),
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0),
    ("api-key", re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}"), 0),
    # scheme://user:secret@host - redact only the password field.
    ("url-credentials", re.compile(
        r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@]+:([^\s/@]+)@"), 1),
]

_SECRETISH_FLAG = (
    r"token|password|passwd|secret|"
    r"api[-_]?key|access[-_]?key|secret[-_]?key|auth"
)
_SECRETISH_NAME = (
    r"TOKEN|SECRET|PASSWORD|PASSWD|APIKEY|API_KEY|"
    r"ACCESS_KEY|SECRET_KEY|CREDENTIAL|CREDENTIALS"
)
_SECRETISH_HEADER = (
    r"Authorization|Proxy-Authorization|Cookie|"
    r"X-Api-Key|Api-Key|X-Auth-Token|X-Access-Token|Private-Token"
)
# Bare names that carry a value as the *next* token rather than after a
# `--flag`. Kept to an unambiguous list: these words do not appear as
# ordinary positional arguments, so the following token is a value.
# `aws configure set aws_secret_access_key <value>` is the shape that
# motivated this - the AWS *secret* key has no prefix of its own, so
# only its context identifies it.
_SECRETISH_WORD = (
    r"aws_secret_access_key|aws_session_token|"
    r"client_secret|refresh_token|access_token|private_key_id"
)
_SECRETISH_QUERY = (
    r"password|passwd|pwd|token|api_key|apikey|"
    r"secret|client_secret|access_token|auth"
)

# Same tuple shape, but the captured value must additionally pass
# `_looks_like_literal_secret` before it is treated as a match.
_ASSIGNMENT_PATTERNS = [
    ("flag-value", re.compile(
        r"--(?:" + _SECRETISH_FLAG + r")(?:[=\s]+)[\"']?([^\s\"']+)", re.I), 1),
    ("env-assignment", re.compile(
        r"\b[A-Za-z_][A-Za-z0-9_]*(?:" + _SECRETISH_NAME + r")"
        r"\s*=\s*[\"']?([^\s\"']+)", re.I), 1),
    ("header-value", re.compile(
        r"(?:" + _SECRETISH_HEADER + r")\s*:\s*"
        r"(?:Bearer\s+|Basic\s+|token\s+)?([^\s\"']+)", re.I), 1),
    ("named-value", re.compile(
        r"\b(?:" + _SECRETISH_WORD + r")[\s=]+[\"']?([^\s\"']+)", re.I), 1),
    # curl -u user:password / --user user:password - redact the password
    # half only, so the account stays visible in the record.
    ("basic-auth", re.compile(
        r"(?:^|\s)(?:-u|--user)[=\s]+[\"']?[^\s:\"']+:([^\s\"']+)"), 1),
    ("query-param", re.compile(
        r"[?&](?:" + _SECRETISH_QUERY + r")=([^\s&\"'#]+)", re.I), 1),
]

# Below this, a value is too short to be a credential worth the false
# positives it would cost. 16 is the shortest token length in common use.
_MIN_VALUE_LEN = 16
# At or above this, a value is too long to be a resource name, so the
# usual "must mix letters and digits" test is waived - it would otherwise
# miss an all-hex key that happens to contain no digits, or an all-alpha
# base62 token.
_LONG_VALUE_LEN = 32


def _looks_like_literal_secret(value):
    """True when `value` looks like a credential literal sitting in argv.

    Deliberately conservative - the assignment shapes fire on any
    `--token X`, so this guard is what keeps `--token $MY_TOKEN` and
    `--token some-resource-name` out of the results. It errs toward
    redacting: a false positive costs one unreadable value in a debug
    log, a false negative costs a credential on disk forever.
    """
    retval = True
    if value.startswith("$") or "$(" in value or "`" in value:
        # A shell expansion: the secret is not in the command string,
        # which is exactly the form we want people using.
        retval = False
    elif len(value) < _MIN_VALUE_LEN:
        retval = False
    elif not re.fullmatch(r"[A-Za-z0-9_\-.+/=~:%]+", value):
        retval = False
    elif len(value) < _LONG_VALUE_LEN and not (
            any(c.isdigit() for c in value)
            and any(c.isalpha() for c in value)):
        # Short *and* all-alphabetic or all-numeric reads as a name or an
        # id, not a key. Long values skip this test - see _LONG_VALUE_LEN.
        retval = False
    return retval


def find_secrets(text):
    """Return credential spans in `text` as `(start, end, kind)` tuples.

    Sorted by position, non-overlapping (an outer match wins over one
    nested inside it). The value itself is never returned - callers get
    shape and position only, so a caller cannot accidentally surface a
    secret in a warning or a diagnostic.
    """
    spans = []
    for kind, pattern, group in _STRUCTURED_PATTERNS:
        for match in pattern.finditer(text):
            spans.append((match.start(group), match.end(group), kind))
    for kind, pattern, group in _ASSIGNMENT_PATTERNS:
        for match in pattern.finditer(text):
            if _looks_like_literal_secret(match.group(group)):
                spans.append((match.start(group), match.end(group), kind))

    # Longest-first at a given start so a header-value span that contains
    # a `ghp_...` span swallows it rather than producing two records.
    spans.sort(key=lambda s: (s[0], -s[1]))
    retval = []
    reach = -1
    for start, end, kind in spans:
        if start >= reach:
            retval.append((start, end, kind))
            reach = end
    return retval


def redact(text):
    """Return `text` with every credential span replaced by a marker.

    The marker names the shape (`[REDACTED:github-token]`) so the record
    stays diagnosable, and the command's structure survives intact.
    Returns `text` unchanged when nothing matches, and is a no-op on
    empty / non-string input.
    """
    if not text:
        retval = text
        return retval
    spans = find_secrets(text)
    if not spans:
        retval = text
        return retval
    out = []
    cursor = 0
    for start, end, kind in spans:
        out.append(text[cursor:start])
        out.append("[REDACTED:{}]".format(kind))
        cursor = end
    out.append(text[cursor:])
    retval = "".join(out)
    return retval
