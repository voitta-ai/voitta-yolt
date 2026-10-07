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
    which is what a log reader needs and a secret is not.

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
    # `sk-` (OpenAI/Anthropic) keeps the loose form: the hyphen makes it
    # distinctive. The underscore form must carry Stripe's `live`/`test`
    # segment - a bare `[sr]k_` matched `rk_analytics_pipeline_worker`.
    # `sk-` stays loose, but hyphen-joined English words are not a key
    # (`sk-configuration-management-placeholder`,
    # `sk-configuration-V2-placeholder`). The discriminator is a hyphen-FREE
    # run of 16+ characters: a real key body is one dense token, while kebab
    # text breaks every word or two. Requiring merely a digit or a capital
    # is not enough -- `V2` supplies both. Issue #165.
    ("api-key", re.compile(
        r"sk-(?=[A-Za-z0-9_\-]*[A-Za-z0-9_]{16,})[A-Za-z0-9_\-]{16,}"), 0),
    ("api-key", re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}"), 0),
    # Lengths pinned to the real formats. The earlier `{16,}` with `_-`
    # allowed matched npm's own environment variables (`npm_config_*`,
    # `npm_package_*`, `npm_lifecycle_*`), which appear constantly in CI
    # and Node work, and HuggingFace cache paths. See issue #92.
    ("vendor-token", re.compile(r"\bnpm_[A-Za-z0-9]{36,}"), 0),
    ("vendor-token", re.compile(r"\bhf_[A-Za-z0-9]{34,}"), 0),
    ("vendor-token", re.compile(r"\bdckr_pat_[A-Za-z0-9_\-]{20,}"), 0),
    ("vendor-token", re.compile(
        r"\b(?:glc_|shpat_|shpss_)[A-Za-z0-9]{20,}"), 0),
    # Google keys are 39 chars (`AIza` + 35), but pinning the length
    # exactly means a truncated or vendor-variant key sails through.
    # `AIza` is distinctive enough that a lower bound is safe.
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}"), 0),
    # A JWT is self-identifying (two base64url segments that decode to
    # `{"...`), so this is near-zero false-positive risk. Previously
    # caught only when it sat behind an Authorization header.
    ("jwt", re.compile(
        r"\be(?:yJ|yA|wo)[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{2,}"
        r"\.[A-Za-z0-9_\-]{8,}"), 0),
    # scheme://user:secret@host - redact only the password field.
    ("url-credentials", re.compile(
        r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@]+:([^\s/@]+)@"), 1),
]

# Note the absence of a bare `auth`: `--auth <mode>` is the common shape
# (`--auth basic`, `--auth SASL_SSL,SCRAM-SHA-512`,
# `--auth kubernetes-service-account`), so it produced more false
# positives than every other flag word combined while almost never
# carrying a literal. `--auth-token` / `--authtoken` still match. #92.
_SECRETISH_FLAG = (
    r"token|password|passwd|secret|"
    r"api[-_]?key|access[-_]?key|secret[-_]?key|auth[-_]?token"
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
    # Each entry is (kind, pattern, group, lenient). `lenient` means the KEY
    # already identified this as a credential, so the value is not also
    # required to look like one. See `_value_is_plausible`.
    #
    # Quoted first, so `--password "two words"` captures the whole value
    # rather than stopping at the space. An unquoted capture would take
    # only `two`, leaving the rest in cleartext. See issue #92.
    # `(?:[^"\\]|\\.)+` rather than `[^"]+` so a backslash-escaped quote
    # inside the value does not end the capture early (issue #165).
    ("flag-value", re.compile(
        r"--(?:" + _SECRETISH_FLAG + r")[=\s]+\"((?:[^\"\\]|\\.)+)\"", re.I), 1, True),
    ("flag-value", re.compile(
        r"--(?:" + _SECRETISH_FLAG + r")[=\s]+'((?:[^'\\]|\\.)+)'", re.I), 1, True),
    # Unquoted `--flag value` stays STRICT. A command-line flag legitimately
    # takes a resource name (`--token some-resource-name`,
    # `--secret ThisIsAVeryLongDescription`), so the value must still earn it.
    # A bare `NAME=` / `NAME:` right-hand side is different: that is a value
    # by construction, which is why those are lenient. Issue #165.
    ("flag-value", re.compile(
        r"--(?:" + _SECRETISH_FLAG + r")(?:[=\s]+)([^\s\"']+)", re.I), 1, False),
    # The name prefix is optional. It used to be `[A-Za-z_][A-Za-z0-9_]*`,
    # which required at least one character *before* the keyword and so
    # made every keyword fail to match itself: `GH_TOKEN=` matched,
    # bare `TOKEN=` did not. See issue #90.
    # `[=:]` rather than `=`, because JSON and YAML separate with a colon and
    # nothing else here accepted one: `{"OPENAI_API_TOKEN": "..."}` and
    # `password: 'hunter2'` matched no pattern at all (issue #165).
    ("env-assignment", re.compile(
        r"\b[A-Za-z0-9_]*(?:" + _SECRETISH_NAME + r")"
        r"[\"']?\s*[=:]\s*\"((?:[^\"\\]|\\.)+)\"", re.I), 1, True),
    ("env-assignment", re.compile(
        r"\b[A-Za-z0-9_]*(?:" + _SECRETISH_NAME + r")"
        r"[\"']?\s*[=:]\s*'((?:[^'\\]|\\.)+)'", re.I), 1, True),
    ("env-assignment", re.compile(
        r"\b[A-Za-z0-9_]*(?:" + _SECRETISH_NAME + r")"
        r"[\"']?\s*[=:]\s*([^\s\"']+)", re.I), 1, True),
    # Split on whether an auth SCHEME keyword is present, because that is the
    # only thing separating two cases of identical shape: `Bearer abcdefgh`
    # must redact (8 chars, all letters) while `X-Api-Key: PLACEHOLDERVALUE`
    # must not (16 chars, all letters). `Bearer`/`Basic`/`token` is an RFC-7235
    # scheme, so what follows is a credential by definition and needs no
    # entropy evidence; a bare header value does. Issue #165.
    ("header-value", re.compile(
        r"(?:" + _SECRETISH_HEADER + r")\s*:\s*"
        r"(?:Bearer|Basic|token)\s+([^\s\"']+)", re.I), 1, True),
    ("header-value", re.compile(
        r"(?:" + _SECRETISH_HEADER + r")\s*:\s*([^\s\"']+)", re.I), 1, False),
    ("named-value", re.compile(
        r"\b(?:" + _SECRETISH_WORD + r")[\s=:]+[\"']?([^\s\"']+)", re.I), 1, True),
    # curl -u user:password / --user user:password - redact the password
    # half only, so the account stays visible in the record.
    ("basic-auth", re.compile(
        r"(?:^|\s)(?:-u|--user)[=\s]+[\"']?[^\s:\"']+:([^\s\"']+)"), 1, False),
    ("query-param", re.compile(
        r"[?&](?:" + _SECRETISH_QUERY + r")=([^\s&\"'#]+)", re.I), 1, False),
]

# Below this, a value is too short to be a credential worth the false
# positives it would cost. 16 is the shortest token length in common use.
_MIN_VALUE_LEN = 16
# At or above this, a value is too long to be a resource name, so the
# usual "must mix letters and digits" test is waived - it would otherwise
# miss an all-alpha base62 token or a passphrase.
#
# 24 was too low: it is exactly the band where hyphenated resource names
# live (`production-deployment-approval`), and it redacted ordinary words
# like `authenticationprovidername`. 28 keeps
# `CORRECTHORSEBATTERYSTAPLEXYZZY` (30) while dropping those, and the
# all-hex rule below covers what 24 was really there for. Issue #92.
_LONG_VALUE_LEN = 28
# An all-hex string of this length is an encoded blob, never a name -
# `deadbeefcafebabedeadbeef` (24, no digits) is a key, not a word. This
# is the precise version of what the lowered length bound approximated.
_MIN_HEX_LEN = 20
# Lowercase kebab-case with alphabetic segments is a resource-name idiom
# (`production-deployment-approval`), never how a credential literal is
# shaped. Without this, that name and the passphrase
# `CORRECTHORSEBATTERYSTAPLEXYZZY` are both 30 all-alpha characters and
# no length bound can separate them. Segments are alpha-only on purpose:
# `abc-123-def-456-ghi` keeps its digits and stays redactable.
_KEBAB_NAME_RE = re.compile(r"[a-z]+(?:-[a-z]+)+")

# Rejected outright: the value is a shell expansion, so the secret is not
# in the command string at all - which is the form we want people using.
# This is a *deny*-list on purpose. The previous allow-list
# (`[A-Za-z0-9_\-.+/=~:%]+`) ran backwards: it excluded `! @ # , & { }`
# and space, so the more punctuation a password had - the more entropy -
# the likelier it was to be dismissed. Issue #92.
_EXPANSION_MARKERS = ("$(", "${", "`")

# The markers this module emits, so a second pass can recognise its own
# output and leave it alone (issue #89). Built from the pattern tables
# rather than hand-listed, so it cannot drift when a kind is added.
#
# Pinned to the exact kind names on purpose: a permissive `[a-z0-9-]+`
# is also the shape of a lowercase-hex API key, so
# `TOKEN=[REDACTED:9f3c1a7e42b8d05e6c1f9a7b3d2e8c40]` read as a marker
# and the value survived. Paste a redacted line back into a command and
# the next secret you put there would be invisible.
_MARKER_RE = re.compile(
    r"\[REDACTED:(?:{})\]".format(
        "|".join(sorted({kind for kind, _, _ in _STRUCTURED_PATTERNS}
                        | {kind for kind, _, _, _ in _ASSIGNMENT_PATTERNS},
                        key=len, reverse=True))
    )
)


def _looks_like_literal_secret(value):
    """True when `value` looks like a credential literal sitting in argv.

    Deliberately conservative about *context*, not about characters - the
    assignment shapes fire on any `--token X`, so this guard is what keeps
    `--token $MY_TOKEN` and `--token some-resource-name` out of the
    results. Within that, it errs toward redacting: a false positive costs
    one unreadable value in a debug log, a false negative costs a
    credential on disk forever.
    """
    retval = True
    if value.startswith("$") or any(m in value for m in _EXPANSION_MARKERS):
        retval = False
    elif len(value) < _MIN_VALUE_LEN:
        retval = False
    elif _looks_like_hex_blob(value):
        retval = True
    elif _KEBAB_NAME_RE.fullmatch(value):
        retval = False
    elif len(value) < _LONG_VALUE_LEN and not (
            any(c.isdigit() for c in value)
            and any(c.isalpha() for c in value)):
        # Short *and* all-alphabetic or all-numeric reads as a name or an
        # id, not a key. Long values skip this test - see _LONG_VALUE_LEN.
        retval = False
    return retval


_CODE_SHAPE_RE = re.compile(r"\(\s*\)|;|\)\s*\.|=>")
# Words that announce a value is a stand-in. Needed only under leniency: a
# scheme keyword makes `Bearer PLACEHOLDERVALUE` a credential POSITION, and
# nothing about its shape distinguishes it from `Bearer abcdefgh`, which is a
# real short token. The word does. The sibling `secrets-in-agent-sessions`
# hook carries the same list for the same reason. Issue #165.
# Deliberately short. `example` and `redacted` were tried and removed: AWS's
# own documented example secret key contains `EXAMPLE`, and a marker-wrapped
# value contains `REDACTED` by construction, so both words rejected real
# credentials. Only words that no credential fixture carries survive here.
_PLACEHOLDER_RE = re.compile(
    r"placeholder|changeme|change[-_]me|replace[-_]?me|notareal|"
    r"your[-_]?(?:token|key|secret|password)", re.I)


def _value_is_plausible(value, lenient):
    """True when `value` may be redacted as a credential.

    `lenient` is set by every pattern whose KEY already named a secret
    (`password=`, `API_TOKEN:`, `Authorization:`). For those the entropy
    heuristics in `_looks_like_literal_secret` are not just unnecessary but
    actively wrong: they rejected `"correct horse battery staple"` for
    containing spaces, `"1234567"` for being short, and
    `password=correcthorsebatterystaple` for being all letters -- three
    values whose key said plainly what they were. Issue #165.

    Two rejections survive leniency, because they are about the value not
    being a literal at all rather than about it looking insufficiently
    random:

    * a shell expansion (`$VAR`, `$(...)`, backticks) -- redacting it would
      destroy a record that holds no secret;
    * code (`response.access_token();x=1`) -- a call, not a value.
    """
    if value.startswith("$") or any(m in value for m in _EXPANSION_MARKERS):
        retval = False
    elif _CODE_SHAPE_RE.search(value):
        retval = False
    elif lenient and _PLACEHOLDER_RE.search(value):
        # Scoped to leniency on purpose. Under strict matching the entropy
        # tests already decide, and a real credential is free to contain the
        # substring `example`; only leniency needs this.
        retval = False
    elif lenient:
        # A floor even under leniency: a 2-character placeholder (`{}`, `--`)
        # is not a credential, and redacting it would change a record that
        # holds nothing. Requires some alphanumeric content and 4+ chars.
        retval = len(value) >= 4 and any(c.isalnum() for c in value)
    else:
        retval = _looks_like_literal_secret(value)
    return retval


def _has_pem_terminator(text):
    """True when an `-----END` appears *after* an `-----BEGIN`.

    Testing mere presence was not enough: a single `-----END` anywhere -
    including before every BEGIN - disarmed the guard and restored the
    full quadratic cost (8.3s on a 4MB input). Deliberately weaker than
    the pattern itself, which needs `-----END ` with a trailing space, so
    this can only over-scan and never skip a real key. Issue #92.
    """
    begin = text.find("-----BEGIN")
    retval = begin != -1 and text.find("-----END", begin) != -1
    return retval


def _looks_like_hex_blob(value):
    """True for a long all-hex string, which is a key and never a name.

    Kept separate from the length bound because the two answer different
    questions: length asks "too long to be a resource name", this asks
    "drawn from an alphabet no human names things in".
    """
    retval = (len(value) >= _MIN_HEX_LEN
              and all(c in "0123456789abcdefABCDEF" for c in value))
    return retval


def find_secrets(text):
    """Return credential spans in `text` as `(start, end, kind)` tuples.

    Sorted by position, non-overlapping (an outer match wins over one
    nested inside it). The value itself is never returned - callers get
    shape and position only, so a caller cannot accidentally surface a
    secret in a warning or a diagnostic.

    Overlaps are *clipped*, never dropped. Dropping a span that starts
    inside its predecessor but ends beyond it left the uncovered tail in
    cleartext next to a marker that made the record read as handled -
    a `--password <run-on PEM>` leaked the whole key body that way. See
    issue #90.
    """
    # Ranges already occupied by this function's own markers. Without
    # this, a second pass matches inside `[REDACTED:...]` - the
    # url-credentials group happily treats one as a password - so
    # `redact(redact(x)) != redact(x)` and "re-scan, expect zero" is not
    # a usable way to verify a scrub. Issue #89.
    # Character-level coverage rather than "contained in one marker": two
    # adjacent markers (`[REDACTED:a][REDACTED:b]`, which clipping
    # produces) form a single run with no whitespace, and a `--password`
    # capture swallows both at once. A span is ignored only when *every*
    # character of it is already inside a marker, so a real secret sitting
    # against a marker is still caught.
    covered = bytearray(len(text))
    for match in _MARKER_RE.finditer(text):
        covered[match.start():match.end()] = b"\x01" * (
            match.end() - match.start())

    def _is_marker(start, end):
        retval = start < end and all(covered[start:end])
        return retval

    spans = []
    for kind, pattern, group in _STRUCTURED_PATTERNS:
        if kind == "private-key" and not _has_pem_terminator(text):
            # The `.*?` with re.S is O(n^2) in unterminated BEGIN markers
            # (800 of them across 4MB measured at 7.7s). Without a
            # terminator *after* a BEGIN no match is possible, so skip
            # the scan entirely. Bounding the body length instead would
            # be worse: an oversized key would stop matching and leak in
            # full. Issue #92.
            continue
        for match in pattern.finditer(text):
            if not _is_marker(match.start(group), match.end(group)):
                spans.append((match.start(group), match.end(group), kind))
    for kind, pattern, group, lenient in _ASSIGNMENT_PATTERNS:
        for match in pattern.finditer(text):
            if _is_marker(match.start(group), match.end(group)):
                continue
            value = match.group(group)
            if _MARKER_RE.search(value):
                # The capture swallowed an existing marker plus context -
                # e.g. `https://u:[REDACTED:url-credentials]@h/` caught by
                # the bare flag-value pattern. Judge only what is left
                # once the markers are removed: if that residue is not
                # itself secret-shaped, the sensitive part is already
                # handled and re-redacting only destabilises the output.
                # This is what makes `redact` idempotent. Issue #89.
                if not _value_is_plausible(_MARKER_RE.sub("", value), lenient):
                    continue
            elif not _value_is_plausible(value, lenient):
                continue
            spans.append((match.start(group), match.end(group), kind))

    # Longest-first at a given start so a header-value span that contains
    # a `ghp_...` span swallows it rather than producing two records.
    spans.sort(key=lambda s: (s[0], -s[1]))
    retval = []
    reach = -1
    for start, end, kind in spans:
        if end <= reach:
            # Fully covered by an earlier span; nothing left to redact.
            continue
        # Clip to the uncovered tail rather than discarding the span.
        start = max(start, reach)
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
