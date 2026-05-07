#!/usr/bin/env python3
"""YOLT shell classifier - decomposes compound shell commands and classifies
each atomic command as read-only (safe), mutating (unsafe), or unknown.

Addresses two gaps in Claude Code's built-in allowlist matcher:

1. Interpreter / wrapper invocations (python3, bash, gh api, curl, kubectl
   exec, ...) that grant arbitrary execution when allowlisted with a
   wildcard but are benign for many specific read-only invocations.

2. Compound shell forms (for / while / if, $(...), `...`, && / || / ;,
   xargs, bash -c "...") whose *outer* token doesn't match the user's
   allowlist even when every *inner* command does.

Zero external dependencies - stdlib only.
"""

import json
import os
import re
import shlex
from fnmatch import fnmatch
from pathlib import Path


DECISION_SAFE = "safe"
DECISION_UNSAFE = "unsafe"
DECISION_UNKNOWN = "unknown"


SHELL_OPERATOR_SEPARATORS = (";", "&&", "||", "|", "&", "\n")
SUBSTITUTION_PLACEHOLDER = "__YOLT_SUB__"

STANDALONE_REDIRECT_OPS = {
    ">", ">>", "<", "<<", "<<<",
    "&>", "&>>",
    "1>", "1>>", "2>", "2>>",
    "3>", "4>", "5>", "6>", "7>", "8>", "9>",
    "3>>", "4>>", "5>>", "6>>", "7>>", "8>>", "9>>",
    "3<", "4<", "5<", "6<", "7<", "8<", "9<",
}

ATTACHED_REDIRECT_RE = re.compile(r"^\d*[<>&][<>&]*\S")
FD_DUP_RE = re.compile(r"^\d+[<>]&\d+-?$")
ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def load_shell_rules(rules_dir, user_overrides_path=None):
    """Load shell classification rules from rules_dir/shell.json plus
    optional user overrides. Overrides merge per-top-level-key, one level
    deep (same shape as yolt_analyzer.load_rules)."""
    rules = {}

    default_path = Path(rules_dir) / "shell.json"
    if default_path.exists():
        with open(default_path, "r") as f:
            rules = json.load(f)

    if user_overrides_path and Path(user_overrides_path).exists():
        with open(user_overrides_path, "r") as f:
            overrides = json.load(f)
        for key, value in overrides.items():
            if key in rules and isinstance(rules[key], dict) and isinstance(value, dict):
                rules[key].update(value)
            else:
                rules[key] = value

    return rules


BASH_PATTERN_RE = re.compile(r"^Bash\((.*)\)$")


def load_allow_patterns(settings_paths):
    """Read Claude Code settings.json files and return the list of inner
    Bash() allow patterns (the part between the parentheses).

    Accepts an iterable of file paths in precedence order; later paths add
    more patterns but never remove ones earlier paths granted. Missing
    files and malformed JSON are silently skipped - YOLT must not break a
    user's session by failing to parse their settings.

    Each entry in `permissions.allow` is a string of the form
    `Bash(<pattern>)`. The inner pattern uses shell glob semantics
    (matched with fnmatch). Non-Bash entries (e.g. `Read`, `Glob`,
    `mcp__github__get_file_contents`) are filtered out. Duplicate
    inner patterns are deduplicated, preserving first-seen order."""
    patterns = []
    seen = set()
    for path in settings_paths:
        if not path:
            continue
        p = Path(path)
        if not p.exists():
            continue
        try:
            with open(p, "r") as f:
                data = json.load(f)
        except (OSError, ValueError):
            continue
        permissions = data.get("permissions") or {}
        allow = permissions.get("allow") or []
        if not isinstance(allow, list):
            continue
        for entry in allow:
            if not isinstance(entry, str):
                continue
            m = BASH_PATTERN_RE.match(entry.strip())
            if not m:
                continue
            inner = m.group(1).strip()
            if not inner:
                continue
            if inner in seen:
                continue
            seen.add(inner)
            patterns.append(inner)
    retval = patterns
    return retval


def match_allow_patterns(command, patterns):
    """Return the matching pattern if `command` matches any allow pattern,
    else None. Matching is fnmatch on the whole command string against the
    unwrapped inner pattern - the same semantics as Claude Code's built-in
    Bash matcher applies to the outer command token."""
    if not patterns:
        retval = None
        return retval
    cmd = command.strip()
    for pat in patterns:
        if fnmatch(cmd, pat):
            retval = pat
            return retval
    retval = None
    return retval


def extract_substitutions(command):
    """Extract $(...) and `...` command substitutions, replacing each with a
    placeholder and returning the inner command strings in order.

    Handles nesting of $(...) and mixed with backticks. Respects single and
    double quotes."""
    subs = []
    result_chars = []
    i = 0
    in_single = False
    in_double = False

    def find_balanced_dollar_paren(s, start_after_paren):
        depth = 1
        j = start_after_paren
        q_single = False
        q_double = False
        while j < len(s):
            c = s[j]
            if q_single:
                if c == "'":
                    q_single = False
                j += 1
                continue
            if q_double:
                if c == '"' and (j == 0 or s[j - 1] != "\\"):
                    q_double = False
                elif c == "$" and j + 1 < len(s) and s[j + 1] == "(":
                    depth += 1
                    j += 2
                    continue
                j += 1
                continue
            if c == "'":
                q_single = True
            elif c == '"':
                q_double = True
            elif c == "$" and j + 1 < len(s) and s[j + 1] == "(":
                depth += 1
                j += 2
                continue
            elif c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    retval = j
                    return retval
            j += 1
        retval = -1
        return retval

    while i < len(command):
        c = command[i]
        if in_single:
            result_chars.append(c)
            if c == "'":
                in_single = False
            i += 1
            continue
        if in_double:
            # Inside double quotes, $(...) substitutions still apply
            if c == '"' and (i == 0 or command[i - 1] != "\\"):
                in_double = False
                result_chars.append(c)
                i += 1
                continue
            if c == "$" and i + 1 < len(command) and command[i + 1] == "(":
                end = find_balanced_dollar_paren(command, i + 2)
                if end < 0:
                    result_chars.append(c)
                    i += 1
                    continue
                inner = command[i + 2:end]
                inner_stripped, nested = extract_substitutions(inner)
                subs.extend(nested)
                subs.append(inner_stripped)
                result_chars.append(SUBSTITUTION_PLACEHOLDER)
                i = end + 1
                continue
            result_chars.append(c)
            i += 1
            continue
        if c == "'":
            in_single = True
            result_chars.append(c)
            i += 1
            continue
        if c == '"':
            in_double = True
            result_chars.append(c)
            i += 1
            continue
        if c == "$" and i + 1 < len(command) and command[i + 1] == "(":
            end = find_balanced_dollar_paren(command, i + 2)
            if end < 0:
                result_chars.append(c)
                i += 1
                continue
            inner = command[i + 2:end]
            inner_stripped, nested = extract_substitutions(inner)
            subs.extend(nested)
            subs.append(inner_stripped)
            result_chars.append(SUBSTITUTION_PLACEHOLDER)
            i = end + 1
            continue
        if c == "`":
            end = command.find("`", i + 1)
            while end > 0 and command[end - 1] == "\\":
                end = command.find("`", end + 1)
            if end < 0:
                result_chars.append(c)
                i += 1
                continue
            inner = command[i + 1:end]
            inner_stripped, nested = extract_substitutions(inner)
            subs.extend(nested)
            subs.append(inner_stripped)
            result_chars.append(SUBSTITUTION_PLACEHOLDER)
            i = end + 1
            continue
        result_chars.append(c)
        i += 1

    retval = ("".join(result_chars), subs)
    return retval


def split_top_level(command):
    """Split a shell command on top-level operators ;, &&, ||, |, &, newline.
    Respects single and double quotes. Returns list of non-empty segment
    strings."""
    segments = []
    current = []
    i = 0
    in_single = False
    in_double = False

    def flush():
        seg = "".join(current).strip()
        if seg:
            segments.append(seg)
        current.clear()

    while i < len(command):
        c = command[i]
        if in_single:
            current.append(c)
            if c == "'":
                in_single = False
            i += 1
            continue
        if in_double:
            current.append(c)
            if c == '"' and (i == 0 or command[i - 1] != "\\"):
                in_double = False
            i += 1
            continue
        if c == "'":
            in_single = True
            current.append(c)
            i += 1
            continue
        if c == '"':
            in_double = True
            current.append(c)
            i += 1
            continue
        if c == ";":
            flush()
            i += 1
            continue
        if c == "\n":
            flush()
            i += 1
            continue
        if c == "&" and i + 1 < len(command) and command[i + 1] == "&":
            flush()
            i += 2
            continue
        if c == "|" and i + 1 < len(command) and command[i + 1] == "|":
            flush()
            i += 2
            continue
        if c == "|":
            flush()
            i += 1
            continue
        if c == "&":
            flush()
            i += 1
            continue
        current.append(c)
        i += 1
    flush()
    retval = segments
    return retval


CASE_PATTERN_RE = re.compile(r".+\)$")


def strip_leading_keywords_and_assignments(tokens, keywords):
    """Drop leading shell keywords (for, while, do, ...) and VAR=value
    assignments from the token list.

    Returns (remaining_tokens, is_word_list). is_word_list is True when the
    remaining tokens are the iteration WORDs of a `for VAR in WORDS` / case
    selector and should be treated as data, not as a command.

    Handles structured keywords that carry a variable name:
      - `for VAR in LIST` / `for VAR` (implicit $@)
      - `select VAR in LIST` / `select VAR`
      - `case WORD in`
      - `PAT)` / `PAT1 | PAT2)` case-arm prefix
    """
    result = list(tokens)
    is_word_list = False
    while result:
        first = result[0]
        if first in {"for", "select"}:
            if len(result) >= 3 and result[2] == "in":
                result = result[3:]
                is_word_list = True
                break
            if len(result) >= 2:
                result = result[2:]
                break
            result = result[1:]
            continue
        if first == "case":
            if len(result) >= 3 and result[2] == "in":
                result = result[3:]
                continue
            if len(result) >= 2:
                result = result[2:]
                continue
            result = result[1:]
            continue
        if first in keywords:
            result = result[1:]
            continue
        if CASE_PATTERN_RE.match(first) and first != ")":
            # Case-arm pattern prefix, e.g. `a)`, `*)`, `"foo")`
            result = result[1:]
            continue
        if ASSIGNMENT_RE.match(first) and "=" in first:
            result = result[1:]
            continue
        break
    retval = (result, is_word_list)
    return retval


DISCARD_REDIRECT_TARGETS = {"/dev/null", "/dev/stderr", "/dev/stdout"}


def strip_redirections(tokens):
    """Drop shell redirection tokens and report whether any of them writes to
    a file target other than /dev/null.

    Returns (cleaned_tokens, writes_to_file_target).

    writes_to_file_target is True when a `>` / `>>` / `&>` / `2>`-style
    redirection targets anything other than /dev/null. Caller uses that to
    refuse auto-allow, since a classifier saying "echo is safe" becomes
    wrong when `echo x > /etc/profile` is the real command."""
    cleaned = []
    writes_to_file = False
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in STANDALONE_REDIRECT_OPS:
            is_write_op = "<" not in tok
            target = tokens[i + 1] if i + 1 < len(tokens) else None
            if is_write_op and target and target not in DISCARD_REDIRECT_TARGETS:
                writes_to_file = True
            i += 2
            continue
        if FD_DUP_RE.match(tok):
            i += 1
            continue
        if ATTACHED_REDIRECT_RE.match(tok):
            # e.g. `2>/dev/null`, `>file`, `&>log`
            m = re.match(r"^(\d*)([<>&]+)(.*)$", tok)
            if m:
                op = m.group(2)
                target = m.group(3)
                is_write_op = "<" not in op
                if is_write_op and target and target not in DISCARD_REDIRECT_TARGETS:
                    writes_to_file = True
            i += 1
            continue
        cleaned.append(tok)
        i += 1
    retval = (cleaned, writes_to_file)
    return retval


def check_unsafe_flags(cmd_args, spec):
    """Check whether cmd_args contains a flag combination the command spec
    declares unsafe. Returns a human-readable description of the match, or
    None."""
    unsafe_flag_values = spec.get("unsafe_flag_values", {})
    unsafe_flag_any_value = set(spec.get("unsafe_flag_any_value", []))
    unsafe_flags_without_value = set(spec.get("unsafe_flags_without_value", []))

    i = 0
    while i < len(cmd_args):
        tok = cmd_args[i]

        flag = tok
        inline_value = None
        if "=" in tok and tok.startswith("-"):
            flag, _, inline_value = tok.partition("=")

        if flag in unsafe_flags_without_value:
            retval = "{} (no value)".format(flag)
            return retval

        if flag in unsafe_flag_values:
            value = inline_value
            if value is None and i + 1 < len(cmd_args):
                value = cmd_args[i + 1]
            if value is not None:
                value_upper = value.upper() if isinstance(value, str) else value
                for unsafe_val in unsafe_flag_values[flag]:
                    if value_upper == unsafe_val.upper():
                        retval = "{} {}".format(flag, value)
                        return retval

        if flag in unsafe_flag_any_value:
            # Present at all (with or without value) marks unsafe.
            retval = flag
            return retval

        i += 1

    retval = None
    return retval


def aggregate_decisions(decisions):
    """Combine a list of (decision, reason) results into one. Precedence:
    unsafe > unknown > safe."""
    if not decisions:
        retval = (DECISION_SAFE, "nothing to classify")
        return retval

    unsafe_reasons = [r for d, r in decisions if d == DECISION_UNSAFE]
    unknown_reasons = [r for d, r in decisions if d == DECISION_UNKNOWN]
    safe_reasons = [r for d, r in decisions if d == DECISION_SAFE]

    if unsafe_reasons:
        retval = (DECISION_UNSAFE, "; ".join(unsafe_reasons))
        return retval
    if unknown_reasons:
        retval = (DECISION_UNKNOWN, "; ".join(unknown_reasons))
        return retval
    retval = (DECISION_SAFE, "; ".join(safe_reasons) if safe_reasons else "no commands")
    return retval


def parse_aws_positionals(cmd_args):
    """Walk aws CLI args skipping flags (--profile prod, --region us-east-1,
    --no-cli-pager, etc.). Return (service, operation, trailing_positionals).
    Either may be None."""
    service = None
    operation = None
    trailing = []

    i = 0
    while i < len(cmd_args):
        tok = cmd_args[i]
        if tok.startswith("--"):
            if "=" in tok:
                i += 1
                continue
            # Known valueless long flags for aws CLI
            if tok in {"--no-cli-pager", "--no-paginate", "--no-verify-ssl",
                      "--no-sign-request", "--debug"}:
                i += 1
                continue
            # Default: assume value follows (covers --profile, --region, etc.)
            if i + 1 < len(cmd_args) and not cmd_args[i + 1].startswith("-"):
                i += 2
                continue
            i += 1
            continue
        if tok.startswith("-") and len(tok) > 1:
            # Short flags - aws only has a few, most long-form
            i += 1
            continue
        if service is None:
            service = tok
            i += 1
            continue
        if operation is None:
            operation = tok
            i += 1
            continue
        trailing.append(tok)
        i += 1

    retval = (service, operation, trailing)
    return retval


class ShellClassifier:
    MAX_RECURSION_DEPTH = 8

    def __init__(self, rules, python_analyzer_factory=None, allow_patterns=None):
        self.rules = rules
        self.commands = rules.get("commands", {})
        self.shell_builtins_safe = set(rules.get("shell_builtins_safe", []))
        self.shell_keywords = set(rules.get("shell_keywords", []))
        self.interpreters = rules.get("interpreters", {})
        self.python_analyzer_factory = python_analyzer_factory
        self.allow_patterns = list(allow_patterns) if allow_patterns else []

    def classify(self, command, _depth=0):
        """Classify a shell command string. Returns (decision, reason).
        decision in {"safe", "unsafe", "unknown"}."""
        if _depth > self.MAX_RECURSION_DEPTH:
            retval = (DECISION_UNKNOWN, "max recursion depth")
            return retval

        if not command or not command.strip():
            retval = (DECISION_SAFE, "empty")
            return retval

        stripped, subs = extract_substitutions(command)

        decisions = []
        for sub in subs:
            d, r = self.classify(sub, _depth=_depth + 1)
            decisions.append((d, "$(...) -> {}".format(r)))

        segments = split_top_level(stripped)
        for seg in segments:
            d, r = self.classify_segment(seg, _depth=_depth + 1)
            decisions.append((d, r))

        retval = aggregate_decisions(decisions)
        return retval

    def classify_segment(self, segment, _depth=0):
        """Classify one segment (no ;, &&, ||, |, & at its top level).

        After the rule-based classifier runs, an `unknown` outcome is
        upgraded to `safe` if the segment matches a user allow pattern
        from settings.json (`permissions.allow` Bash entries). `unsafe`
        is never weakened - YOLT keeps flagging mutating calls even when
        the user's allowlist would otherwise permit them.

        The allowlist match runs against the segment after leading shell
        keywords (`do`, `then`, `else`, ...) have been stripped, so that
        `for x in $(...); do mycli list "$x"; done` matches a user
        pattern of `Bash(mycli list*)`. Redirection tokens are kept in
        the match string so `Bash(echo *)` covers `echo x > /tmp/file`.
        """
        if _depth > self.MAX_RECURSION_DEPTH:
            retval = (DECISION_UNKNOWN, "max recursion depth")
            return retval

        try:
            tokens = shlex.split(segment, posix=True)
        except ValueError as e:
            retval = self._maybe_allow(segment, (DECISION_UNKNOWN, "shlex: {}".format(e)))
            return retval

        tokens, is_word_list = strip_leading_keywords_and_assignments(
            tokens, self.shell_keywords
        )
        # Snapshot the post-keyword tokens for allowlist matching - it
        # still contains redirection ops so e.g. `Bash(echo *)` matches
        # `echo x > /tmp/file` the way Claude Code's outer matcher would.
        match_string = " ".join(tokens) if tokens else segment

        tokens, writes_to_file = strip_redirections(tokens)

        if writes_to_file:
            retval = self._maybe_allow(
                match_string, (DECISION_UNKNOWN, "writes to a file via redirection")
            )
            return retval

        if not tokens:
            retval = (DECISION_SAFE, "keywords/assignments/redirections only")
            return retval

        if is_word_list:
            retval = (DECISION_SAFE, "word list (for/select iteration values)")
            return retval

        # Drop the placeholder from extract_substitutions if it appears alone
        if len(tokens) == 1 and tokens[0] == SUBSTITUTION_PLACEHOLDER:
            retval = (DECISION_SAFE, "bare substitution result")
            return retval

        result = self.classify_tokens(tokens, _depth=_depth)
        retval = self._maybe_allow(match_string, result)
        return retval

    def _maybe_allow(self, match_string, result):
        """If `result` is unknown and `match_string` matches a user allow
        pattern, upgrade to safe with an explanatory reason. Otherwise
        return `result` unchanged."""
        decision, reason = result
        if decision != DECISION_UNKNOWN:
            retval = result
            return retval
        match = match_allow_patterns(match_string, self.allow_patterns)
        if match is None:
            retval = result
            return retval
        retval = (DECISION_SAFE, "matches user allow pattern '{}'".format(match))
        return retval

    def classify_tokens(self, tokens, _depth=0):
        """Classify a simple command given its argv tokens."""
        if not tokens:
            retval = (DECISION_SAFE, "empty")
            return retval

        if all(t == SUBSTITUTION_PLACEHOLDER for t in tokens):
            retval = (DECISION_SAFE, "only substitution result (classified separately)")
            return retval

        cmd_name = os.path.basename(tokens[0])
        cmd_args = tokens[1:]

        if cmd_name in self.shell_builtins_safe:
            retval = (DECISION_SAFE, "builtin: {}".format(cmd_name))
            return retval

        if cmd_name in self.interpreters:
            retval = self.classify_interpreter(cmd_name, cmd_args, _depth=_depth)
            return retval

        if cmd_name in self.commands:
            retval = self.classify_known_command(cmd_name, cmd_args, _depth=_depth)
            return retval

        retval = (DECISION_UNKNOWN, "no rule: {}".format(cmd_name))
        return retval

    def classify_interpreter(self, name, cmd_args, _depth):
        spec = self.interpreters[name]
        inline_flag = spec.get("inline_flag")
        delegate = spec.get("delegate", "unknown")
        read_script_file = spec.get("read_script_file", False)

        inline_code = None
        if inline_flag and inline_flag in cmd_args:
            idx = cmd_args.index(inline_flag)
            if idx + 1 < len(cmd_args):
                inline_code = cmd_args[idx + 1]

        if inline_code is not None:
            if delegate == "python":
                retval = self.classify_python_source(
                    inline_code, "{} {} ...".format(name, inline_flag)
                )
                return retval
            if delegate == "bash":
                d, r = self.classify(inline_code, _depth=_depth + 1)
                retval = (d, "{} -c -> {}".format(name, r))
                return retval
            retval = (DECISION_UNKNOWN, "cannot analyze inline {}".format(delegate))
            return retval

        if read_script_file and delegate == "python":
            script_path = None
            for arg in cmd_args:
                if arg.startswith("-"):
                    continue
                if arg.endswith(".py") or os.path.isfile(arg):
                    script_path = arg
                    break
            if script_path and os.path.isfile(script_path):
                try:
                    with open(script_path, "r") as f:
                        code = f.read()
                except (OSError, UnicodeDecodeError) as e:
                    retval = (DECISION_UNKNOWN, "cannot read {}: {}".format(script_path, e))
                    return retval
                retval = self.classify_python_source(
                    code, "{} {}".format(name, script_path)
                )
                return retval

        retval = (DECISION_UNKNOWN, "{} invocation not analyzable".format(name))
        return retval

    def classify_python_source(self, source, description):
        if self.python_analyzer_factory is None:
            retval = (DECISION_UNKNOWN, "python analyzer unavailable")
            return retval
        analyzer = self.python_analyzer_factory()
        result = analyzer.analyze(source)
        if result.get("safe"):
            retval = (DECISION_SAFE, "python: {}".format(description))
            return retval
        retval = (DECISION_UNSAFE, "python {}: {}".format(
            description, result.get("reason", "destructive call")
        ))
        return retval

    def classify_known_command(self, cmd_name, cmd_args, _depth):
        spec = self.commands[cmd_name]
        default = spec.get("default", "unknown")

        unsafe_match = check_unsafe_flags(cmd_args, spec)
        if unsafe_match:
            retval = (DECISION_UNSAFE, "{}: flag {}".format(cmd_name, unsafe_match))
            return retval

        if default == "safe":
            retval = (DECISION_SAFE, "{}: read-only".format(cmd_name))
            return retval
        if default == "unsafe":
            retval = (DECISION_UNSAFE, "{}: mutating".format(cmd_name))
            return retval
        if default == "ask":
            retval = (DECISION_UNKNOWN, "{}: rules punt".format(cmd_name))
            return retval
        if default == "subcommand":
            retval = self.classify_subcommand(cmd_name, cmd_args, spec, _depth=_depth)
            return retval
        if default == "delegate_to_argument":
            retval = self.classify_delegate_to_argument(cmd_name, cmd_args, spec, _depth=_depth)
            return retval
        if default == "aws_cli":
            retval = self.classify_aws(cmd_args, spec)
            return retval
        if default == "gcloud_cli":
            retval = self.classify_verb_cli(cmd_args, spec, label="gcloud")
            return retval
        if default == "az_cli":
            retval = self.classify_verb_cli(cmd_args, spec, label="az")
            return retval

        retval = (DECISION_UNKNOWN, "{}: unknown default '{}'".format(cmd_name, default))
        return retval

    def classify_subcommand(self, cmd_name, cmd_args, spec, _depth):
        positional = self._skip_flags(cmd_args)
        if not positional:
            retval = (DECISION_UNKNOWN, "{}: no subcommand".format(cmd_name))
            return retval

        sub = positional[0]
        rest = positional[1:]
        remaining_args = cmd_args[cmd_args.index(sub) + 1:] if sub in cmd_args else rest

        nested = spec.get("nested_subcommand", {})
        if sub in nested:
            nested_spec = nested[sub]
            nested_unsafe = check_unsafe_flags(remaining_args, nested_spec)
            if nested_unsafe:
                retval = (DECISION_UNSAFE, "{} {}: flag {}".format(cmd_name, sub, nested_unsafe))
                return retval

            if "default" in nested_spec:
                nested_default = nested_spec["default"]
                if nested_default == "safe":
                    retval = (DECISION_SAFE, "{} {}: read-only".format(cmd_name, sub))
                    return retval
                if nested_default == "unsafe":
                    retval = (DECISION_UNSAFE, "{} {}: mutating".format(cmd_name, sub))
                    return retval

            retval = self._match_subcommand_lists(
                "{} {}".format(cmd_name, sub), rest, nested_spec
            )
            return retval

        retval = self._match_subcommand_lists(cmd_name, positional, spec)
        return retval

    def _match_subcommand_lists(self, label, positional, spec):
        safe_subs = set(spec.get("safe_subcommands", []))
        unsafe_subs = set(spec.get("unsafe_subcommands", []))
        safe_patterns = spec.get("safe_subcommand_patterns", [])
        unsafe_patterns = spec.get("unsafe_subcommand_patterns", [])

        if not positional:
            retval = (DECISION_UNKNOWN, "{}: no subcommand".format(label))
            return retval

        sub = positional[0]

        if sub in safe_subs:
            retval = (DECISION_SAFE, "{} {}: read-only".format(label, sub))
            return retval
        if sub in unsafe_subs:
            retval = (DECISION_UNSAFE, "{} {}: mutating".format(label, sub))
            return retval
        for pat in safe_patterns:
            if fnmatch(sub, pat):
                retval = (DECISION_SAFE, "{} {}: matches safe pattern {}".format(label, sub, pat))
                return retval
        for pat in unsafe_patterns:
            if fnmatch(sub, pat):
                retval = (DECISION_UNSAFE, "{} {}: matches unsafe pattern {}".format(label, sub, pat))
                return retval

        retval = (DECISION_UNKNOWN, "{} {}: no rule".format(label, sub))
        return retval

    def classify_delegate_to_argument(self, cmd_name, cmd_args, spec, _depth):
        skip_first_positional = spec.get("_skip_first_positional", False)

        i = 0
        while i < len(cmd_args):
            tok = cmd_args[i]
            if tok.startswith("--"):
                if "=" in tok:
                    i += 1
                    continue
                if i + 1 < len(cmd_args) and not cmd_args[i + 1].startswith("-"):
                    i += 2
                    continue
                i += 1
                continue
            if tok.startswith("-") and len(tok) > 1:
                if len(tok) > 2 and not tok[2].isalpha():
                    # Inline value like -n5 or -I{}
                    i += 1
                    continue
                if i + 1 < len(cmd_args) and not cmd_args[i + 1].startswith("-"):
                    i += 2
                    continue
                i += 1
                continue
            if cmd_name == "env" and ASSIGNMENT_RE.match(tok) and "=" in tok:
                i += 1
                continue
            if skip_first_positional:
                skip_first_positional = False
                i += 1
                continue
            break

        if i >= len(cmd_args):
            retval = (DECISION_UNKNOWN, "{}: no wrapped command".format(cmd_name))
            return retval

        wrapped_tokens = cmd_args[i:]
        d, r = self.classify_tokens(wrapped_tokens, _depth=_depth + 1)
        retval = (d, "{} wraps: {}".format(cmd_name, r))
        return retval

    def classify_aws(self, cmd_args, spec):
        service, operation, trailing = parse_aws_positionals(cmd_args)
        if service is None:
            retval = (DECISION_UNKNOWN, "aws: no service")
            return retval
        if operation is None:
            retval = (DECISION_UNKNOWN, "aws {}: no operation".format(service))
            return retval

        service_overrides = spec.get("service_overrides", {})
        per_service = service_overrides.get(service, {})

        safe_subs = set(per_service.get("safe_subcommands", []))
        unsafe_subs = set(per_service.get("unsafe_subcommands", []))
        if operation in safe_subs:
            retval = (DECISION_SAFE, "aws {} {}: read-only".format(service, operation))
            return retval
        if operation in unsafe_subs:
            retval = (DECISION_UNSAFE, "aws {} {}: mutating".format(service, operation))
            return retval

        extra_safe = per_service.get("extra_safe_patterns", [])
        for pat in extra_safe:
            if fnmatch(operation, pat):
                retval = (DECISION_SAFE, "aws {} {}: service override safe".format(service, operation))
                return retval

        svc_safe_patterns = per_service.get("safe_operation_patterns", [])
        svc_unsafe_patterns = per_service.get("unsafe_operation_patterns", [])
        for pat in svc_safe_patterns:
            if fnmatch(operation, pat):
                retval = (DECISION_SAFE, "aws {} {}: service-safe pattern".format(service, operation))
                return retval
        for pat in svc_unsafe_patterns:
            if fnmatch(operation, pat):
                retval = (DECISION_UNSAFE, "aws {} {}: service-unsafe pattern".format(service, operation))
                return retval

        for pat in spec.get("safe_operation_patterns", []):
            if fnmatch(operation, pat):
                retval = (DECISION_SAFE, "aws {} {}: global read-only".format(service, operation))
                return retval
        for pat in spec.get("unsafe_operation_patterns", []):
            if fnmatch(operation, pat):
                retval = (DECISION_UNSAFE, "aws {} {}: global mutating".format(service, operation))
                return retval

        retval = (DECISION_UNKNOWN, "aws {} {}: unclassified".format(service, operation))
        return retval

    def classify_verb_cli(self, cmd_args, spec, label):
        """For gcloud / az CLIs - they typically use 'verb' subcommands like
        `list`, `describe`, `create`, `delete`. Without detailed rules we
        keep this permissive on known read verbs and unsafe on known write
        verbs; otherwise unknown."""
        positional = self._skip_flags(cmd_args)
        if len(positional) < 2:
            retval = (DECISION_UNKNOWN, "{}: too few positionals".format(label))
            return retval

        verb = positional[-1]
        safe_verbs = {"list", "describe", "get", "show", "export", "version", "help"}
        unsafe_verbs = {
            "create", "delete", "update", "replace", "set", "add", "remove",
            "deploy", "run", "execute", "exec", "ssh",
            "enable", "disable", "reset", "rollback", "promote", "restart",
            "scale", "resize",
        }
        if verb in safe_verbs:
            retval = (DECISION_SAFE, "{} {}: read verb".format(label, verb))
            return retval
        if verb in unsafe_verbs:
            retval = (DECISION_UNSAFE, "{} {}: write verb".format(label, verb))
            return retval
        retval = (DECISION_UNKNOWN, "{} {}: unknown verb".format(label, verb))
        return retval

    @staticmethod
    def _skip_flags(cmd_args):
        """Return only positional (non-flag) tokens from cmd_args, skipping
        flag-values heuristically."""
        positional = []
        i = 0
        while i < len(cmd_args):
            tok = cmd_args[i]
            if tok.startswith("--"):
                if "=" in tok:
                    i += 1
                    continue
                if i + 1 < len(cmd_args) and not cmd_args[i + 1].startswith("-"):
                    i += 2
                    continue
                i += 1
                continue
            if tok.startswith("-") and len(tok) > 1:
                if len(tok) > 2 and not tok[2].isalpha():
                    i += 1
                    continue
                if i + 1 < len(cmd_args) and not cmd_args[i + 1].startswith("-"):
                    i += 2
                    continue
                i += 1
                continue
            positional.append(tok)
            i += 1
        retval = positional
        return retval


def classify_command(command, rules, python_analyzer_factory=None, allow_patterns=None):
    """Module-level convenience wrapper."""
    classifier = ShellClassifier(
        rules,
        python_analyzer_factory=python_analyzer_factory,
        allow_patterns=allow_patterns,
    )
    retval = classifier.classify(command)
    return retval


def run_cli():
    """CLI: read a shell command from argv and print its classification."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: shell_classifier.py '<shell command>'", file=sys.stderr)
        sys.exit(1)

    command = sys.argv[1]
    yolt_dir = Path(__file__).resolve().parent.parent
    rules = load_shell_rules(
        rules_dir=yolt_dir / "rules",
        user_overrides_path=Path.home() / ".claude" / "yolt" / "shell.json",
    )

    cwd = Path.cwd()
    allow_patterns = load_allow_patterns([
        Path.home() / ".claude" / "settings.json",
        cwd / ".claude" / "settings.json",
        cwd / ".claude" / "settings.local.json",
    ])

    # Lazy-import the python analyzer for --c / script delegation
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from yolt_analyzer import SafetyAnalyzer, load_rules as load_py_rules
        py_rules = load_py_rules(
            rules_dir=yolt_dir / "rules",
            user_overrides_path=Path.home() / ".claude" / "yolt" / "rules.json",
        )

        def _factory():
            retval = SafetyAnalyzer(py_rules)
            return retval
        factory = _factory
    except ImportError:
        factory = None

    decision, reason = classify_command(
        command, rules,
        python_analyzer_factory=factory,
        allow_patterns=allow_patterns,
    )
    output = {"decision": decision, "reason": reason}
    print(json.dumps(output, indent=2))
    sys.exit(0 if decision == DECISION_SAFE else 1)


if __name__ == "__main__":
    run_cli()
