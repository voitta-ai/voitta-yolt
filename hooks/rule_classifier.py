#!/usr/bin/env python3
"""YOLT argv-level rule classifier.

Given a list of argv tokens for a single simple command, classify the call
as safe / unsafe / unknown by consulting `rules/shell.json`. This module is
language-agnostic w.r.t. Bash quoting and decomposition; it expects the
caller (the grammar-driven walker in `grammar_classifier.py`) to have
already produced argv from the AST.

The rule schema lives in `rules/shell.json`. Major shapes:

  - `commands`: dict of cmd_name -> spec. Spec defaults: "safe", "unsafe",
    "ask", "subcommand", "delegate_to_argument", "aws_cli", "gcloud_cli",
    "az_cli". Subcommand specs carry safe / unsafe lists and patterns.
  - `interpreters`: dict of cmd_name -> spec for `python3 -c`, `bash -c`,
    `python3 file.py`. Inline-flag scripts get delegated to a Python AST
    analyzer; bash inline scripts re-enter via the grammar walker (the
    grammar walker passes itself in as the bash analyzer).
  - `shell_builtins_safe`: list of always-safe builtins.

Settings I/O (`load_shell_rules`, `load_allow_patterns`, `match_allow_patterns`)
also lives here for symmetry.
"""

import json
import os
import re
from fnmatch import fnmatch
from pathlib import Path


DECISION_SAFE = "safe"
DECISION_UNSAFE = "unsafe"
DECISION_UNKNOWN = "unknown"

SUBSTITUTION_PLACEHOLDER = "__YOLT_SUB__"

# Reason marker for an inline `python3 -c` script the static analyzer could
# not parse. A parse bail is not evidence of a destructive call, so
# format_unsafe_reason() (yolt_analyzer) keys on this prefix to render a
# dedicated message instead of the standard "mutating command" envelope.
# Only the `-c` path uses it; `python3 file.py` parse errors keep the
# SyntaxError reason because there the broken file is the real problem.
# See issue #37.
UNANALYZABLE_INLINE_PYTHON_PREFIX = (
    "could not statically analyze inline python3 -c script"
)

ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
BASH_PATTERN_RE = re.compile(r"^Bash\((.*)\)$")


# --- SQL safety detection (used by sql_cli default) ---
#
# Conservative scan: strip string literals and comments, then look for
# mutating keywords anywhere. If none, classify by the first remaining
# keyword. This treats `EXPLAIN DELETE FROM t` as unsafe (the DELETE
# keyword is still present even though it would not execute); we accept
# that false-positive to keep the rule simple.
#
# Keyword-only scanning misses side-effecting *functions* called from
# inside an otherwise read-looking statement (`SELECT pg_terminate_backend(...)`,
# `SELECT LOAD_FILE('/etc/passwd')`, `SELECT load_extension('evil.so')`).
# After the keyword pass we therefore scan `IDENT(` function calls against
# per-dialect deny lists, plus MySQL `INTO OUTFILE/DUMPFILE` file-write
# tokens. Dialect is taken from the CLI name (psql->postgres, mysql/mariadb
# ->mysql, sqlite3->sqlite, duckdb->duckdb). See issue #26.

SQL_MUTATING_KEYWORDS = frozenset({
    "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER",
    "TRUNCATE", "REPLACE", "MERGE", "GRANT", "REVOKE",
    "VACUUM", "REINDEX", "ATTACH", "DETACH",
    "COMMIT", "ROLLBACK", "BEGIN", "SAVEPOINT", "RELEASE",
    "CALL", "EXEC", "EXECUTE", "DO",
    "COPY", "LOAD", "IMPORT",
    "LOCK", "UNLOCK",
    "SET", "RESET",
})

SQL_SAFE_FIRST_KEYWORDS = frozenset({
    "SELECT", "WITH", "EXPLAIN", "SHOW", "DESCRIBE", "DESC",
    "VALUES", "TABLE",
})

# Strip comments and string/identifier literals before keyword scanning.
# Order in the regex matters — line comments are matched before block
# comments to keep nested `/*` inside `-- ...` from leaking through.
_SQL_STRIP_RE = re.compile(
    r"""
    --[^\n]*               # -- line comment
    | /\*.*?\*/            # /* block comment */
    | '(?:[^']|'')*'       # 'single' quoted string ('' is escape)
    | \"(?:[^\"]|\"\")*\"  # "double" quoted ident/string
    | `[^`]*`              # `backtick` ident (MySQL)
    | \$(\w*)\$.*?\$\1\$   # $$...$$ / $tag$...$tag$ dollar-quoted string (Postgres)
    """,
    re.DOTALL | re.VERBOSE,
)

_SQL_WORD_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b")

# sqlite3 has a separate "dot-command" namespace (.tables, .schema, ...)
# that runs inside the CLI but isn't SQL. Most read state; a few load
# or write files.
SQLITE_DOT_SAFE = frozenset({
    ".tables", ".schema", ".databases", ".indexes", ".indices",
    ".show", ".help", ".headers", ".mode", ".width", ".print",
    ".timer", ".eqp", ".changes", ".dbinfo", ".dbconfig",
    ".fullschema", ".scanstats", ".limit", ".nullvalue",
    ".separator", ".prompt", ".excel", ".version", ".lint",
    ".stats", ".explain", ".binary", ".filectrl",
})
SQLITE_DOT_UNSAFE = frozenset({
    ".import", ".load", ".save", ".backup", ".restore",
    ".system", ".shell", ".read", ".cd", ".open", ".dump",
    ".archive", ".clone", ".log", ".recover",
})

# SQL dialect per CLI name. mysql and mariadb share a dialect.
SQL_DIALECT_BY_CLI = {
    "psql": "postgres",
    "mysql": "mysql",
    "mariadb": "mysql",
    "sqlite3": "sqlite",
    "duckdb": "duckdb",
}

# Side-effecting functions that can be called from inside a SELECT and so
# slip past the keyword + safe-first-keyword check. Names are lowercase for
# case-insensitive matching. See issue #26 for the source enumeration.
SQL_SIDE_EFFECT_FUNCTIONS = {
    "postgres": frozenset({
        "pg_terminate_backend", "pg_cancel_backend", "pg_promote",
        "pg_reload_conf", "pg_rotate_logfile",
        "nextval", "setval",
        "lo_unlink", "lo_export", "lo_import",
        "pg_read_file", "pg_read_binary_file", "pg_ls_dir",
        "dblink_exec", "pg_logical_emit_message",
        "pg_advisory_lock", "pg_advisory_xact_lock",
        "pg_sleep", "pg_sleep_for", "pg_sleep_until",
        "set_config",
    }),
    "mysql": frozenset({
        "load_file", "get_lock", "sleep", "benchmark",
    }),
    "sqlite": frozenset({
        "load_extension", "randomblob",
    }),
    "duckdb": frozenset(),
}

# MySQL `SELECT ... INTO OUTFILE/DUMPFILE '...'` writes a file with no
# function call and no mutating keyword. Require the `INTO` context so a
# plain read of a column/table named `outfile`/`dumpfile` is not flagged.
_MYSQL_INTO_OUTFILE_RE = re.compile(r"\bINTO\s+(?:OUTFILE|DUMPFILE)\b")

# Postgres `pg_*` system functions are a mostly-side-effecting set, so any
# pg_-prefixed call is denied unless it is a known read-only one (exact name
# or a read-only prefix such as `pg_get_*`). See issue #26.
PG_READONLY_FUNCTIONS = frozenset({
    "pg_database_size", "pg_relation_size", "pg_total_relation_size",
    "pg_typeof", "pg_size_pretty",
})
PG_READONLY_PREFIXES = ("pg_get_",)

# Function-call identifier immediately followed by `(` (optional whitespace).
_SQL_FUNC_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def _classify_sql_functions(cmd_name, dialect, stripped):
    """Scan stripped+uppercased SQL for side-effecting function calls.
    Returns a (decision, reason) tuple when a denied function is found,
    else None. `stripped` has had comments/literals removed already."""
    if dialect is None:
        return None
    deny = SQL_SIDE_EFFECT_FUNCTIONS.get(dialect, frozenset())
    for m in _SQL_FUNC_RE.finditer(stripped):
        ident = m.group(1).lower()
        if ident in deny:
            retval = (DECISION_UNSAFE,
                      "{}: side-effecting function {}()".format(cmd_name, ident))
            return retval
        if dialect == "postgres" and ident.startswith("pg_"):
            if ident in PG_READONLY_FUNCTIONS:
                continue
            if any(ident.startswith(p) for p in PG_READONLY_PREFIXES):
                continue
            retval = (DECISION_UNSAFE,
                      "{}: postgres system function {}() not read-only "
                      "allowlisted".format(cmd_name, ident))
            return retval
    return None


def classify_sql_text(cmd_name, sql, dialect=None):
    """Return (decision, reason) for a single SQL string passed to a
    SQL CLI. Handles sqlite3 dot-commands too — they're not SQL but they
    arrive through the same channel (positional / -cmd / -e).

    `dialect` overrides the CLI→dialect lookup. SQL CLIs leave it None and
    the dialect is derived from `cmd_name`; payload scanning of cloud-API
    flags (see `classify_aws`) passes it explicitly because the synthetic
    `cmd_name` (e.g. "aws athena start-query-execution") is not a known
    SQL CLI."""
    sql = sql.strip()
    if not sql:
        retval = (DECISION_SAFE, "{}: empty SQL".format(cmd_name))
        return retval

    if cmd_name == "sqlite3" and sql.startswith("."):
        first_line = sql.split("\n", 1)[0].strip()
        dot_tokens = first_line.split()
        dot = dot_tokens[0] if dot_tokens else ""
        if dot in SQLITE_DOT_SAFE:
            retval = (DECISION_SAFE,
                      "sqlite3 dot-cmd {}: read-only".format(dot))
            return retval
        if dot in SQLITE_DOT_UNSAFE:
            retval = (DECISION_UNSAFE,
                      "sqlite3 dot-cmd {}: mutating".format(dot))
            return retval
        retval = (DECISION_UNKNOWN,
                  "sqlite3 dot-cmd {}: no rule".format(dot))
        return retval

    stripped = _SQL_STRIP_RE.sub(" ", sql).upper()
    if dialect is None:
        dialect = SQL_DIALECT_BY_CLI.get(cmd_name)

    first_word = None
    for m in _SQL_WORD_RE.finditer(stripped):
        word = m.group(1)
        if first_word is None:
            first_word = word
        if word in SQL_MUTATING_KEYWORDS:
            retval = (DECISION_UNSAFE,
                      "{}: SQL contains mutating keyword {}".format(cmd_name, word))
            return retval

    if dialect == "mysql" and _MYSQL_INTO_OUTFILE_RE.search(stripped):
        retval = (DECISION_UNSAFE,
                  "{}: SQL writes file via INTO OUTFILE/DUMPFILE".format(cmd_name))
        return retval

    func_decision = _classify_sql_functions(cmd_name, dialect, stripped)
    if func_decision is not None:
        return func_decision

    if first_word == "PRAGMA":
        if "=" in stripped:
            retval = (DECISION_UNSAFE,
                      "{}: PRAGMA assignment".format(cmd_name))
            return retval
        retval = (DECISION_SAFE, "{}: PRAGMA read".format(cmd_name))
        return retval

    if first_word in SQL_SAFE_FIRST_KEYWORDS:
        retval = (DECISION_SAFE,
                  "{}: read-only SQL ({})".format(cmd_name, first_word))
        return retval

    if first_word is None:
        retval = (DECISION_SAFE, "{}: no SQL keywords".format(cmd_name))
        return retval

    retval = (DECISION_UNKNOWN,
              "{}: unclassified SQL ({})".format(cmd_name, first_word))
    return retval


def parse_sql_cli_argv(cmd_args, spec):
    """Walk argv for a SQL CLI, returning (sql_strings, sql_from_file).
    `spec` carries: sql_flags (list), valueless_flags (list),
    sql_file_flags (list), sql_positional_index (int or None)."""
    sql_flags = set(spec.get("sql_flags", []))
    sql_file_flags = set(spec.get("sql_file_flags", []))
    valueless = set(spec.get("valueless_flags", []))
    sql_positional_index = spec.get("sql_positional_index")

    sqls = []
    positionals = []
    file_input = False

    i = 0
    while i < len(cmd_args):
        tok = cmd_args[i]

        if tok.startswith("--") and "=" in tok:
            flag, _, value = tok.partition("=")
            if flag in sql_flags:
                sqls.append(value)
            elif flag in sql_file_flags:
                file_input = True
            i += 1
            continue

        if tok in sql_flags:
            if i + 1 < len(cmd_args):
                sqls.append(cmd_args[i + 1])
                i += 2
                continue
            i += 1
            continue

        if tok in sql_file_flags:
            file_input = True
            if i + 1 < len(cmd_args) and not cmd_args[i + 1].startswith("-"):
                i += 2
                continue
            i += 1
            continue

        if tok in valueless:
            i += 1
            continue

        if tok.startswith("-") and len(tok) > 1:
            if i + 1 < len(cmd_args) and not cmd_args[i + 1].startswith("-"):
                i += 2
                continue
            i += 1
            continue

        positionals.append(tok)
        i += 1

    if (
        sql_positional_index is not None
        and sql_positional_index < len(positionals)
    ):
        sqls.append(positionals[sql_positional_index])

    retval = (sqls, file_input)
    return retval


def load_shell_rules(rules_dir, user_overrides_path=None, validate=True):
    """Load shell rules from rules_dir/shell.json plus optional overrides.
    Overrides merge per top-level key, one level deep.

    By default the merged result is schema-checked via `validate_shell_rules`
    and a `ShellRulesValidationError` is raised on drift, so malformed rule
    data (including user overrides under `~/.claude/yolt/shell.json`) fails
    at load time rather than degrading silently to `unknown` at classify
    time. Pass `validate=False` to skip — useful for tests that construct
    intentionally-malformed rule fixtures."""
    rules = {}

    default_path = Path(rules_dir) / "shell.json"
    if default_path.exists():
        with open(default_path, "r") as f:
            rules = json.load(f)

    if user_overrides_path and Path(user_overrides_path).exists():
        with open(user_overrides_path, "r") as f:
            overrides = json.load(f)
        merge_shell_overrides(rules, overrides)

    if validate:
        errors = validate_shell_rules(rules)
        if errors:
            raise ShellRulesValidationError(default_path, user_overrides_path, errors)

    return rules


def merge_shell_overrides(rules, overrides):
    """Merge a user-override dict into loaded shell rules, one level deep per
    top-level key — the exact semantics `load_shell_rules` applies to
    `~/.claude/yolt/shell.json`. A dict value is shallow-`update`d into the
    existing top-level dict (so a `commands` override adds or replaces
    individual command specs); any other value replaces wholesale (so an
    override of `safe_write_targets` replaces the whole list rather than
    extending it). Mutates and returns `rules`.

    Extracted so the reviewer (`yolt_review.py`) can validate a candidate
    override against the same merge the hook performs, with no second copy
    of the merge rule to drift from this one (issue #45)."""
    for key, value in overrides.items():
        if key in rules and isinstance(rules[key], dict) and isinstance(value, dict):
            rules[key].update(value)
        else:
            rules[key] = value
    return rules


class ShellRulesValidationError(ValueError):
    """Raised when shell rule data references keys or defaults the
    classifier does not implement. Carries the source paths and the full
    list of error strings so callers can log them verbatim."""

    def __init__(self, default_path, user_overrides_path, errors):
        self.default_path = default_path
        self.user_overrides_path = user_overrides_path
        self.errors = list(errors)
        message = "shell rules failed validation ({} error(s)): {}".format(
            len(self.errors), "; ".join(self.errors),
        )
        super().__init__(message)


def load_allow_patterns(settings_paths):
    """Read Claude Code settings.json files and return the list of inner
    Bash() allow patterns (the part between the parentheses)."""
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
            if not inner or inner in seen:
                continue
            seen.add(inner)
            patterns.append(inner)
    return patterns


def match_allow_patterns(command, patterns):
    """Return the matching pattern if `command` matches any allow pattern,
    else None. Matching is fnmatch against the unwrapped inner pattern."""
    if not patterns:
        return None
    cmd = command.strip()
    for pat in patterns:
        if fnmatch(cmd, pat):
            return pat
    return None


def aggregate_decisions(decisions):
    """Combine (decision, reason) results. Precedence: unsafe > unknown > safe."""
    if not decisions:
        return (DECISION_SAFE, "nothing to classify")

    unsafe_reasons = [r for d, r in decisions if d == DECISION_UNSAFE]
    unknown_reasons = [r for d, r in decisions if d == DECISION_UNKNOWN]
    safe_reasons = [r for d, r in decisions if d == DECISION_SAFE]

    if unsafe_reasons:
        return (DECISION_UNSAFE, "; ".join(unsafe_reasons))
    if unknown_reasons:
        return (DECISION_UNKNOWN, "; ".join(unknown_reasons))
    return (DECISION_SAFE, "; ".join(safe_reasons) if safe_reasons else "no commands")


def _expand_home(path):
    home = os.environ.get("HOME")
    if home and path.startswith("~/"):
        return home + path[1:]
    return path


def _path_matches_target_list(target, patterns):
    """Return True if `target` matches any glob in `patterns` under fnmatch
    semantics, comparing both the raw token and its `~/`-expanded form.
    Shared by the safe-write and unsafe-write target checks so redirect
    writes and command write-args match identically."""
    if not patterns:
        return False
    expanded = _expand_home(target)
    for pat in patterns:
        pat_expanded = _expand_home(pat)
        if fnmatch(target, pat) or fnmatch(expanded, pat_expanded):
            return True
    return False


def _path_matches_safe_write_targets(target, safe_write_targets):
    """Return True if `target` matches any of `safe_write_targets`. Mirrors
    `grammar_classifier._target_is_safe_write` so flag-value writes
    (e.g. `find -fprint FILE`) and `> file` redirects use the same white
    list."""
    return _path_matches_target_list(target, safe_write_targets)


def check_unsafe_flags(cmd_args, spec, safe_write_targets=None,
                       unsafe_write_targets=None):
    """Check whether cmd_args contains a flag combination the command spec
    declares unsafe. Returns a human-readable description, or None.

    Recognized fields on `spec`:

    - `unsafe_flags_without_value`: list of flags that are unsafe by their
      presence alone (`find -delete`).
    - `unsafe_flag_values`: dict flag -> list of values. Match is
      case-insensitive equality against the value (`curl -X POST`).
    - `unsafe_flag_any_value`: list of flags unsafe whenever they appear,
      regardless of value (`curl -d ...`).
    - `unsafe_flag_value_prefix`: dict flag -> fnmatch glob pattern.
      The flag carries a value (inline `--flag=value` or split
      `--flag value`); the value is matched against the glob
      (`find -exec rm`, `gh api --input body.json`). `"*"` matches any
      value.
    - `write_flag_value_targets`: list of flags whose immediately
      following value is a file path the command will write to
      (`find -fprint FILE`, `install -t DIR`). The value is checked
      against the top-level `unsafe_write_targets` deny list first
      (a match flags a protected-path write) and then the
      `safe_write_targets` white list (a non-matching path makes the
      call unsafe). Requires those lists to be passed in.
    - `write_value_prefix_targets`: list of token prefixes whose suffix
      is a write-target path (`dd of=PATH`). The suffix is checked
      against `unsafe_write_targets`.
    - `write_target_last_positional` / `write_target_all_positional`:
      the last / every non-flag positional argument is a write-target
      path (`cp SRC DST`, `tee FILE...`). Checked against
      `unsafe_write_targets`.

    The last three only consult the deny list. The commands that use
    them are already `default: unsafe`, so a deny match upgrades the
    reason from a generic prompt to a specific protected-path one; a
    non-match falls through to the command default.
    """
    unsafe_flag_values = spec.get("unsafe_flag_values", {})
    unsafe_flag_any_value = set(spec.get("unsafe_flag_any_value", []))
    unsafe_flags_without_value = set(spec.get("unsafe_flags_without_value", []))
    unsafe_flag_value_prefix = spec.get("unsafe_flag_value_prefix", {})
    write_flag_value_targets = set(spec.get("write_flag_value_targets", []))

    i = 0
    while i < len(cmd_args):
        tok = cmd_args[i]

        flag = tok
        inline_value = None
        if "=" in tok and tok.startswith("-"):
            flag, _, inline_value = tok.partition("=")

        if flag in unsafe_flags_without_value:
            return "{} (no value)".format(flag)

        if flag in unsafe_flag_values:
            value = inline_value
            if value is None and i + 1 < len(cmd_args):
                value = cmd_args[i + 1]
            if value is not None:
                value_upper = value.upper() if isinstance(value, str) else value
                for unsafe_val in unsafe_flag_values[flag]:
                    if value_upper == unsafe_val.upper():
                        return "{} {}".format(flag, value)

        if flag in unsafe_flag_value_prefix:
            value = inline_value
            if value is None and i + 1 < len(cmd_args):
                value = cmd_args[i + 1]
            if value is not None:
                pat = unsafe_flag_value_prefix[flag]
                if fnmatch(value, pat):
                    return "{} {}".format(flag, value)

        if flag in write_flag_value_targets:
            value = inline_value
            if value is None and i + 1 < len(cmd_args):
                value = cmd_args[i + 1]
            if value is not None:
                if _path_matches_target_list(value, unsafe_write_targets):
                    return "{} {} (protected path)".format(flag, value)
                if not _path_matches_safe_write_targets(value, safe_write_targets):
                    return "{} {}".format(flag, value)

        if flag in unsafe_flag_any_value:
            return flag

        i += 1

    # Write-target arguments routed through the unsafe_write_targets deny
    # list. The commands carrying these fields are already
    # `default: unsafe`, so a match upgrades the reason to a specific
    # protected-path one; a non-match falls through to the default.
    if unsafe_write_targets:
        for pref in spec.get("write_value_prefix_targets", []):
            for tok in cmd_args:
                if tok.startswith(pref):
                    value = tok[len(pref):]
                    if value and _path_matches_target_list(
                        value, unsafe_write_targets
                    ):
                        return "{}{} (protected path)".format(pref, value)

        positionals = [a for a in cmd_args if not a.startswith("-")]
        targets = []
        if spec.get("write_target_all_positional"):
            targets = positionals
        elif spec.get("write_target_last_positional") and positionals:
            targets = [positionals[-1]]
        for value in targets:
            if _path_matches_target_list(value, unsafe_write_targets):
                return "{} (protected path)".format(value)

    return None


_ALLOWED_DEFAULTS = frozenset({
    "safe", "unsafe", "ask", "unknown",
    "subcommand", "delegate_to_argument",
    "aws_cli", "gcloud_cli", "az_cli", "sql_cli",
})

_ALLOWED_TOP_LEVEL_KEYS = frozenset({
    "_meta", "_safe_write_targets_note", "_unsafe_write_targets_note",
    "shell_builtins_safe", "shell_keywords",
    "safe_write_targets", "unsafe_write_targets",
    "commands", "interpreters",
})

_ALLOWED_COMMAND_KEYS = frozenset({
    "default", "_note", "_skip_first_positional",
    "unsafe_flag_values", "unsafe_flag_any_value",
    "unsafe_flags_without_value", "unsafe_flag_value_prefix",
    "write_flag_value_targets",
    "write_value_prefix_targets",
    "write_target_last_positional", "write_target_all_positional",
    "valueless_flags",
    "safe_subcommands", "unsafe_subcommands",
    "safe_subcommand_patterns", "unsafe_subcommand_patterns",
    "nested_subcommand",
    "empty_decision",
    "service_overrides",
    "safe_operation_patterns", "unsafe_operation_patterns",
    "sql_flags", "sql_file_flags", "sql_positional_index",
    "sql_payload_flags",
})

_ALLOWED_SQL_PAYLOAD_FLAG_KEYS = frozenset({"flag", "dialect"})

_ALLOWED_EMPTY_DECISIONS = frozenset({"safe", "unsafe"})

_ALLOWED_SERVICE_OVERRIDE_KEYS = frozenset({
    "_note",
    "safe_subcommands", "unsafe_subcommands",
    "safe_operation_patterns", "unsafe_operation_patterns",
    "extra_safe_patterns",
})

_ALLOWED_INTERPRETER_KEYS = frozenset({
    "inline_flag", "module_flag", "delegate", "read_script_file",
    "safe_modules", "unsafe_modules",
    "safe_module_patterns", "unsafe_module_patterns",
    "nested_modules",
})

_ALLOWED_NESTED_MODULE_KEYS = frozenset({
    "default",
    "safe_subcommands", "unsafe_subcommands",
    "safe_subcommand_patterns", "unsafe_subcommand_patterns",
})

# `_classify_nested_module` only resolves "safe" and "unsafe"; any other
# value silently degrades to `unknown` at classify time, which is exactly
# the drift this validator exists to catch.
_ALLOWED_NESTED_MODULE_DEFAULTS = frozenset({"safe", "unsafe"})


def validate_shell_rules(rules):
    """Schema-check a loaded shell.json. Returns a list of error strings —
    empty list means the data only uses keys / defaults the classifier
    actually evaluates. Catches drift where the rule file references a
    field the implementation silently ignores."""
    errors = []

    for key in rules:
        if key not in _ALLOWED_TOP_LEVEL_KEYS:
            errors.append("top-level: unknown key '{}'".format(key))

    commands = rules.get("commands", {})
    if not isinstance(commands, dict):
        errors.append("commands: must be a dict")
        commands = {}

    for name, spec in commands.items():
        if not isinstance(spec, dict):
            errors.append("commands.{}: must be a dict".format(name))
            continue
        _validate_command_spec("commands.{}".format(name), spec, errors)

    interpreters = rules.get("interpreters", {})
    if not isinstance(interpreters, dict):
        errors.append("interpreters: must be a dict")
        interpreters = {}

    for name, spec in interpreters.items():
        if not isinstance(spec, dict):
            errors.append("interpreters.{}: must be a dict".format(name))
            continue
        for key in spec:
            if key not in _ALLOWED_INTERPRETER_KEYS:
                errors.append(
                    "interpreters.{}: unknown key '{}'".format(name, key)
                )
        nested = spec.get("nested_modules", {})
        if isinstance(nested, dict):
            for mod, mod_spec in nested.items():
                if not isinstance(mod_spec, dict):
                    errors.append(
                        "interpreters.{}.nested_modules.{}: must be a dict"
                        .format(name, mod)
                    )
                    continue
                for key in mod_spec:
                    if key not in _ALLOWED_NESTED_MODULE_KEYS:
                        errors.append(
                            "interpreters.{}.nested_modules.{}: unknown key '{}'"
                            .format(name, mod, key)
                        )
                mod_default = mod_spec.get("default")
                if (
                    mod_default is not None
                    and mod_default not in _ALLOWED_NESTED_MODULE_DEFAULTS
                ):
                    errors.append(
                        "interpreters.{}.nested_modules.{}: unknown default '{}'"
                        .format(name, mod, mod_default)
                    )

    return errors


def _validate_command_spec(path, spec, errors):
    for key in spec:
        if key not in _ALLOWED_COMMAND_KEYS:
            errors.append("{}: unknown key '{}'".format(path, key))

    default = spec.get("default")
    if default is not None and default not in _ALLOWED_DEFAULTS:
        errors.append("{}: unknown default '{}'".format(path, default))

    empty_decision = spec.get("empty_decision")
    if empty_decision is not None and empty_decision not in _ALLOWED_EMPTY_DECISIONS:
        errors.append(
            "{}: empty_decision must be 'safe' or 'unsafe', got '{}'".format(
                path, empty_decision
            )
        )

    nested = spec.get("nested_subcommand", {})
    if isinstance(nested, dict):
        for sub, sub_spec in nested.items():
            if not isinstance(sub_spec, dict):
                errors.append(
                    "{}.nested_subcommand.{}: must be a dict".format(path, sub)
                )
                continue
            _validate_command_spec(
                "{}.nested_subcommand.{}".format(path, sub),
                sub_spec,
                errors,
            )

    overrides = spec.get("service_overrides", {})
    if isinstance(overrides, dict):
        for svc, svc_spec in overrides.items():
            if not isinstance(svc_spec, dict):
                errors.append(
                    "{}.service_overrides.{}: must be a dict".format(path, svc)
                )
                continue
            for key in svc_spec:
                if key not in _ALLOWED_SERVICE_OVERRIDE_KEYS:
                    errors.append(
                        "{}.service_overrides.{}: unknown key '{}'"
                        .format(path, svc, key)
                    )

    payload_flags = spec.get("sql_payload_flags", {})
    if isinstance(payload_flags, dict):
        for op_key, entry in payload_flags.items():
            if op_key.startswith("_"):
                continue
            entry_path = "{}.sql_payload_flags.{}".format(path, op_key)
            if not isinstance(entry, dict):
                errors.append("{}: must be a dict".format(entry_path))
                continue
            for key in entry:
                if key not in _ALLOWED_SQL_PAYLOAD_FLAG_KEYS:
                    errors.append(
                        "{}: unknown key '{}'".format(entry_path, key)
                    )
            if not entry.get("flag"):
                errors.append("{}: missing 'flag'".format(entry_path))


def parse_aws_positionals(cmd_args):
    """Walk aws CLI args skipping flags. Return (service, operation, trailing)."""
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
            if tok in {"--no-cli-pager", "--no-paginate", "--no-verify-ssl",
                      "--no-sign-request", "--debug"}:
                i += 1
                continue
            if i + 1 < len(cmd_args) and not cmd_args[i + 1].startswith("-"):
                i += 2
                continue
            i += 1
            continue
        if tok.startswith("-") and len(tok) > 1:
            i += 1
            continue
        if service is None:
            service = tok
        elif operation is None:
            operation = tok
        else:
            trailing.append(tok)
        i += 1

    return (service, operation, trailing)


def extract_flag_value(cmd_args, flag):
    """Return the value passed to `flag` in cmd_args, or None if the flag is
    absent (or present with no following value). Handles both `--flag value`
    and `--flag=value` forms."""
    retval = None
    eq_prefix = flag + "="
    i = 0
    while i < len(cmd_args):
        tok = cmd_args[i]
        if tok == flag:
            if i + 1 < len(cmd_args):
                retval = cmd_args[i + 1]
            break
        if tok.startswith(eq_prefix):
            retval = tok[len(eq_prefix):]
            break
        i += 1
    return retval


class RuleClassifier:
    """Classifies a simple command (argv tokens already reconstructed) by
    consulting rule data. The grammar-driven walker owns decomposition;
    this class is purely the rule-lookup half."""

    MAX_RECURSION_DEPTH = 8

    def __init__(self, rules, python_analyzer_factory=None, bash_analyzer=None):
        self.rules = rules
        self.commands = rules.get("commands", {})
        self.shell_builtins_safe = set(rules.get("shell_builtins_safe", []))
        self.interpreters = rules.get("interpreters", {})
        self.safe_write_targets = list(rules.get("safe_write_targets", []))
        self.unsafe_write_targets = list(rules.get("unsafe_write_targets", []))
        self.python_analyzer_factory = python_analyzer_factory
        # When a `bash -c '<script>'` interpreter call needs nested analysis,
        # the grammar walker injects itself here as a callable
        # (script: str) -> (decision, reason).
        self.bash_analyzer = bash_analyzer

    def classify_tokens(self, tokens, _depth=0):
        if _depth > self.MAX_RECURSION_DEPTH:
            return (DECISION_UNKNOWN, "max recursion depth")

        if not tokens:
            return (DECISION_SAFE, "empty")

        if all(t == SUBSTITUTION_PLACEHOLDER for t in tokens):
            return (DECISION_SAFE, "only substitution result (classified separately)")

        cmd_name = os.path.basename(tokens[0])
        cmd_args = tokens[1:]

        if cmd_name in self.shell_builtins_safe:
            return (DECISION_SAFE, "builtin: {}".format(cmd_name))

        if cmd_name in self.interpreters:
            return self.classify_interpreter(cmd_name, cmd_args, _depth=_depth)

        if cmd_name in self.commands:
            return self.classify_known_command(cmd_name, cmd_args, _depth=_depth)

        return (DECISION_UNKNOWN, "no rule: {}".format(cmd_name))

    def classify_interpreter(self, name, cmd_args, _depth):
        spec = self.interpreters[name]
        inline_flag = spec.get("inline_flag")
        module_flag = spec.get("module_flag")
        delegate = spec.get("delegate", "unknown")
        read_script_file = spec.get("read_script_file", False)

        inline_code = None
        if inline_flag and inline_flag in cmd_args:
            idx = cmd_args.index(inline_flag)
            if idx + 1 < len(cmd_args):
                inline_code = cmd_args[idx + 1]

        if inline_code is not None:
            if delegate == "python":
                return self.classify_python_source(
                    inline_code, "{} {} ...".format(name, inline_flag),
                    inline=True,
                )
            if delegate == "bash":
                if self.bash_analyzer is None:
                    return (DECISION_UNKNOWN, "bash analyzer unavailable")
                d, r = self.bash_analyzer(inline_code, _depth + 1)
                return (d, "{} -c -> {}".format(name, r))
            return (DECISION_UNKNOWN, "cannot analyze inline {}".format(delegate))

        # `python3 -m <module> [args...]` — classify by module name. The
        # module-rule data lives in `interpreters.<name>.{safe,unsafe}_modules`
        # plus `nested_modules` for cases like `pip` where the subcommand
        # decides (install/uninstall = unsafe, list/show/freeze = safe).
        if module_flag and module_flag in cmd_args:
            idx = cmd_args.index(module_flag)
            if idx + 1 < len(cmd_args):
                module = cmd_args[idx + 1]
                module_args = cmd_args[idx + 2:]
                return self._classify_module(name, module, module_args, spec)
            return (DECISION_UNKNOWN, "{} {}: no module".format(name, module_flag))

        if read_script_file and delegate == "python":
            for arg in cmd_args:
                if arg.startswith("-"):
                    continue
                if arg.endswith(".py") or os.path.isfile(arg):
                    try:
                        with open(arg, "r") as f:
                            code = f.read()
                    except (OSError, UnicodeDecodeError) as e:
                        return (DECISION_UNKNOWN, "cannot read {}: {}".format(arg, e))
                    return self.classify_python_source(code, "{} {}".format(name, arg))
                break

        return (DECISION_UNKNOWN, "{} invocation not analyzable".format(name))

    def _classify_module(self, name, module, module_args, spec):
        safe_modules = set(spec.get("safe_modules", []))
        unsafe_modules = set(spec.get("unsafe_modules", []))
        nested = spec.get("nested_modules", {})

        if module in safe_modules:
            return (DECISION_SAFE, "{} -m {}: read-only".format(name, module))
        if module in unsafe_modules:
            return (DECISION_UNSAFE, "{} -m {}: mutating".format(name, module))

        if module in nested:
            return self._classify_nested_module(
                name, module, module_args, nested[module]
            )

        for pat in spec.get("safe_module_patterns", []):
            if fnmatch(module, pat):
                return (DECISION_SAFE,
                        "{} -m {}: matches safe pattern".format(name, module))
        for pat in spec.get("unsafe_module_patterns", []):
            if fnmatch(module, pat):
                return (DECISION_UNSAFE,
                        "{} -m {}: matches unsafe pattern".format(name, module))

        return (DECISION_UNKNOWN, "{} -m {}: no rule".format(name, module))

    def _classify_nested_module(self, name, module, args, mod_spec):
        safe_subs = set(mod_spec.get("safe_subcommands", []))
        unsafe_subs = set(mod_spec.get("unsafe_subcommands", []))

        sub = None
        for a in args:
            if not a.startswith("-"):
                sub = a
                break

        label = "{} -m {}".format(name, module)

        if sub is None:
            default = mod_spec.get("default")
            if default == "safe":
                return (DECISION_SAFE, "{}: read-only".format(label))
            if default == "unsafe":
                return (DECISION_UNSAFE, "{}: mutating".format(label))
            return (DECISION_UNKNOWN, "{}: no subcommand".format(label))

        if sub in safe_subs:
            return (DECISION_SAFE, "{} {}: read-only".format(label, sub))
        if sub in unsafe_subs:
            return (DECISION_UNSAFE, "{} {}: mutating".format(label, sub))

        return (DECISION_UNKNOWN, "{} {}: no rule".format(label, sub))

    def classify_python_source(self, source, description, inline=False):
        if self.python_analyzer_factory is None:
            return (DECISION_UNKNOWN, "python analyzer unavailable")
        analyzer = self.python_analyzer_factory()
        result = analyzer.analyze(source)
        if result.get("safe"):
            return (DECISION_SAFE, "python: {}".format(description))
        if inline and result.get("parse_error"):
            reason = "{} (parser bailed at line {})".format(
                UNANALYZABLE_INLINE_PYTHON_PREFIX,
                result.get("parse_error_lineno", "?"),
            )
            return (DECISION_UNSAFE, reason)
        return (DECISION_UNSAFE, "python {}: {}".format(
            description, result.get("reason", "destructive call")
        ))

    def classify_known_command(self, cmd_name, cmd_args, _depth):
        spec = self.commands[cmd_name]
        default = spec.get("default", "unknown")

        unsafe_match = check_unsafe_flags(
            cmd_args, spec,
            safe_write_targets=self.safe_write_targets,
            unsafe_write_targets=self.unsafe_write_targets,
        )
        if unsafe_match:
            return (DECISION_UNSAFE, "{}: flag {}".format(cmd_name, unsafe_match))

        if default == "safe":
            return (DECISION_SAFE, "{}: read-only".format(cmd_name))
        if default == "unsafe":
            return (DECISION_UNSAFE, "{}: mutating".format(cmd_name))
        if default == "ask":
            return (DECISION_UNKNOWN, "{}: rules punt".format(cmd_name))
        if default == "subcommand":
            return self.classify_subcommand(cmd_name, cmd_args, spec, _depth=_depth)
        if default == "delegate_to_argument":
            return self.classify_delegate_to_argument(cmd_name, cmd_args, spec, _depth=_depth)
        if default == "aws_cli":
            return self.classify_aws(cmd_args, spec)
        if default == "gcloud_cli":
            return self.classify_verb_cli(cmd_args, spec, label="gcloud")
        if default == "az_cli":
            return self.classify_verb_cli(cmd_args, spec, label="az")
        if default == "sql_cli":
            return self.classify_sql_cli(cmd_name, cmd_args, spec)

        return (DECISION_UNKNOWN, "{}: unknown default '{}'".format(cmd_name, default))

    def classify_subcommand(self, cmd_name, cmd_args, spec, _depth):
        valueless = set(spec.get("valueless_flags", []))
        positional = self._skip_flags(cmd_args, valueless_flags=valueless)
        if not positional:
            return (DECISION_UNKNOWN, "{}: no subcommand".format(cmd_name))

        sub = positional[0]
        rest = positional[1:]
        remaining_args = cmd_args[cmd_args.index(sub) + 1:] if sub in cmd_args else rest

        nested = spec.get("nested_subcommand", {})
        if sub in nested:
            nested_spec = nested[sub]
            nested_unsafe = check_unsafe_flags(
                remaining_args, nested_spec,
                safe_write_targets=self.safe_write_targets,
                unsafe_write_targets=self.unsafe_write_targets,
            )
            if nested_unsafe:
                return (DECISION_UNSAFE, "{} {}: flag {}".format(cmd_name, sub, nested_unsafe))
            if "default" in nested_spec:
                nested_default = nested_spec["default"]
                if nested_default == "safe":
                    return (DECISION_SAFE, "{} {}: read-only".format(cmd_name, sub))
                if nested_default == "unsafe":
                    return (DECISION_UNSAFE, "{} {}: mutating".format(cmd_name, sub))
            empty_decision = nested_spec.get("empty_decision")
            if empty_decision and not rest:
                if empty_decision == "safe":
                    return (DECISION_SAFE, "{} {}: read-only (no positional)".format(cmd_name, sub))
                if empty_decision == "unsafe":
                    return (DECISION_UNSAFE, "{} {}: mutating (no positional)".format(cmd_name, sub))
            return self._match_subcommand_lists(
                "{} {}".format(cmd_name, sub), rest, nested_spec
            )

        return self._match_subcommand_lists(cmd_name, positional, spec)

    def _match_subcommand_lists(self, label, positional, spec):
        safe_subs = set(spec.get("safe_subcommands", []))
        unsafe_subs = set(spec.get("unsafe_subcommands", []))
        safe_patterns = spec.get("safe_subcommand_patterns", [])
        unsafe_patterns = spec.get("unsafe_subcommand_patterns", [])

        if not positional:
            return (DECISION_UNKNOWN, "{}: no subcommand".format(label))

        sub = positional[0]

        if sub in safe_subs:
            return (DECISION_SAFE, "{} {}: read-only".format(label, sub))
        if sub in unsafe_subs:
            return (DECISION_UNSAFE, "{} {}: mutating".format(label, sub))
        for pat in safe_patterns:
            if fnmatch(sub, pat):
                return (DECISION_SAFE, "{} {}: matches safe pattern {}".format(label, sub, pat))
        for pat in unsafe_patterns:
            if fnmatch(sub, pat):
                return (DECISION_UNSAFE, "{} {}: matches unsafe pattern {}".format(label, sub, pat))

        return (DECISION_UNKNOWN, "{} {}: no rule".format(label, sub))

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
            return (DECISION_UNKNOWN, "{}: no wrapped command".format(cmd_name))

        wrapped_tokens = cmd_args[i:]
        d, r = self.classify_tokens(wrapped_tokens, _depth=_depth + 1)
        return (d, "{} wraps: {}".format(cmd_name, r))

    def classify_aws(self, cmd_args, spec):
        service, operation, _ = parse_aws_positionals(cmd_args)
        if service is None:
            return (DECISION_UNKNOWN, "aws: no service")
        if operation is None:
            return (DECISION_UNKNOWN, "aws {}: no operation".format(service))

        verb_decision, verb_reason = self._classify_aws_verb(
            service, operation, spec
        )

        payload_flags = spec.get("sql_payload_flags", {})
        entry = payload_flags.get("{} {}".format(service, operation))
        if entry is None:
            return (verb_decision, verb_reason)

        retval = self._scan_aws_sql_payload(
            cmd_args, service, operation, entry, verb_decision, verb_reason
        )
        return retval

    def _scan_aws_sql_payload(self, cmd_args, service, operation, entry,
                              verb_decision, verb_reason):
        """Refine an aws decision by scanning the SQL string the operation
        carries in a flag (e.g. athena `--query-string`, rds-data `--sql`).

        A write verb is a hard floor: `start-*` / `execute-*` stay unsafe
        regardless of payload, so payload scanning cannot weaken an
        un-overridden mutating operation. Below that floor the SQL governs,
        which (a) refines an unknown verb such as `timestream-query query`
        to safe/unsafe by its payload, and (b) lets a user who has marked
        the operation safe (via an `extra_safe_patterns` override) still get
        destructive SQL flagged instead of blanket-allowed."""
        label = "aws {} {}".format(service, operation)
        if verb_decision == DECISION_UNSAFE:
            retval = (verb_decision, verb_reason)
            return retval

        flag = entry.get("flag")
        sql = extract_flag_value(cmd_args, flag)
        if sql is None:
            # The operation is registered as SQL-bearing but the payload is
            # not on the expected flag — absent, interactive, or supplied via
            # an alternate input form such as `--cli-input-json`. The scanner
            # cannot inspect it, so a verb-safe override must NOT blanket-allow
            # the call; downgrade to unknown so Claude Code prompts. (A verb
            # already classified unsafe returned above.)
            retval = (DECISION_UNKNOWN,
                      "{}: registered SQL op but no {} payload to scan; "
                      "not certifying safe".format(label, flag))
            return retval

        dialect = entry.get("dialect")
        payload_decision, payload_reason = classify_sql_text(
            label, sql, dialect=dialect
        )
        retval = (payload_decision,
                  "{} (payload scan; verb: {})".format(
                      payload_reason, verb_decision))
        return retval

    def _classify_aws_verb(self, service, operation, spec):
        service_overrides = spec.get("service_overrides", {})
        per_service = service_overrides.get(service, {})

        safe_subs = set(per_service.get("safe_subcommands", []))
        unsafe_subs = set(per_service.get("unsafe_subcommands", []))
        if operation in safe_subs:
            return (DECISION_SAFE, "aws {} {}: read-only".format(service, operation))
        if operation in unsafe_subs:
            return (DECISION_UNSAFE, "aws {} {}: mutating".format(service, operation))

        for pat in per_service.get("extra_safe_patterns", []):
            if fnmatch(operation, pat):
                return (DECISION_SAFE, "aws {} {}: service override safe".format(service, operation))

        for pat in per_service.get("safe_operation_patterns", []):
            if fnmatch(operation, pat):
                return (DECISION_SAFE, "aws {} {}: service-safe pattern".format(service, operation))
        for pat in per_service.get("unsafe_operation_patterns", []):
            if fnmatch(operation, pat):
                return (DECISION_UNSAFE, "aws {} {}: service-unsafe pattern".format(service, operation))

        for pat in spec.get("safe_operation_patterns", []):
            if fnmatch(operation, pat):
                return (DECISION_SAFE, "aws {} {}: global read-only".format(service, operation))
        for pat in spec.get("unsafe_operation_patterns", []):
            if fnmatch(operation, pat):
                return (DECISION_UNSAFE, "aws {} {}: global mutating".format(service, operation))

        return (DECISION_UNKNOWN, "aws {} {}: unclassified".format(service, operation))

    def classify_sql_cli(self, cmd_name, cmd_args, spec):
        sqls, file_input = parse_sql_cli_argv(cmd_args, spec)
        if file_input:
            return (DECISION_UNKNOWN,
                    "{}: SQL from file (opaque)".format(cmd_name))
        if not sqls:
            return (DECISION_UNKNOWN,
                    "{}: no inline SQL (interactive or stdin)".format(cmd_name))
        decisions = [classify_sql_text(cmd_name, s) for s in sqls]
        return aggregate_decisions(decisions)

    def classify_verb_cli(self, cmd_args, spec, label):
        positional = self._skip_flags(cmd_args)
        if len(positional) < 2:
            return (DECISION_UNKNOWN, "{}: too few positionals".format(label))

        verb = positional[-1]
        safe_verbs = {"list", "describe", "get", "show", "export", "version", "help"}
        unsafe_verbs = {
            "create", "delete", "update", "replace", "set", "add", "remove",
            "deploy", "run", "execute", "exec", "ssh",
            "enable", "disable", "reset", "rollback", "promote", "restart",
            "scale", "resize",
        }
        if verb in safe_verbs:
            return (DECISION_SAFE, "{} {}: read verb".format(label, verb))
        if verb in unsafe_verbs:
            return (DECISION_UNSAFE, "{} {}: write verb".format(label, verb))
        return (DECISION_UNKNOWN, "{} {}: unknown verb".format(label, verb))

    @staticmethod
    def _skip_flags(cmd_args, valueless_flags=None):
        valueless_flags = valueless_flags or set()
        positional = []
        i = 0
        while i < len(cmd_args):
            tok = cmd_args[i]
            if tok.startswith("--"):
                if "=" in tok:
                    i += 1
                    continue
                if tok in valueless_flags:
                    i += 1
                    continue
                if i + 1 < len(cmd_args) and not cmd_args[i + 1].startswith("-"):
                    i += 2
                    continue
                i += 1
                continue
            if tok.startswith("-") and len(tok) > 1:
                if tok in valueless_flags:
                    i += 1
                    continue
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
        return positional
