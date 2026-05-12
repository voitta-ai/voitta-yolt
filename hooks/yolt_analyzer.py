#!/usr/bin/env python3
"""YOLT (You Only Live Twice) - Python script safety analyzer for Claude Code.

Analyzes Python scripts for potentially destructive operations.
Safe scripts get auto-allowed; destructive scripts prompt for review.

Zero external dependencies - stdlib only.
"""

import ast
import datetime
import json
import os
import sys
from fnmatch import fnmatch
from pathlib import Path


def load_rules(rules_dir, user_overrides_path=None):
    """Load and merge rules from default + user overrides."""
    rules = {}

    default_path = Path(rules_dir) / "default.json"
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


class SafetyAnalyzer(ast.NodeVisitor):
    """AST visitor that checks Python code against safety rules.

    Import-binding resolution
    -------------------------
    During traversal we record the local name introduced by each import so
    that calls written via aliases or `from`-imports can be matched against
    rule patterns that use the original dotted path. Supported forms:

      - `import mod`                       -> {"mod": "mod"}
      - `import mod as alias`              -> {"alias": "mod"}
      - `import mod.sub`                   -> {"mod": "mod"}
      - `import mod.sub as alias`          -> {"alias": "mod.sub"}
      - `from mod import name`             -> {"name": "mod.name"}
      - `from mod import name as alias`    -> {"alias": "mod.name"}

    `_resolve` rewrites the leading binding of each call target via this
    table. Anything not bound by one of those import forms is left
    unchanged - we never guess. Out of scope for this release: variable
    rebinding (`f = os.system; f(...)`), reassignment through attribute
    access, conditional / starred imports, and proving object identity
    for arbitrary locals."""

    def __init__(self, rules):
        self.rules = rules
        self.findings = []
        self.imports = set()
        self.import_modules = set()
        self.safe_imports = set(rules.get("_safe_imports", []))
        # local-name -> fully-qualified dotted path it points to.
        self.alias_table = {}

    def visit_Import(self, node):
        for alias in node.names:
            top_level = alias.name.split(".")[0]
            self.imports.add(alias.name)
            self.import_modules.add(top_level)
            # `import os.path` binds the top-level name `os` in the local
            # scope; `import os.path as p` binds `p` to the submodule.
            if alias.asname:
                self.alias_table[alias.asname] = alias.name
            else:
                self.alias_table[top_level] = top_level
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        # Relative imports (`from . import x`) cannot be resolved without
        # knowing the package context, so we skip the binding step.
        if not node.module:
            self.generic_visit(node)
            return
        top_level = node.module.split(".")[0]
        self.imports.add(node.module)
        self.import_modules.add(top_level)
        for alias in node.names:
            if alias.name == "*":
                # `from mod import *` makes the bound names unknowable
                # statically. Don't guess.
                continue
            local = alias.asname or alias.name
            self.alias_table[local] = "{}.{}".format(node.module, alias.name)
        self.generic_visit(node)

    def visit_Call(self, node):
        call_name = self._get_call_name(node)
        if call_name:
            self._check_call(call_name, node)

        if call_name == "open":
            self._check_open_mode(node)

        self.generic_visit(node)

    def _get_call_name(self, node):
        """Extract the full dotted name of a function call, rewriting the
        leading binding via the import-alias table when known."""
        if isinstance(node.func, ast.Name):
            retval = self._resolve(node.func.id)
            return retval
        if isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            parts.reverse()
            retval = self._resolve(".".join(parts))
            return retval
        return None

    def _resolve(self, name):
        """Rewrite the leading segment of `name` via the import-alias table
        if it is a recorded binding; otherwise return `name` unchanged.
        Never guesses for unknown leading names - see class docstring for
        the supported forms and out-of-scope cases."""
        head, sep, rest = name.partition(".")
        if head not in self.alias_table:
            return name
        resolved_head = self.alias_table[head]
        if sep:
            return "{}.{}".format(resolved_head, rest)
        return resolved_head

    def _matches_pattern(self, name, pattern):
        """Check if a name matches a glob pattern.

        Matches against both the full dotted name and just the method name,
        since variable names obscure the actual object type in static analysis.
        """
        if fnmatch(name, pattern):
            return True
        method = name.rsplit(".", 1)[-1] if "." in name else name
        retval = fnmatch(method, pattern)
        return retval

    def _check_call(self, call_name, node):
        """Check a function call against all rule categories."""
        for category, category_rules in self.rules.items():
            if category.startswith("_") or not isinstance(category_rules, dict):
                continue

            trigger_imports = category_rules.get("trigger_imports", [])
            if trigger_imports:
                if not any(imp in self.import_modules for imp in trigger_imports):
                    continue

            safe_patterns = (
                category_rules.get("safe_methods", [])
                + category_rules.get("safe_calls", [])
            )
            for pattern in safe_patterns:
                if self._matches_pattern(call_name, pattern):
                    return

            destructive_patterns = (
                category_rules.get("destructive_methods", [])
                + category_rules.get("destructive_calls", [])
            )
            for pattern in destructive_patterns:
                if self._matches_pattern(call_name, pattern):
                    source_line = ""
                    if hasattr(self, "source_lines") and 0 < node.lineno <= len(self.source_lines):
                        source_line = self.source_lines[node.lineno - 1].strip()
                    self.findings.append({
                        "type": "destructive",
                        "call": call_name,
                        "pattern": pattern,
                        "category": category,
                        "line": node.lineno,
                        "source_line": source_line,
                    })
                    return

    def _check_open_mode(self, node):
        """Special handling for open() - check the file mode argument."""
        file_rules = self.rules.get("file_io", {})
        if not file_rules.get("check_open_mode", False):
            return

        destructive_modes = set(file_rules.get("destructive_open_modes", []))

        mode = None
        if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
            mode = node.args[1].value
        else:
            for kw in node.keywords:
                if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                    mode = kw.value.value

        if mode is None:
            return

        if mode in destructive_modes:
            source_line = ""
            if hasattr(self, "source_lines") and 0 < node.lineno <= len(self.source_lines):
                source_line = self.source_lines[node.lineno - 1].strip()
            self.findings.append({
                "type": "destructive",
                "call": "open(mode='{}')".format(mode),
                "pattern": "open with mode '{}'".format(mode),
                "category": "file_io",
                "line": node.lineno,
                "source_line": source_line,
            })

    def analyze(self, source):
        """Analyze Python source code and return safety assessment."""
        try:
            tree = ast.parse(source)
        except SyntaxError as e:
            retval = {
                "safe": False,
                "reason": "SyntaxError: {}".format(e),
                "findings": [],
            }
            return retval

        self.source_lines = source.splitlines()
        self.visit(tree)

        is_safe = len(self.findings) == 0

        retval = {
            "safe": is_safe,
            "findings": self.findings,
            "imports": sorted(self.imports),
            "unknown_imports": sorted(self.import_modules - self.safe_imports),
        }

        if not is_safe:
            reasons = []
            for f in self.findings:
                reasons.append(
                    "L{}: {} matches destructive pattern '{}' ({})".format(
                        f["line"], f["call"], f["pattern"], f["category"]
                    )
                )
            retval["reason"] = "; ".join(reasons)

        return retval


def make_hook_response(decision, reason=None):
    """Build the Claude Code hook JSON response."""
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
        }
    }
    if reason:
        output["hookSpecificOutput"]["permissionDecisionReason"] = reason
    return output


DEFAULT_LOG_PATH = Path.home() / ".claude" / "yolt.log"
DEFAULT_LOG_MAX_BYTES = 5 * 1024 * 1024  # 5 MB


def _resolve_log_path():
    """Resolve the log destination.

    - `YOLT_LOG_FILE` unset -> default to ~/.claude/yolt.log (always-on
      so plugin install gives users a usable log out of the box).
    - `YOLT_LOG_FILE` set to an empty string -> opt out, no logging.
    - Otherwise -> the path the user specified.
    """
    env_value = os.environ.get("YOLT_LOG_FILE")
    if env_value is None:
        return DEFAULT_LOG_PATH
    if env_value == "":
        return None
    return Path(env_value)


def _resolve_log_max_bytes():
    """Maximum log size before rotation. Defaults to 5MB. `YOLT_LOG_MAX_BYTES`
    overrides; set to 0 to disable rotation entirely."""
    raw = os.environ.get("YOLT_LOG_MAX_BYTES")
    if raw is None:
        return DEFAULT_LOG_MAX_BYTES
    try:
        return max(0, int(raw))
    except ValueError:
        return DEFAULT_LOG_MAX_BYTES


def _maybe_rotate_log(log_path, max_bytes):
    """Single-generation rotation. If `log_path` exceeds `max_bytes`,
    rename it to `<log_path>.old` (clobbering any existing .old), so
    the next write starts a fresh file. One previous generation kept.

    No-op if `max_bytes` is 0 (rotation disabled), if the file doesn't
    exist, or if the rename fails for any reason — rotation is
    best-effort and must never break the hook."""
    if max_bytes <= 0:
        return
    try:
        size = log_path.stat().st_size
    except OSError:
        return
    if size < max_bytes:
        return
    try:
        old = log_path.with_suffix(log_path.suffix + ".old")
        os.replace(log_path, old)
    except OSError:
        pass


def _log_hook_decision(command, decision, reason):
    """Append a JSON-line record of this hook fire to the resolved log
    path. Logs by default to `~/.claude/yolt.log`; the user can override
    with `YOLT_LOG_FILE=<path>` or opt out with `YOLT_LOG_FILE=""`.

    Useful for dogfooding / QA: tail the log to see exactly which
    decision YOLT made on every Bash invocation — including the silent
    unknown-fallthrough cases that the Claude Code UI hides.

    Rotates the log when it grows past `YOLT_LOG_MAX_BYTES` (default
    5MB) by renaming it to `<log>.old` — one previous generation
    preserved. Set `YOLT_LOG_MAX_BYTES=0` to disable.

    Failures (unwritable path, full disk, ...) are swallowed: logging
    must never break the hook. The command is truncated to 500 chars to
    avoid pathologically long lines.
    """
    log_path = _resolve_log_path()
    if log_path is None:
        return
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        _maybe_rotate_log(log_path, _resolve_log_max_bytes())
        record = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "decision": decision,
            "reason": reason,
            "command": command[:500] if command else "",
        }
        with open(log_path, "a") as f:
            f.write(json.dumps(record) + "\n")
    except OSError:
        pass


def run_hook():
    """Run as a Claude Code PreToolUse hook.

    Flow:
      1. Validate this is a Bash invocation.
      2. Parse the command with tree-sitter-bash and walk the AST via
         GrammarClassifier (handles compound forms, substitutions,
         wrappers, interpreters, heredocs uniformly). The classifier
         delegates python3 inline / script analysis to SafetyAnalyzer.
      3. Map classifier decision -> hook response:
           safe    -> permissionDecision: allow
           unsafe  -> permissionDecision: ask (with explanation)
           unknown -> exit silently, let Claude Code apply its default.

    If tree-sitter-bash is not importable on the host (broken install,
    unsupported platform), exit silently so Claude Code falls through to
    its default prompt rather than failing the hook.

    When `YOLT_LOG_FILE` is set, every examined Bash invocation appends
    a JSON-line record there — including the silent-fallthrough cases.
    """
    try:
        hook_input = json.load(sys.stdin)
    except (json.JSONDecodeError, EOFError):
        sys.exit(0)

    tool_name = hook_input.get("tool_name", "")
    if tool_name != "Bash":
        sys.exit(0)

    command = hook_input.get("tool_input", {}).get("command", "")
    if not command.strip():
        sys.exit(0)

    yolt_dir = Path(__file__).resolve().parent.parent
    py_rules = load_rules(
        rules_dir=yolt_dir / "rules",
        user_overrides_path=Path.home() / ".claude" / "yolt" / "rules.json",
    )

    try:
        hooks_dir = Path(__file__).resolve().parent
        if str(hooks_dir) not in sys.path:
            sys.path.insert(0, str(hooks_dir))
        from grammar_classifier import GrammarClassifier
        from rule_classifier import (
            DECISION_SAFE, DECISION_UNSAFE,
            ShellRulesValidationError,
            load_allow_patterns, load_shell_rules,
        )
    except ImportError as e:
        _log_hook_decision(command, "import-error", str(e))
        sys.exit(0)

    try:
        shell_rules = load_shell_rules(
            rules_dir=yolt_dir / "rules",
            user_overrides_path=Path.home() / ".claude" / "yolt" / "shell.json",
        )
    except ShellRulesValidationError as e:
        _log_hook_decision(command, "rules-validation-error", str(e))
        sys.exit(0)

    cwd_str = hook_input.get("cwd") or os.getcwd()
    cwd = Path(cwd_str)
    allow_patterns = load_allow_patterns([
        Path.home() / ".claude" / "settings.json",
        cwd / ".claude" / "settings.json",
        cwd / ".claude" / "settings.local.json",
    ])

    def _python_factory():
        return SafetyAnalyzer(py_rules)

    classifier = GrammarClassifier(
        shell_rules,
        python_analyzer_factory=_python_factory,
        allow_patterns=allow_patterns,
    )
    decision, reason = classifier.classify(command)
    _log_hook_decision(command, decision, reason)

    if decision == DECISION_SAFE:
        response = make_hook_response("allow", "YOLT: {}".format(reason))
        print(json.dumps(response))
        sys.exit(0)
    if decision == DECISION_UNSAFE:
        response = make_hook_response(
            "ask", "YOLT: Mutating command detected:\n  {}".format(reason)
        )
        print(json.dumps(response))
        sys.exit(0)
    # decision == DECISION_UNKNOWN: let Claude Code handle it
    sys.exit(0)


def run_cli():
    """Run as a CLI tool for direct analysis."""
    if len(sys.argv) < 2:
        print("Usage: yolt_analyzer.py [--hook | <script.py>]", file=sys.stderr)
        sys.exit(1)

    if sys.argv[1] == "--hook":
        run_hook()
        return

    script_path = sys.argv[1]
    with open(script_path, "r") as f:
        source_code = f.read()

    yolt_dir = Path(__file__).resolve().parent.parent
    rules = load_rules(
        rules_dir=yolt_dir / "rules",
        user_overrides_path=Path.home() / ".claude" / "yolt" / "rules.json",
    )

    analyzer = SafetyAnalyzer(rules)
    result = analyzer.analyze(source_code)

    print(json.dumps(result, indent=2))
    sys.exit(0 if result["safe"] else 1)


if __name__ == "__main__":
    run_cli()
