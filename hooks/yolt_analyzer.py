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
    Before the AST walk, a pre-pass scans only the *direct module-level*
    statements of the parsed tree and builds two data structures:

      - `_module_events`: a line-ordered list of binding events (imports
        and reassignments) at module scope. Used to compute the binding
        snapshot effective at any given source line, so a module-scope
        call resolves against the bindings that existed *just before* it,
        not against the final state of the module. This matters when
        the script imports, calls, then later rebinds or re-imports the
        same name — the earlier call should still see the original
        binding.
      - `alias_table`: the *final* snapshot, applied to calls that live
        inside function / class bodies. Those bodies execute when their
        enclosing function/class is invoked, conceptually after the
        module-level code finishes, so they see the final state.

    Supported import forms (recorded as binding events):

      - `import mod`                       -> {"mod": "mod"}
      - `import mod as alias`              -> {"alias": "mod"}
      - `import mod.sub`                   -> {"mod": "mod"}
      - `import mod.sub as alias`          -> {"alias": "mod.sub"}
      - `from mod import name`             -> {"name": "mod.name"}
      - `from mod import name as alias`    -> {"alias": "mod.name"}

    Scope rules:

      - Only top-of-file (direct module-body) imports are honored.
        Imports nested under control flow (`if cond: import x`,
        `if False:` branches, `try`/`except`, `with`) or inside a
        function/class body are NOT honored — we cannot statically prove
        they execute, so the surface name is left alone.
      - Module-scope reassignments (`name = ...`, `for name in ...`,
        `name += ...`, `with ... as name:`, including assignments
        inside top-level `if`/`for` blocks) are recorded as "drop"
        events at their source line, so a later module-scope call no
        longer resolves through the old binding.
      - Function-internal rebinds do NOT participate, because those
        introduce their own scope.

    `_resolve` rewrites the leading binding of each call target. Names
    that have no recorded binding effective at the call's position are
    left unchanged — we never guess. Still out of scope: variable
    rebinding via attribute access, starred imports
    (`from mod import *`), relative imports (`from . import x`), and
    proving object identity for arbitrary locals."""

    def __init__(self, rules):
        self.rules = rules
        self.findings = []
        self.imports = set()
        self.import_modules = set()
        self.safe_imports = set(rules.get("_safe_imports", []))
        # Final snapshot: used for calls inside function / class bodies.
        # Populated by `_collect_top_level_bindings` before the AST walk.
        self.alias_table = {}
        # Ordered list of (lineno, name, target_or_None) module-scope
        # binding events. `target=None` means the event drops the binding
        # (reassignment). Snapshots at any line are computed by replaying
        # events with `lineno < line`.
        self._module_events = []
        # Tracks whether the current AST position is inside a function
        # or class body. Calls at depth 0 use position-specific
        # resolution; deeper calls use the final snapshot.
        self._scope_depth = 0

    def visit_Import(self, node):
        for alias in node.names:
            top_level = alias.name.split(".")[0]
            self.imports.add(alias.name)
            self.import_modules.add(top_level)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if not node.module:
            self.generic_visit(node)
            return
        top_level = node.module.split(".")[0]
        self.imports.add(node.module)
        self.import_modules.add(top_level)
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        self._visit_function_like(node)

    def visit_AsyncFunctionDef(self, node):
        self._visit_function_like(node)

    def visit_Lambda(self, node):
        # Defaults run at lambda-creation time (module scope); body runs
        # when the lambda is called.
        for d in node.args.defaults:
            self.visit(d)
        for d in node.args.kw_defaults:
            if d is not None:
                self.visit(d)
        self._scope_depth += 1
        try:
            self.visit(node.body)
        finally:
            self._scope_depth -= 1

    def visit_ClassDef(self, node):
        # A class body executes at module load (it's just a sequence of
        # statements run in a fresh namespace), so calls inside it must
        # resolve against the position-aware module snapshot. Decorators,
        # bases, and keyword arguments also evaluate at the class
        # statement's position. Do NOT bump `_scope_depth`.
        self.generic_visit(node)

    def _visit_function_like(self, node):
        """Walk a `def` / `async def` carefully: decorators, default and
        kw-default values, and annotations all evaluate at definition
        time (module scope in the typical top-level case), so they must
        resolve against the position-aware snapshot. Only the function
        body is deferred until the function is called; bump
        `_scope_depth` only across the body."""
        for d in node.decorator_list:
            self.visit(d)
        for d in node.args.defaults:
            self.visit(d)
        for d in node.args.kw_defaults:
            if d is not None:
                self.visit(d)
        if node.returns is not None:
            self.visit(node.returns)
        self._scope_depth += 1
        try:
            for stmt in node.body:
                self.visit(stmt)
        finally:
            self._scope_depth -= 1

    def _collect_top_level_bindings(self, tree):
        """Walk the module-level body (only) and build the line-ordered
        binding event list plus the final snapshot. See class docstring
        for the scoping rationale."""
        if not isinstance(tree, ast.Module):
            return

        events = []

        for stmt in tree.body:
            if isinstance(stmt, ast.Import):
                for alias in stmt.names:
                    if alias.asname:
                        events.append((stmt.lineno, alias.asname, alias.name))
                    else:
                        # `import os.path` binds the top-level name `os`.
                        top_level = alias.name.split(".")[0]
                        events.append((stmt.lineno, top_level, top_level))
            elif isinstance(stmt, ast.ImportFrom):
                if not stmt.module:
                    # Relative imports: package context unavailable, skip.
                    continue
                for alias in stmt.names:
                    if alias.name == "*":
                        # Starred imports: bound names are not statically
                        # knowable, do not guess.
                        continue
                    local = alias.asname or alias.name
                    events.append((
                        stmt.lineno,
                        local,
                        "{}.{}".format(stmt.module, alias.name),
                    ))
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                # Function / class definitions don't bind module-scope
                # names other than their own; that name's "binding" is
                # not something the resolver should rewrite, so skip.
                continue
            else:
                # Walk this top-level statement collecting module-scope
                # reassignments as drop events keyed to their source line.
                for node in self._walk_module_scope(stmt):
                    line = getattr(node, "lineno", stmt.lineno)
                    if isinstance(node, ast.Assign):
                        for tgt in node.targets:
                            for name in self._names_in_target(tgt):
                                events.append((line, name, None))
                    elif isinstance(node, ast.AugAssign):
                        for name in self._names_in_target(node.target):
                            events.append((line, name, None))
                    elif isinstance(node, ast.AnnAssign):
                        if node.value is not None:
                            for name in self._names_in_target(node.target):
                                events.append((line, name, None))
                    elif isinstance(node, ast.For):
                        for name in self._names_in_target(node.target):
                            events.append((line, name, None))
                    elif isinstance(node, ast.With):
                        for item in node.items:
                            if item.optional_vars is not None:
                                for name in self._names_in_target(
                                    item.optional_vars
                                ):
                                    events.append((line, name, None))

        # Stable sort by lineno preserves intra-line declaration order.
        events.sort(key=lambda e: e[0])
        self._module_events = events

        # Final snapshot for function / class bodies.
        final = {}
        for _, name, target in events:
            if target is None:
                final.pop(name, None)
            else:
                final[name] = target
        self.alias_table = final

    def _snapshot_at_line(self, lineno):
        """Replay binding events strictly before `lineno` and return the
        resulting name -> target dict. Used for module-scope calls so
        they see the binding state effective at their position rather
        than the final module state."""
        snapshot = {}
        for evt_line, name, target in self._module_events:
            if evt_line >= lineno:
                break
            if target is None:
                snapshot.pop(name, None)
            else:
                snapshot[name] = target
        return snapshot

    @staticmethod
    def _names_in_target(target):
        """Extract the bare-name targets from an assignment target.
        Handles `x`, `(x, y)`, `[x, y]`, and starred-tuple cases. Attribute
        / subscript targets (`obj.x = ...`, `arr[0] = ...`) do not rebind
        a local name so they're ignored."""
        retval = set()
        if isinstance(target, ast.Name):
            retval.add(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                retval.update(SafetyAnalyzer._names_in_target(elt))
        elif isinstance(target, ast.Starred):
            retval.update(SafetyAnalyzer._names_in_target(target.value))
        return retval

    @staticmethod
    def _walk_module_scope(stmt):
        """Yield every descendant of `stmt` that still lives in module
        scope. Walks past `if`/`for`/`while`/`try`/`with` since those
        share the enclosing scope, but stops at function and class
        boundaries which introduce their own."""
        yield stmt
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return
        for child in ast.iter_child_nodes(stmt):
            yield from SafetyAnalyzer._walk_module_scope(child)

    def visit_Call(self, node):
        call_name = self._get_call_name(node)
        if call_name:
            self._check_call(call_name, node)

        if call_name == "open":
            self._check_open_mode(node)

        self.generic_visit(node)

    def _get_call_name(self, node):
        """Extract the full dotted name of a function call, rewriting the
        leading binding via the position-appropriate alias table. Module-
        scope calls resolve against the binding snapshot effective just
        before their line; calls inside function / class bodies resolve
        against the final module snapshot."""
        if isinstance(node.func, ast.Name):
            return self._resolve(node.func.id, node)
        if isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            parts.reverse()
            return self._resolve(".".join(parts), node)
        return None

    def _resolve(self, name, node):
        """Rewrite the leading segment of `name` if it is a recorded
        binding effective at the call's position; otherwise return `name`
        unchanged. Never guesses for unknown leading names - see class
        docstring for the supported forms and out-of-scope cases."""
        if self._scope_depth == 0:
            table = self._snapshot_at_line(node.lineno)
        else:
            table = self.alias_table
        head, sep, rest = name.partition(".")
        if head not in table:
            return name
        resolved_head = table[head]
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
        self._collect_top_level_bindings(tree)
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
