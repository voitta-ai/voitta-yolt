#!/usr/bin/env python3
"""YOLT (You Only Live Twice) - Python script safety analyzer for Claude Code.

Analyzes Python scripts for potentially destructive operations.
Safe scripts get auto-allowed; destructive scripts prompt for review.

Zero external dependencies - stdlib only.
"""

import ast
import json
import os
import shlex
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
    """AST visitor that checks Python code against safety rules."""

    def __init__(self, rules):
        self.rules = rules
        self.findings = []
        self.imports = set()
        self.import_modules = set()
        self.safe_imports = set(rules.get("_safe_imports", []))

    def visit_Import(self, node):
        for alias in node.names:
            top_level = alias.name.split(".")[0]
            self.imports.add(alias.name)
            self.import_modules.add(top_level)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            top_level = node.module.split(".")[0]
            self.imports.add(node.module)
            self.import_modules.add(top_level)
        self.generic_visit(node)

    def visit_Call(self, node):
        call_name = self._get_call_name(node)
        if call_name:
            self._check_call(call_name, node)

        if call_name == "open":
            self._check_open_mode(node)

        self.generic_visit(node)

    def _get_call_name(self, node):
        """Extract the full dotted name of a function call."""
        if isinstance(node.func, ast.Name):
            retval = node.func.id
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
            retval = ".".join(parts)
            return retval
        return None

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


def extract_heredoc_script(command):
    """Extract Python source from a heredoc command like: python3 << 'EOF'\n...\nEOF"""
    import re
    # Match heredoc operator with optional quoting of delimiter
    # Supports: << EOF, << 'EOF', << "EOF", <<-EOF, <<-'EOF', <<-"EOF"
    match = re.match(r"python3\s+<<-?\s*['\"]?(\w+)['\"]?\s*\n", command)
    if not match:
        return None
    delimiter = match.group(1)
    # Find the closing delimiter on its own line
    body_start = match.end()
    closing_pattern = re.compile(r"^\s*" + re.escape(delimiter) + r"\s*$", re.MULTILINE)
    closing_match = closing_pattern.search(command, body_start)
    if not closing_match:
        return None
    retval = command[body_start:closing_match.start()]
    return retval


def extract_script_from_command(command):
    """Extract the Python script path or inline code from a command string."""
    # Check for heredoc before shlex.split (which doesn't understand heredocs)
    if "<<" in command:
        heredoc_source = extract_heredoc_script(command)
        if heredoc_source is not None:
            return "inline", heredoc_source

    try:
        parts = shlex.split(command)
    except ValueError:
        return None, None

    if not parts or parts[0] != "python3":
        return None, None

    if "-c" in parts:
        idx = parts.index("-c")
        if idx + 1 < len(parts):
            return "inline", parts[idx + 1]

    for part in parts[1:]:
        if part.startswith("-"):
            continue
        if part.endswith(".py") or os.path.isfile(part):
            return "file", part

    return None, None


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


def run_hook():
    """Run as a Claude Code PreToolUse hook."""
    try:
        hook_input = json.load(sys.stdin)
    except (json.JSONDecodeError, EOFError):
        sys.exit(0)

    tool_name = hook_input.get("tool_name", "")
    if tool_name != "Bash":
        sys.exit(0)

    command = hook_input.get("tool_input", {}).get("command", "")
    if not command.lstrip().startswith("python3"):
        sys.exit(0)

    source_type, source = extract_script_from_command(command)
    if source_type is None:
        # Can't determine what script to analyze - ask user
        response = make_hook_response("ask", "YOLT: Could not extract script to analyze")
        print(json.dumps(response))
        sys.exit(0)

    if source_type == "file":
        script_path = source
        if not os.path.isfile(script_path):
            # File doesn't exist yet - let it fail naturally
            sys.exit(0)
        with open(script_path, "r") as f:
            source_code = f.read()
    else:
        source_code = source

    yolt_dir = Path(__file__).resolve().parent.parent
    rules = load_rules(
        rules_dir=yolt_dir / "rules",
        user_overrides_path=Path.home() / ".claude" / "yolt" / "rules.json",
    )

    analyzer = SafetyAnalyzer(rules)
    result = analyzer.analyze(source_code)

    if result["safe"]:
        reason = "YOLT: Script analyzed - safe (imports: {})".format(
            ", ".join(result["imports"]) if result["imports"] else "none"
        )
        response = make_hook_response("allow", reason)
        print(json.dumps(response))
        sys.exit(0)
    else:
        lines = ["YOLT: Destructive operations detected:"]
        for finding in result["findings"]:
            line_info = "  Line {}: {} ({})".format(
                finding["line"], finding["call"], finding["category"]
            )
            source_line = finding.get("source_line", "")
            if source_line:
                line_info += "\n    > {}".format(source_line)
            lines.append(line_info)
        reason = "\n".join(lines)
        response = make_hook_response("ask", reason)
        print(json.dumps(response))
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
