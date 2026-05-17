#!/usr/bin/env python3
"""YOLT grammar-driven Bash classifier.

Walks a tree-sitter-bash AST instead of string-walking. Each AST node type
maps to a visitor: `command` reconstructs argv and calls into the rule
classifier, `redirected_statement` checks redirect targets, control-flow
nodes (`for_statement`, `if_statement`, `while_statement`, `case_statement`,
`subshell`, ...) are walked transparently into their bodies.

Design rationale: see GitHub issue #4. The previous string walker
accumulated quote-state edge cases (the bash `'\\''` close-escape-open
idiom inside `$(...)` is the trigger that broke this open). A maintained
grammar removes the whole class.
"""

import json
import os
import sys
from fnmatch import fnmatch
from pathlib import Path

import tree_sitter_bash as _tsb
from tree_sitter import Language, Parser

from rule_classifier import (
    DECISION_SAFE, DECISION_UNSAFE, DECISION_UNKNOWN,
    SUBSTITUTION_PLACEHOLDER,
    RuleClassifier,
    aggregate_decisions,
    load_allow_patterns,
    load_shell_rules,
    match_allow_patterns,
)


_BASH_LANG = Language(_tsb.language())

_PYTHON_INTERPRETERS = {
    "python", "python3",
    "python3.10", "python3.11", "python3.12", "python3.13",
}

_BASH_INTERPRETERS = {"bash", "sh"}

_WRITE_REDIR_OPS = {">", ">>", "&>", "&>>", "1>", "1>>", "2>", "2>>"}


class GrammarClassifier:
    """Top-level classifier. Parses Bash via tree-sitter, walks the AST,
    and aggregates per-command decisions."""

    MAX_RECURSION_DEPTH = 8

    def __init__(self, rules, python_analyzer_factory=None, allow_patterns=None):
        self.rules = rules
        self.python_analyzer_factory = python_analyzer_factory
        self.allow_patterns = list(allow_patterns) if allow_patterns else []
        self.safe_write_targets = list(rules.get("safe_write_targets", ["/dev/null"]))
        self._rules = RuleClassifier(
            rules,
            python_analyzer_factory=python_analyzer_factory,
            bash_analyzer=self._bash_inline_analyzer,
        )
        self._parser = Parser(_BASH_LANG)

    # --- Public API ---

    def classify(self, command, _depth=0):
        if _depth > self.MAX_RECURSION_DEPTH:
            return (DECISION_UNKNOWN, "max recursion depth")
        if not command or not command.strip():
            return (DECISION_SAFE, "empty")

        src = command.encode("utf-8")
        tree = self._parser.parse(src)
        root = tree.root_node

        if root.has_error:
            return (DECISION_UNKNOWN, "tree-sitter parse error")

        decisions = []
        self._walk(root, src, decisions, _depth)
        if not decisions:
            return (DECISION_SAFE, "no commands")
        return aggregate_decisions(decisions)

    def suggest_allow_pattern(self, command):
        """Best-effort `Bash(...)` allow hint for a single primary command.

        This is intentionally narrow and only covers the self-PR workflow
        write shapes we document today. Compound shells with multiple
        primary commands return `None` rather than guessing."""
        if not command or not command.strip():
            return None

        src = command.encode("utf-8")
        tree = self._parser.parse(src)
        root = tree.root_node
        if root.has_error:
            return None

        commands = []
        self._collect_primary_command_nodes(root, commands)
        if len(commands) != 1:
            return None

        argv = self._argv_from_command(commands[0], src)
        if not argv:
            return None
        return self._suggest_allow_pattern_from_argv(argv)

    # --- AST walker ---

    def _walk(self, node, src, decisions, _depth):
        t = node.type

        if t == "command":
            d, r = self._classify_command_node(node, src, _depth)
            decisions.append((d, r))
            return

        if t == "redirected_statement":
            self._walk_redirected(node, src, decisions, _depth)
            return

        if t == "variable_assignment":
            for c in node.children:
                if c.type in ("command_substitution", "process_substitution"):
                    self._walk(c, src, decisions, _depth)
            return

        if t == "function_definition":
            # Defining a function does not run it. Body is dormant.
            return

        # Pass through: program, list, pipeline, negated_command,
        # subshell, compound_statement, command_substitution,
        # process_substitution, if_statement, for_statement,
        # while_statement, case_statement, do_group, etc.
        for c in node.children:
            self._walk(c, src, decisions, _depth)

    def _walk_redirected(self, node, src, decisions, _depth):
        writes = False
        for c in node.children:
            if c.type == "file_redirect" and self._redirect_writes_to_file(c, src):
                writes = True
                break
        if writes:
            seg = self._slice(node, src)
            decisions.append(self._maybe_allow(
                seg, (DECISION_UNKNOWN, "writes to a file via redirection"),
            ))
            return

        cmd_node = self._first_child(node, "command")
        heredoc_node = self._first_child(node, "heredoc_redirect")
        if cmd_node is not None and heredoc_node is not None:
            argv = self._argv_from_command(cmd_node, src)
            if argv and os.path.basename(argv[0]) in _PYTHON_INTERPRETERS:
                body = self._heredoc_body(heredoc_node, src)
                if body is not None:
                    decisions.append(self._classify_python(
                        body, "{} <<heredoc".format(argv[0]),
                    ))
                    return  # Don't double-classify the bare `python3` argv.

        for c in node.children:
            if c.type in ("file_redirect", "heredoc_redirect"):
                continue
            self._walk(c, src, decisions, _depth)

    # --- Command classification ---

    def _classify_command_node(self, node, src, _depth):
        argv = self._argv_from_command(node, src)
        if not argv:
            return (DECISION_SAFE, "empty command")

        cmd_name = os.path.basename(argv[0])

        # bash -c '<script>' / sh -c '<script>': re-parse the body.
        if cmd_name in _BASH_INTERPRETERS and "-c" in argv[1:]:
            try:
                idx = argv.index("-c", 1)
            except ValueError:
                idx = -1
            if idx >= 0 and idx + 1 < len(argv):
                inline = argv[idx + 1]
                d, r = self.classify(inline, _depth=_depth + 1)
                return (d, "{} -c -> {}".format(cmd_name, r))

        # Argv is built; classify any nested $(...) / <(...) inside the
        # argument nodes separately so destructive substitutions can't
        # smuggle past as opaque placeholders.
        sub_decisions = []
        for c in node.children:
            self._collect_substitutions(c, src, sub_decisions, _depth + 1)

        match_string = " ".join(argv)
        result = self._rules.classify_tokens(argv)
        result = self._maybe_allow(match_string, result)
        if sub_decisions:
            return aggregate_decisions(sub_decisions + [result])
        return result

    def _collect_substitutions(self, node, src, decisions, _depth):
        if node.type in ("command_substitution", "process_substitution"):
            for c in node.children:
                self._walk(c, src, decisions, _depth)
            return
        for c in node.children:
            self._collect_substitutions(c, src, decisions, _depth)

    def _collect_primary_command_nodes(self, node, commands):
        if node.type in ("command_substitution", "process_substitution",
                         "function_definition"):
            return
        if node.type == "redirected_statement":
            cmd = self._first_child(node, "command")
            if cmd is not None:
                commands.append(cmd)
                return
        if node.type == "command":
            commands.append(node)
            return
        for c in node.children:
            self._collect_primary_command_nodes(c, commands)

    # --- Argv reconstruction ---

    def _argv_from_command(self, command_node, src):
        argv = []
        for c in command_node.children:
            if c.type == "variable_assignment":
                # Pre-command env assignment, e.g. `FOO=bar baz`. Skip.
                continue
            argv.append(self._node_text(c, src))
        return argv

    def _node_text(self, node, src):
        t = node.type
        if t == "raw_string":
            txt = self._slice(node, src)
            if len(txt) >= 2 and txt[0] == "'" and txt[-1] == "'":
                return txt[1:-1]
            return txt
        if t == "string":
            return self._reconstruct_string(node, src)
        if t == "ansi_c_string":
            txt = self._slice(node, src)
            if txt.startswith("$'") and txt.endswith("'"):
                return txt[2:-1]
            return txt
        if t == "concatenation":
            return "".join(self._node_text(c, src) for c in node.children)
        if t in ("command_substitution", "process_substitution",
                 "arithmetic_expansion"):
            return SUBSTITUTION_PLACEHOLDER
        if t == "command_name":
            if len(node.children) == 1:
                return self._node_text(node.children[0], src)
            return self._slice(node, src)
        # word, number, simple_expansion, expansion, escape_sequence,
        # variable_name, etc.: surface text.
        return self._slice(node, src)

    def _reconstruct_string(self, node, src):
        out = []
        for c in node.children:
            if c.type == '"':
                continue
            if c.type in ("command_substitution", "process_substitution",
                          "arithmetic_expansion"):
                out.append(SUBSTITUTION_PLACEHOLDER)
            else:
                out.append(self._slice(c, src))
        return "".join(out)

    # --- Helpers ---

    def _redirect_writes_to_file(self, redirect_node, src):
        op = None
        target = None
        for c in redirect_node.children:
            if c.type in _WRITE_REDIR_OPS:
                op = c.type
            elif c.type == "word" and target is None:
                target = self._slice(c, src)
            elif c.type == "string" and target is None:
                target = self._reconstruct_string(c, src)
        if op is None:
            return False
        if target is None:
            return False
        if self._target_is_safe_write(target):
            return False
        return True

    def _target_is_safe_write(self, target):
        """Match `target` against the configured safe-write globs from
        rules/shell.json#safe_write_targets. Expands `~/` and `$HOME/`
        before matching so users who write `~/.cache/foo` and the rule
        `~/.cache/*` both line up. Uses fnmatch semantics."""
        expanded = self._expand_home(target)
        for pat in self.safe_write_targets:
            pat_expanded = self._expand_home(pat)
            if fnmatch(target, pat) or fnmatch(expanded, pat_expanded):
                return True
        return False

    @staticmethod
    def _expand_home(path):
        home = os.environ.get("HOME")
        if home and path.startswith("~/"):
            return home + path[1:]
        return path

    def _heredoc_body(self, heredoc_node, src):
        for c in heredoc_node.children:
            if c.type == "heredoc_body":
                return self._slice(c, src)
        return None

    def _classify_python(self, source, description):
        if self.python_analyzer_factory is None:
            return (DECISION_UNKNOWN, "python analyzer unavailable")
        analyzer = self.python_analyzer_factory()
        result = analyzer.analyze(source)
        if result.get("safe"):
            return (DECISION_SAFE, "python: {}".format(description))
        return (DECISION_UNSAFE, "python {}: {}".format(
            description, result.get("reason", "destructive call"),
        ))

    def _bash_inline_analyzer(self, script, depth):
        """Used by RuleClassifier for `bash -c <script>` interpreters."""
        return self.classify(script, _depth=depth)

    def _maybe_allow(self, match_string, result):
        decision, reason = result
        if decision == DECISION_SAFE:
            return result
        match = match_allow_patterns(match_string, self.allow_patterns)
        if match is None:
            return result
        return (DECISION_SAFE, "matches user allow pattern '{}'".format(match))

    @staticmethod
    def _suggest_allow_pattern_from_argv(argv):
        cmd_name = os.path.basename(argv[0])
        if cmd_name == "git":
            return GrammarClassifier._suggest_git_allow_pattern(argv)
        if cmd_name == "gh":
            return GrammarClassifier._suggest_gh_allow_pattern(argv)
        return None

    @staticmethod
    def _suggest_git_allow_pattern(argv):
        prefix = ["git"]
        i = 1
        if i + 1 < len(argv) and argv[i] == "-C":
            prefix.extend(["-C", "*"])
            i += 2

        if i >= len(argv) or argv[i].startswith("-"):
            return None

        sub = argv[i]
        if sub in {"add", "commit"}:
            return "Bash({} {}:*)".format(" ".join(prefix), sub)

        if sub != "push":
            return None

        hint = prefix + ["push"]
        j = i + 1
        if j < len(argv) and argv[j] == "-u":
            hint.append("-u")
            j += 1
        if j + 1 >= len(argv):
            return None

        remote = argv[j]
        branch = argv[j + 1]
        if remote != "origin":
            return None

        branch_pat = "feature/*" if branch.startswith("feature/") else branch
        hint.extend([remote, branch_pat])
        return "Bash({})".format(" ".join(hint))

    @staticmethod
    def _suggest_gh_allow_pattern(argv):
        if len(argv) < 3:
            return None

        namespace = argv[1]
        action = argv[2]
        allowed = {
            "pr": {"create", "comment", "edit", "merge", "ready"},
            "issue": {"create", "comment", "edit"},
        }
        if action in allowed.get(namespace, set()):
            return "Bash(gh {} {}:*)".format(namespace, action)
        return None

    @staticmethod
    def _slice(node, src):
        return src[node.start_byte:node.end_byte].decode("utf-8", "replace")

    @staticmethod
    def _first_child(node, type_name):
        for c in node.children:
            if c.type == type_name:
                return c
        return None


def classify_command(command, rules, python_analyzer_factory=None, allow_patterns=None):
    """Module-level convenience wrapper."""
    classifier = GrammarClassifier(
        rules,
        python_analyzer_factory=python_analyzer_factory,
        allow_patterns=allow_patterns,
    )
    return classifier.classify(command)


def run_cli():
    """CLI: read a shell command from argv and print its classification."""
    if len(sys.argv) < 2:
        print("Usage: grammar_classifier.py '<shell command>'", file=sys.stderr)
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

    # Python analyzer factory — lazy import so this CLI works without
    # the rule data dir for python rules.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from yolt_analyzer import SafetyAnalyzer, load_rules as load_py_rules

    py_rules = load_py_rules(
        rules_dir=yolt_dir / "rules",
        user_overrides_path=Path.home() / ".claude" / "yolt" / "rules.json",
    )

    def factory():
        return SafetyAnalyzer(py_rules)

    decision, reason = classify_command(
        command,
        rules,
        python_analyzer_factory=factory,
        allow_patterns=allow_patterns,
    )

    print(json.dumps({"decision": decision, "reason": reason}, indent=2))
    sys.exit(0)


if __name__ == "__main__":
    run_cli()
