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
    _expand_home,
    DECISION_SAFE, DECISION_UNSAFE, DECISION_UNKNOWN,
    SUBSTITUTION_PLACEHOLDER,
    RuleClassifier,
    aggregate_decisions,
    load_allow_patterns,
    load_shell_rules,
    match_allow_patterns,
)


_BASH_LANG = Language(_tsb.language())

# Redirect-target node types that carry readable surface text. A
# `concatenation` is the `$HOME/path` shape; the expansions are a bare
# `$VAR` target, which resolves to no known-safe glob and so costs a prompt.
_REDIR_TARGET_NODES = ("concatenation", "simple_expansion", "expansion")

# A write redirect whose target could not be read. Distinct from None, which
# means "not a write redirect at all" -- see #128.
UNEXTRACTABLE_WRITE_TARGET = object()

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
        self.unsafe_write_targets = list(rules.get("unsafe_write_targets", []))
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
        write_targets = []
        unreadable_target = False
        for c in self._file_redirects(node):
            t = self._redirect_write_target(c, src)
            if t is UNEXTRACTABLE_WRITE_TARGET:
                unreadable_target = True
            elif t is not None:
                write_targets.append(t)
        # Evaluate EVERY write redirect with unsafe > unknown > safe
        # precedence. A safe first redirect must not mask a later unsafe or
        # unknown target -- e.g. `echo x > /tmp/ok > ~/.bashrc` and
        # `echo x > /tmp/ok 2> ~/.bashrc` both still write ~/.bashrc.
        # Deny list is checked before the safe list, so a protected path
        # (e.g. ~/.claude/settings.json) overrides a broader safe glob
        # (~/.claude/*) and classifies unsafe.
        unsafe_target = next(
            (t for t in write_targets if self._target_is_unsafe_write(t)),
            None,
        )
        if unsafe_target is not None:
            seg = self._slice(node, src)
            decisions.append(self._maybe_allow(
                seg, (DECISION_UNSAFE,
                      "writes to protected path '{}' via redirection".format(
                          unsafe_target)),
            ))
            # Symmetric with the unknown branch below: record and continue.
            # Returning here masked the command's own reason --
            # `rm -rf /tmp/x > ~/.bashrc` reported only the redirect, never
            # `rm: mutating`. The verdict was unsafe either way, so this was
            # never a security gap, but the reason is not decoration:
            # `scripts/replay_unsafe.py` groups the corpus BY reason, and
            # #100 drafts the non-delegable list from that grouping. A masked
            # `rm: mutating` under-counts rm in the measurement that decides
            # what Phase 3 deletes.
        if unreadable_target or any(
            not self._target_is_safe_write(t) for t in write_targets
        ):
            seg = self._slice(node, src)
            decisions.append(self._maybe_allow(
                seg, (DECISION_UNKNOWN, "writes to a file via redirection"),
            ))
            # Deliberately NOT returning. An unknown redirect target must not
            # mask the command's own verdict: `terraform destroy ... > $LOG`
            # is `terraform destroy: mutating` first and an unclassifiable
            # redirect second. Returning here dropped the destroy entirely,
            # and aggregation already ranks unsafe above unknown, so falling
            # through yields the stricter of the two rather than whichever
            # was noticed first.
            #
            # This was latent before #128: an unreadable target was dropped,
            # write_targets came back empty, and the command got classified
            # by accident. Reading the target correctly is what exposed it.
        # All write targets safe (or none): fall through and classify the
        # command itself.

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
        """Rebuild the value of a double-quoted string from its children.

        The bytes between two adjacent children are part of the string and
        have to be carried across (#115). tree-sitter-bash ends a
        `string_content` run at a newline and starts a fresh one after it,
        so a multi-line `"..."` arrives as one child per line with the
        newlines belonging to no child at all. Concatenating only the
        children welds every line onto the next: a multi-line
        `python3 -c "..."` reached the Python analyzer as a single line,
        `ast.parse` raised on it, and the inline path turned that into
        "could not statically analyze inline python3 -c script (parser
        bailed at line 1)" -- for every such command, since after the weld
        there is only ever a line 1. The gate then parked read-only scripts
        for a human, which is the safe direction but the wrong answer.

        Gap bytes are copied verbatim rather than normalized to "\n": what
        is uncovered is literal string text, and the analyzer downstream
        wants it exactly as the shell would pass it."""
        out = []
        prev_end = None
        for c in node.children:
            if prev_end is not None and c.start_byte > prev_end:
                out.append(src[prev_end:c.start_byte].decode("utf-8", "replace"))
            prev_end = c.end_byte
            if c.type == '"':
                continue
            if c.type in ("command_substitution", "process_substitution",
                          "arithmetic_expansion"):
                out.append(SUBSTITUTION_PLACEHOLDER)
            else:
                out.append(self._slice(c, src))
        return "".join(out)

    # --- Helpers ---

    @staticmethod
    def _file_redirects(node):
        """Every `file_redirect` belonging to this statement.

        A heredoc nests its redirect one level deeper than a plain one:

            redirected_statement
              command            'cat'
              heredoc_redirect   "<<'X' > ~/.ssh/authorized_keys"
                file_redirect      '> ~/.ssh/authorized_keys'

        A scan of direct children alone therefore finds nothing for
        `cat <<'X' > target`, the write target never reaches the deny list,
        and the statement is judged on the verb -- so `cat` reported
        `read-only` for a command installing an SSH key, and the hook
        granted it. Issue #136.
        """
        retval = []
        for child in node.children:
            if child.type == "file_redirect":
                retval.append(child)
            elif child.type == "heredoc_redirect":
                retval.extend(
                    g for g in child.children if g.type == "file_redirect"
                )
        return retval

    def _redirect_write_target(self, redirect_node, src):
        """Return the target path of a write redirect (`> FILE`, `>> FILE`),
        or None if this redirect is not a write. The caller classifies the
        target's tier (unsafe / safe / unknown); this only extracts it."""
        op = None
        target = None
        for c in redirect_node.children:
            if c.type in _WRITE_REDIR_OPS:
                op = c.type
            elif target is not None:
                continue
            elif c.type == "word":
                target = self._slice(c, src)
            elif c.type == "string":
                target = self._reconstruct_string(c, src)
            elif c.type == "raw_string":
                # `> '/path/with space'` parses as a `raw_string`. Single
                # quotes suppress every expansion, so unlike a `string` the
                # content needs no reconstruction -- only the quotes come
                # off. Until #132 this matched no branch, the target stayed
                # None, and quoting a protected path was enough to turn an
                # `ask` into silence.
                target = self._slice(c, src).strip("'")
            elif c.type in _REDIR_TARGET_NODES:
                # `> $HOME/.ssh/authorized_keys` parses as a `concatenation`,
                # not a `word`. Before #128 neither branch matched, the
                # target stayed None, and the caller read that as "not a
                # write redirect" -- so the redirect was dropped entirely and
                # the line was judged on `echo` alone. Take the surface text
                # and let `_expand_home` resolve it.
                target = self._slice(c, src)
        if op is None:
            return None
        if target is None:
            # A write redirect whose target this cannot read. NOT the same as
            # "no write redirect", and that conflation is what made #128 a
            # grant rather than a prompt. Any node shape nobody anticipated
            # lands here and must cost friction, never silence.
            return UNEXTRACTABLE_WRITE_TARGET
        return target

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

    def _target_is_unsafe_write(self, target):
        """Match `target` against rules/shell.json#unsafe_write_targets --
        dotfile / config / startup paths dangerous enough to classify
        unsafe (ask with a specific reason) rather than unknown. Same
        fnmatch + `~/`-expansion semantics as `_target_is_safe_write`.
        Checked before the safe list so an entry here overrides a broader
        safe glob (the ~/.claude/settings.json carve-out)."""
        expanded = self._expand_home(target)
        for pat in self.unsafe_write_targets:
            pat_expanded = self._expand_home(pat)
            if fnmatch(target, pat) or fnmatch(expanded, pat_expanded):
                return True
        return False

    # The rule layer's function, not a copy of it. These two had identical
    # bodies and identical blind spots, so #128 was open in both places and
    # fixing either alone would have left the other.
    _expand_home = staticmethod(_expand_home)

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
            return "Bash({} {}*)".format(" ".join(prefix), sub)

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

        # Mapped push (`git push origin <local>:<remote>`) carries the
        # full `local:remote` refspec in `branch`. Generalize only the
        # remote side to `feature/*` so the hint covers the branch family,
        # not a single literal pair. See issue #37.
        if ":" in branch:
            local, remote_ref = branch.split(":", 1)
            if remote_ref.startswith("feature/"):
                branch_pat = "{}:feature/*".format(local)
            else:
                branch_pat = "{}:{}".format(local, remote_ref)
        elif branch.startswith("feature/"):
            branch_pat = "feature/*"
        else:
            branch_pat = branch
        hint.extend([remote, branch_pat])
        return "Bash({})".format(" ".join(hint))

    @staticmethod
    def _suggest_gh_allow_pattern(argv):
        if len(argv) < 3:
            return None

        namespace = argv[1]
        action = argv[2]
        allowed = {
            "pr": {"create", "comment", "edit", "merge", "ready",
                   "review", "update-branch"},
            "issue": {"create", "comment", "edit", "close", "reopen"},
        }
        if action in allowed.get(namespace, set()):
            return "Bash(gh {} {}*)".format(namespace, action)
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
    """CLI: read a shell command from argv and print its classification.

    `--no-user-allow` drops the Claude Code settings files from the allow-pattern
    sources. They are permissions a human wrote for an interactive terminal, and
    a consumer that is not that terminal -- a service classifying commands on
    behalf of whoever can talk to it -- inherits them silently otherwise, so its
    auto-run set is whatever the operator once allowed themselves. That is a
    confused deputy, and only the consumer knows which it is; the Claude Code
    hook keeps the default.
    """
    argv = [a for a in sys.argv[1:] if a != "--no-user-allow"]
    no_user_allow = len(argv) != len(sys.argv) - 1
    if not argv:
        print(
            "Usage: grammar_classifier.py [--no-user-allow] '<shell command>'",
            file=sys.stderr,
        )
        sys.exit(1)

    command = argv[0]
    yolt_dir = Path(__file__).resolve().parent.parent
    rules = load_shell_rules(
        rules_dir=yolt_dir / "rules",
        user_overrides_path=Path.home() / ".claude" / "yolt" / "shell.json",
    )

    cwd = Path.cwd()
    allow_patterns = [] if no_user_allow else load_allow_patterns([
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

    # How many allow patterns were in play is part of the verdict's meaning: the
    # same command classifies differently under a different settings file, and
    # without this a consumer cannot see -- or log at startup -- how large the
    # inherited auto-run surface is.
    print(json.dumps(
        {"decision": decision, "reason": reason, "allow_patterns": len(allow_patterns)},
        indent=2,
    ))
    sys.exit(0)


if __name__ == "__main__":
    run_cli()
