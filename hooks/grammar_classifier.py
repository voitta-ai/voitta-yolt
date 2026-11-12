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

import codecs
import itertools
import json
import os
import re
import sys
from fnmatch import fnmatch
from pathlib import Path

import tree_sitter_bash as _tsb
from tree_sitter import Language, Parser

from rule_classifier import (
    _expand_home,
    _is_unresolved_path,
    _write_target_note,
    _path_matches_safe_write_targets,
    _path_matches_target_list,
    DECISION_SAFE, DECISION_UNSAFE, DECISION_UNKNOWN, DECISION_DENY,
    CWD_UNRESOLVED,
    SUBSTITUTION_PLACEHOLDER,
    WRITE_CWDS,
    RuleClassifier,
    aggregate_decisions,
    load_shell_rules,
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

_VAR_REF_RE = re.compile(
    r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")
# Expansions `_expand_home` resolves from the environment when the line
# never spells them. A line that does spell one leaves it unresolved: which
# binding is in force at the write (an assignment, `unset`, `read`, ...) is
# not something this reads.
_ENV_PATH_VARS = {"HOME", "TMPDIR"}
# Shell values that are always digits, so they cannot carry `/` or `..`
# out of the directory a target names.
_DIGIT_PARAMS_RE = re.compile(r"\$(?:[$!?#]|\{[$!?#]\})")
_DIGIT_VARS = {"RANDOM", "PPID", "SECONDS", "LINENO", "UID", "EUID"}
# Names the shell itself sets or reads (`read`, `cd`, `getopts`, word
# splitting, ...): never resolved from an assignment on the line.
_SHELL_MANAGED_VARS = {
    "REPLY", "OPTARG", "OPTIND", "MAPFILE", "PWD", "OLDPWD", "IFS",
    "CDPATH", "PATH", "COPROC", "PIPESTATUS", "FUNCNAME", "GROUPS", "_",
}
# Commands that can bind any variable out of sight of a static reading.
_VAR_OPAQUE_COMMANDS = {"eval", "source", ".", "trap"}
# Builtins that bind the variable named by an argument. Their arguments
# must be plain words, or the name may be assembled where `_spelled`
# cannot see it (`read F\OO`, `declare ${X}OO=...`).
_VAR_BINDING_COMMANDS = {
    "read", "mapfile", "readarray", "getopts", "unset", "printf", "let",
    "select", "export", "declare", "typeset", "local", "readonly",
}
# Prefixes that run the next word as the command (`builtin unset X`,
# `time read X`); their own options are skipped.
_VAR_PREFIX_COMMANDS = {"builtin", "command", "time"}
_PLAIN_WORD_RE = re.compile(r"^[A-Za-z0-9_%./:=+,@-]*$")
_MAX_VAR_VALUES = 16
_MAX_VAR_DEPTH = 8
_MKTEMP_SAFE_FLAGS = {"-d", "-q", "-u", "--directory", "--quiet", "--dry-run"}

_WRITE_REDIR_OPS = {">", ">>", "&>", "&>>", "1>", "1>>", "2>", "2>>",
                    ">|", ">&"}


class GrammarClassifier:
    """Top-level classifier. Parses Bash via tree-sitter, walks the AST,
    and aggregates per-command decisions."""

    MAX_RECURSION_DEPTH = 8

    def __init__(self, rules, python_analyzer_factory=None, cwd=None,
                 policy=None):
        self.rules = rules
        self.python_analyzer_factory = python_analyzer_factory
        # The shell's directory when the command starts, and the deny
        # policy that may consult git state there. `_cwd` is re-derived per
        # `classify()` call because a leading `cd` moves it.
        self.cwd = cwd
        self.policy = policy
        self._cwd = cwd
        self.safe_write_targets = list(rules.get("safe_write_targets", ["/dev/null"]))
        self.unsafe_write_targets = list(rules.get("unsafe_write_targets", []))
        self._rules = RuleClassifier(
            rules,
            python_analyzer_factory=python_analyzer_factory,
            bash_analyzer=self._bash_inline_analyzer,
        )
        self._parser = Parser(_BASH_LANG)
        self._vars = None

    # --- Public API ---

    def classify(self, command, _depth=0):
        if _depth > self.MAX_RECURSION_DEPTH:
            return (DECISION_UNSAFE, "max recursion depth")
        if not command or not command.strip():
            return (DECISION_SAFE, "empty")

        src = command.encode("utf-8")
        tree = self._parser.parse(src)
        root = tree.root_node

        # Bash runs what the grammar cannot parse -- an unterminated
        # heredoc only warns, and a line the grammar rejects may be one bash
        # accepts. Unknown would be silence in the hook, so it asks.
        if root.has_error:
            return (DECISION_UNSAFE, "tree-sitter parse error")

        cwds_token = None
        if _depth == 0:
            self._cwd = self.cwd
            cwds_token = WRITE_CWDS.set(
                (os.path.abspath(self.cwd),) if self.cwd else None)

        # Each parse has its own variables: a `bash -c` body cannot see
        # the outer line's assignments, and must not replace them.
        outer_vars = self._vars
        self._vars = self._scan_variables(root, src)
        try:
            decisions = []
            self._walk(root, src, decisions, _depth)
        finally:
            self._vars = outer_vars
            if cwds_token is not None:
                WRITE_CWDS.reset(cwds_token)
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
        # What the redirects themselves run: a substitution in a target
        # (`> $(cmd)`, `< $(cmd)`, `2> >(cmd)`), a substitution in an
        # unquoted heredoc body, and a command chained after the heredoc
        # start (`cat <<EOF | sh`), which the grammar nests inside the
        # heredoc redirect.
        for c in node.children:
            if c.type == "file_redirect":
                self._collect_substitutions(c, src, decisions, _depth + 1)
            elif c.type == "heredoc_redirect":
                self._walk_heredoc_redirect(c, src, decisions, _depth)
        # The grammar hangs a trailing redirect on a whole `&&` list
        # (`cd /etc && echo hi > hosts`), so the target is judged before the
        # walk reaches the `cd`s in front of it. Directories only accumulate,
        # so taking them in now is safe for every shape.
        for cd in self._cd_commands(node):
            self._track_write_cwds(self._argv_from_command(cd, src))
        write_targets = []
        unresolved_target = None
        for c in self._file_redirects(node):
            t = self._redirect_write_target(c, src)
            if t is UNEXTRACTABLE_WRITE_TARGET:
                unresolved_target = self._slice(c.children[-1], src)
            elif t is not None:
                resolved = self._resolve_vars(t, c.start_byte)
                if resolved is None:
                    unresolved_target = t
                else:
                    write_targets.extend(resolved)
        # A target this cannot resolve to a path -- a variable the line
        # does not assign, a substitution, a node shape nobody anticipated
        # -- can name any file, protected ones included. Unknown would be
        # silence in the hook, so it asks.
        if unresolved_target is None:
            unresolved_target = next(
                (t for t in write_targets if _is_unresolved_path(t)), None)
        if unresolved_target is not None:
            decisions.append(
                (DECISION_UNSAFE,
                 "writes to a path that cannot be resolved statically "
                 "'{}' via redirection".format(unresolved_target)),
            )
            write_targets = [
                t for t in write_targets if not _is_unresolved_path(t)]
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
            decisions.append(
                (DECISION_UNSAFE,
                 ("writes to protected path '{}' via redirection"
                  if _write_target_note(unsafe_target) == "protected path"
                  else "writes to a path that cannot be resolved statically "
                  "'{}' via redirection").format(unsafe_target)),
            )
            # Symmetric with the unknown branch below: record and continue.
            # Returning here masked the command's own reason --
            # `rm -rf /tmp/x > ~/.bashrc` reported only the redirect, never
            # `rm: mutating`. The verdict is unsafe either way, so this was
            # never a security gap, but the reason is not decoration:
            # `scripts/replay_unsafe.py` groups the corpus BY reason and #100
            # drafts the non-delegable list from that grouping.
        # A target already reported as unsafe must not ALSO be reported as
        # unclassifiable: an unsafe target is not a safe one, so the bare
        # `not safe` test fired for it too and one redirect recorded two
        # decisions. Aggregation picked the right verdict either way, which
        # is why it was invisible, but "writes to a protected path" and
        # "could not be classified" are contradictory claims about the same
        # token.
        if any(
            not self._target_is_safe_write(t)
            and not self._target_is_unsafe_write(t)
            for t in write_targets
        ):
            decisions.append(
                (DECISION_UNKNOWN, "writes to a file via redirection"),
            )
            # Deliberately NOT returning. An unknown redirect target must not
            # mask the command's own verdict: `terraform destroy ... > $LOG`
            # is `terraform destroy: mutating` first and an unclassifiable
            # redirect second. Aggregation already ranks unsafe above unknown,
            # so falling through yields the stricter of the two rather than
            # whichever was noticed first.
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
        argv = [self._resolve_arg(a, node.start_byte) for a in argv]

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

        # A literal `cd` moves the directory the policy layer will judge,
        # and it has to be tracked before the sibling commands are
        # classified: `cd <repo> && git push` is the whole reason this
        # exists.
        if cmd_name == "cd":
            self._track_cd(argv)

        result = self._rules.classify_tokens(argv)
        result = self._maybe_deny_by_policy(argv, result)
        if sub_decisions:
            return aggregate_decisions(sub_decisions + [result])
        return result

    def _cd_commands(self, node):
        """Every `cd` command in a redirected statement's body."""
        out, stack = [], [c for c in node.children
                          if c.type not in ("file_redirect", "heredoc_redirect")]
        while stack:
            n = stack.pop()
            if n.type == "command":
                name = self._first_child(n, "command_name")
                if name is not None and name.text == b"cd":
                    out.append(n)
            stack.extend(n.children)
        return out

    def _track_write_cwds(self, argv):
        """Add the directory a `cd` may move to to WRITE_CWDS, the set a
        relative write target is judged against. Every directory the line
        may be in is kept, not only the last: the walk is in source order,
        but a `cd` in a subshell, a branch or a failed `cd` leaves the
        shell where it was. One the walker cannot resolve makes every
        later relative target unresolved."""
        cwds = WRITE_CWDS.get()
        if cwds is None or cwds == CWD_UNRESOLVED:
            return
        args = [a for a in argv[1:] if a != "--"]
        args = [a for a in args if not (a.startswith("-") and a != "-")]
        target = args[0] if args else "~"
        if target == "~" or target.startswith("~/"):
            home = os.environ.get("HOME")
            if not home or self._vars is None or not self._env_var_ok("HOME"):
                WRITE_CWDS.set(CWD_UNRESOLVED)
                return
            target = home + target[1:]
        if target == "-" or target.startswith("~") or any(
                ch in target for ch in "$`*{}?[") \
                or SUBSTITUTION_PLACEHOLDER in target:
            WRITE_CWDS.set(CWD_UNRESOLVED)
            return
        added = [os.path.normpath(os.path.join(c, target)) for c in cwds]
        merged = tuple(dict.fromkeys(cwds + tuple(added)))
        WRITE_CWDS.set(merged if len(merged) <= _MAX_VAR_VALUES
                       else CWD_UNRESOLVED)

    def _track_cd(self, argv):
        """Follow a literal `cd` so the policy layer judges the directory
        the later commands actually run in.

        `cd /path/to/worktree && git push --force` is the shape this exists
        for. Anything the walker cannot resolve statically -- an expansion,
        `cd -`, a substitution -- sets the tracked directory to None, which
        disables the policy for the rest of the invocation rather than
        letting it judge the wrong tree.
        """
        # `cd -` is the previous directory, which no static walk can know.
        # It has to be tested BEFORE flags are filtered out, or it is
        # discarded as a flag and `cd -` silently resolves to $HOME -- which
        # is both wrong and the opposite of unresolvable.
        self._track_write_cwds(argv)
        raw = argv[1:]
        if "-" in raw:
            self._cwd = None
            return
        args = [a for a in raw if not a.startswith("-")]
        if not args:
            self._cwd = os.path.expanduser("~")
            return
        target = args[0]
        # Anything the walker cannot resolve to one literal path. Brace
        # expansion and `?` are here for completeness rather than risk:
        # an unexpanded `{a,b}` would not exist on disk, so the probe would
        # fail and deny nothing either way. Marking it explicitly keeps the
        # unresolvable set a statement of intent instead of a list of the
        # cases someone happened to think of.
        if any(ch in target for ch in "$`*{}?"):
            self._cwd = None
            return
        target = os.path.expanduser(target)
        if os.path.isabs(target):
            self._cwd = target
        elif self._cwd is not None:
            self._cwd = os.path.normpath(os.path.join(self._cwd, target))

    def _maybe_deny_by_policy(self, argv, result):
        """Give the policy layer a chance to upgrade `unsafe` -> `deny`.

        Only `unsafe` is offered. The policy exists to refuse a narrow set
        of writes the static rules already flagged; it must never be able
        to reach something the rules cleared, so `safe` and `unknown` are
        not routed through it.

        What a `None` from the policy means, since it is the common case
        and the reason this is safe:

            SOLO          -> no deny; `unsafe` stands, operator is asked
            UNDETERMINED  -> no deny; `unsafe` stands, operator is asked
            SHARED        -> deny

        `UNDETERMINED` is not a pessimistic default or a retry signal. It
        is every probe failure -- git missing, `user.email` unset, remote
        never fetched, timeout, garbled output -- and it deliberately lands
        in the same bucket as SOLO. The ancestor of this policy (#82) used
        the same probes to *grant*, where collapsing "definitely not" into
        "cannot tell" was safe. Inverted it is not: an unset `user.email`
        read as SHARED would deny every force push in the repository.

        See `git_policy.authorship`, and the tests in
        `tests/test_git_policy.py` -- `FailedProbeNeverDenies` at the
        policy layer, `ProbeFailureNeverDeniesThroughTheClassifier` at this
        one.
        """
        if self.policy is None or result[0] != DECISION_UNSAFE:
            return result
        reason = self._policy_reason(argv, 0)
        if reason is None:
            return result
        return (DECISION_DENY, reason)

    def _policy_reason(self, argv, _depth):
        """The policy's deny reason for `argv` or for any command a wrapper
        in it may run (`env`, `nice`, `timeout`, `command`, ...), read at
        the same start positions the rule classifier classifies (#178)."""
        reason = self.policy.evaluate(argv, self._cwd)
        if reason is not None or _depth > self.MAX_RECURSION_DEPTH:
            return reason
        cmd_name = os.path.basename(argv[0])
        spec = self._rules.commands.get(cmd_name)
        if not spec or spec.get("default") != "delegate_to_argument":
            return None
        readings = self._rules.delegate_starts(cmd_name, argv[1:], spec)
        if readings is None:
            return None
        for s in readings[0]:
            reason = self._policy_reason(argv[1 + s:], _depth + 1)
            if reason is not None:
                return reason
        return None

    def _walk_heredoc_redirect(self, node, src, decisions, _depth):
        """Classify what a heredoc redirect runs besides its target, which
        `_walk_redirected` judges with the other write targets."""
        start = self._first_child(node, "heredoc_start")
        quoted = start is not None and any(
            ch in self._slice(start, src) for ch in "'\"\\")
        for c in node.children:
            if c.type == "file_redirect":
                self._collect_substitutions(c, src, decisions, _depth + 1)
            elif c.type == "heredoc_body":
                if quoted:
                    continue
                subs = []
                self._collect_substitutions(c, src, subs, _depth + 1)
                decisions.extend(subs)
                # The grammar does not parse every substitution in a body
                # (backticks, `<<-` bodies), and the shell runs them all.
                body = self._slice(c, src)
                parsed = self._count_nodes(c, "command_substitution")
                if "`" in body or body.count("$(") > parsed:
                    decisions.append(
                        (DECISION_UNSAFE,
                         "heredoc body runs a command substitution that "
                         "could not be parsed"))
            elif c.type not in ("heredoc_start", "heredoc_end"):
                self._walk(c, src, decisions, _depth)

    @staticmethod
    def _count_nodes(node, node_type):
        count, stack = 0, [node]
        while stack:
            n = stack.pop()
            count += n.type == node_type
            stack.extend(n.children)
        return count

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
            elif c.type == "number" and op == ">&":
                # `>&2`, `2>&1`: duplicates a descriptor, writes no file.
                return None
            elif c.type == "word":
                target = self._slice(c, src)
            elif c.type == "concatenation":
                # `"$HOME"/.bashrc`, `~/".bashrc"`: the quotes are not part
                # of the path, and left in they kept it off both lists.
                target = self._unquote_concatenation(c, src)
            elif c.type == "string":
                target = self._reconstruct_string(c, src)
            elif c.type in ("ansi_c_string", "translated_string"):
                target = self._dollar_quoted_text(c, src)
            elif c.type == "raw_string":
                # `> '/path/with space'` parses as a `raw_string`. Single
                # quotes suppress every expansion, so unlike a `string` the
                # content needs no reconstruction -- only the quotes come
                # off. Until #132 this matched no branch, the target stayed
                # None, and quoting a protected path turned an `ask` into
                # silence.
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

    def _unquote_concatenation(self, node, src):
        """The path a concatenation names, with each quoted part's quotes
        removed. Expansions stay as written for `_expand_home`."""
        parts = []
        for c in node.children:
            if c.type == "string":
                parts.append(self._reconstruct_string(c, src))
            elif c.type == "raw_string":
                parts.append(self._slice(c, src)[1:-1])
            elif c.type in ("ansi_c_string", "translated_string"):
                parts.append(self._dollar_quoted_text(c, src))
            elif c.type == "$":
                # `~/$".bashrc"` splits into word, `$`, string: the `$` is
                # the locale-translation marker, not part of the path.
                continue
            else:
                parts.append(self._slice(c, src))
        return "".join(parts)

    def _dollar_quoted_text(self, node, src):
        """The value of `$'...'` (escapes decoded) or `$"..."`."""
        if node.type == "translated_string":
            inner = [c for c in node.children if c.type == "string"]
            return self._reconstruct_string(inner[0], src) if inner else self._slice(node, src)
        body = self._node_text(node, src)
        try:
            return codecs.decode(body, "unicode_escape")
        except (UnicodeDecodeError, ValueError):
            return body

    # --- Variables ---
    #
    # A write target that holds `$NAME` is judged on the values the line
    # itself gives NAME, and only in one shape: NAME is spelled exactly once
    # on the line other than as `$NAME` / `${NAME}`, and that once is a
    # literal assignment at the top level (or a `for NAME in` over literal
    # words, for uses in its body). Any other way a name can be bound --
    # `read`, `unset`, `printf -v`, `declare -n`, `${NAME:=...}`, a trap, a
    # wrapped builtin -- spells it a second time and leaves it unresolved,
    # which asks. Guessing which of several bindings is in force is what
    # this deliberately does not do.

    def _scan_variables(self, root, src):
        """`{"text": source, "opaque": bool, "nodes": {name: node}}` for
        `_resolve_vars`; `nodes` holds the single binding node per name."""
        text = src.decode("utf-8", "replace")
        scope = {"text": text, "opaque": False, "nodes": {}, "memo": {}}
        stack = [root]
        while stack:
            n = stack.pop()
            stack.extend(n.children)
            if n.type == "command":
                if self._may_bind_unseen(n, src):
                    scope["opaque"] = True
            elif n.type == "unset_command":
                if any(c.type != "word" or not _PLAIN_WORD_RE.match(self._slice(c, src))
                       for c in n.children[1:]):
                    scope["opaque"] = True
            elif n.type == "declaration_command":
                for c in n.children[1:]:
                    if c.type == "variable_assignment":
                        first = c.children[0] if c.children else None
                        if first is None or first.type != "variable_name":
                            scope["opaque"] = True
                    elif c.type not in ("variable_name", "word") or not \
                            _PLAIN_WORD_RE.match(self._slice(c, src)):
                        scope["opaque"] = True
            elif n.type == "variable_assignment" and self._is_top_level_assignment(n):
                first = n.children[0] if n.children else None
                if first is not None and first.type == "variable_name" \
                        and "=" in [c.type for c in n.children]:
                    scope["nodes"].setdefault(self._slice(first, src), []).append(n)
            elif n.type == "for_statement":
                c = self._first_child(n, "variable_name")
                if c is not None:
                    scope["nodes"].setdefault(self._slice(c, src), []).append(n)
        return scope

    def _may_bind_unseen(self, node, src):
        """Whether this command could bind a variable under a name the
        line never spells as one token: `eval` / `source` / `trap` in any
        spelling, a command whose name is not a plain word, or a binding
        builtin with an argument that is not a plain word."""
        words = [c for c in node.children if c.type != "variable_assignment"]
        if not words:
            return False
        head = words[0]
        head_text = self._slice(head, src)
        if head.type != "command_name" or not _PLAIN_WORD_RE.match(head_text):
            return True
        names = [os.path.basename(head_text)]
        args = words[1:]
        while names[-1] in _VAR_PREFIX_COMMANDS:
            while args and self._slice(args[0], src).startswith("-"):
                args = args[1:]
            if not args:
                break
            if args[0].type != "word" or not _PLAIN_WORD_RE.match(self._slice(args[0], src)):
                return True
            names.append(os.path.basename(self._slice(args[0], src)))
            args = args[1:]
        if any(n in _VAR_OPAQUE_COMMANDS for n in names):
            return True
        if names[-1] in _VAR_BINDING_COMMANDS:
            if names[-1] == "printf" and not any(
                    re.match(r"^-[A-Za-z]*v", self._slice(a, src)) for a in args):
                return False
            return any(a.type != "word" or not _PLAIN_WORD_RE.match(self._slice(a, src))
                       for a in args)
        return False

    @staticmethod
    def _is_top_level_assignment(node):
        """A statement of its own at the top of the line, in the
        foreground: `NAME=v;` or `export NAME=v;`. Not a prefix (`NAME=v
        cmd`), not in a chain, branch, loop, pipeline, subshell, function,
        and not followed by `&`."""
        n = node
        if n.parent is not None and n.parent.type == "declaration_command":
            keyword = n.parent.children[0].type if n.parent.children else ""
            if keyword != "export" or any(
                    c.type == "word" for c in n.parent.children):
                return False
            n = n.parent
        if n.parent is None or n.parent.type != "program":
            return False
        nxt = n.next_sibling
        return nxt is None or nxt.type != "&"

    def _for_words(self, node, src):
        """The values a `for NAME in WORDS` loop binds: each literal word,
        or None when the list is absent (positional parameters) or any word
        expands, globs or substitutes."""
        words = []
        seen_in = False
        for c in node.children:
            if c.type == "in":
                seen_in = True
            elif c.type in (";", "do_group", "\n"):
                break
            elif seen_in:
                if c.type == "word" and not any(ch in "*?[{$`\\" for ch in self._slice(c, src)):
                    words.append(self._slice(c, src))
                elif c.type == "raw_string":
                    words.append(self._slice(c, src)[1:-1])
                else:
                    return None
        return words if seen_in and words else None

    def _assignment_value(self, node, src):
        """The literal text an assignment stores, `$NAME` references kept
        for `_resolve_vars`, or None when it is not literal."""
        t = node.type
        if t == "command_substitution":
            return self._mktemp_value(node, src)
        stack = [node]
        while stack:
            n = stack.pop()
            if n.type in ("command_substitution", "process_substitution",
                          "arithmetic_expansion", "brace_expression"):
                return None
            stack.extend(n.children)
        if t in ("word", "simple_expansion", "expansion", "number"):
            return self._slice(node, src)
        if t == "string":
            return self._reconstruct_string(node, src)
        if t == "raw_string":
            return self._slice(node, src)[1:-1]
        if t == "concatenation":
            return self._unquote_concatenation(node, src)
        return None

    def _mktemp_value(self, node, src):
        """A stand-in for what `$(mktemp ...)` prints: a fresh name under
        $TMPDIR (or /tmp). None for any form that can place it elsewhere --
        a template argument, `-p DIR`, `--tmpdir`."""
        cmds = [c for c in node.children if c.type == "command"]
        if len(cmds) != 1 or len(node.named_children) != 1:
            return None
        argv = self._argv_from_command(cmds[0], src)
        if not argv or os.path.basename(argv[0]) != "mktemp":
            return None
        args = argv[1:]
        i = 0
        while i < len(args):
            a = args[i]
            if a in _MKTEMP_SAFE_FLAGS:
                i += 1
            elif a == "-t" and i + 1 < len(args) and "/" not in args[i + 1]:
                i += 2
            else:
                return None
        if not self._env_var_ok("TMPDIR"):
            return None
        base = os.environ.get("TMPDIR") or "/tmp"
        return base.rstrip("/") + "/mktemp.XXXXXXXX"

    def _spelled(self, name):
        """How often the line spells `name` other than as `$name` or
        `${name}` -- every place it could be bound, and then some."""
        memo = self._vars["memo"]
        if ("#", name) not in memo:
            text = self._vars["text"]
            word = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(name)
                              + r"(?![A-Za-z0-9_])")
            refs = re.compile(r"\$" + re.escape(name) + r"(?![A-Za-z0-9_])|\$\{"
                              + re.escape(name) + r"\}")
            # `printf -vNAME` glues the name to the option.
            glued = re.compile(r"-[A-Za-z]*v[\"']?" + re.escape(name)
                               + r"(?![A-Za-z0-9_])")
            memo[("#", name)] = (len(word.findall(text))
                                 - len(refs.findall(text))
                                 + len(glued.findall(text)))
        return memo[("#", name)]

    def _env_var_ok(self, name):
        """Whether `$name` (HOME, TMPDIR) can be left for `_expand_home`
        to read from the environment: nothing on the line can rebind it."""
        return not self._spelled(name) and not self._vars["opaque"]

    def _name_values(self, name, pos, depth, src):
        """The values `name` may hold at byte `pos`, or None."""
        scope = self._vars
        if name in _SHELL_MANAGED_VARS or scope["opaque"]:
            return None
        nodes = scope["nodes"].get(name, [])
        if self._spelled(name) != 1 or len(nodes) != 1:
            return None
        node = nodes[0]
        if node.type == "for_statement":
            body = self._first_child(node, "do_group")
            if body is None or not (body.start_byte <= pos < body.end_byte):
                return None
            return self._for_words(node, src)
        if node.end_byte > pos:
            return None
        rest = node.children[2:]
        value = self._assignment_value(rest[0], src) if rest else ""
        if value is None:
            return None
        return self._resolve_vars(value, node.start_byte, depth + 1)

    def _resolve_vars(self, text, pos, _depth=0):
        """Every text `text` can expand to at byte `pos`, each `$NAME` the
        line assigns (see above) replaced by its values. None when a name
        cannot be resolved. $HOME and $TMPDIR (and `~`) stay for
        `_expand_home` when the line never spells them and nothing on it
        can bind a name out of sight; otherwise they are unresolved. Any
        other expansion stays as written, and the matchers treat it as
        unresolvable."""
        scope = self._vars
        if scope is None or _depth > _MAX_VAR_DEPTH:
            return None
        src = scope["text"].encode("utf-8")
        text = _DIGIT_PARAMS_RE.sub("0", text)
        if text == "~" or text.startswith("~/"):
            if not self._env_var_ok("HOME"):
                return None
        names = []
        for m in _VAR_REF_RE.finditer(text):
            name = m.group(1) or m.group(2)
            if name not in names:
                names.append(name)
        if not names:
            return [text]
        choices = []
        for name in names:
            key = (name, pos, _depth)
            if key not in scope["memo"]:
                if name in _ENV_PATH_VARS:
                    values = [None] if self._env_var_ok(name) else None
                elif name in _DIGIT_VARS and not self._spelled(name):
                    values = ["0"]
                else:
                    values = self._name_values(name, pos, _depth, src)
                scope["memo"][key] = values
            values = scope["memo"][key]
            if values is None:
                return None
            choices.append(values)
        out = []
        for combo in itertools.product(*choices):
            if len(out) >= _MAX_VAR_VALUES:
                return None
            subst = dict(zip(names, combo))

            def repl(m):
                value = subst[m.group(1) or m.group(2)]
                return m.group(0) if value is None else value
            out.append(_VAR_REF_RE.sub(repl, text))
        return out

    def _resolve_arg(self, arg, pos):
        """`arg` with the line's own variables substituted, when every
        value is a plain word; several values come back as one brace list,
        which the write-target matchers expand. Otherwise `arg` unchanged.
        Never under a changed IFS, which would split the value."""
        if "$" not in arg and not arg.startswith("~"):
            return arg
        if self._vars is None:
            return arg
        resolved = None
        if "IFS" not in self._vars["text"]:
            resolved = self._resolve_vars(arg, pos)
        if not resolved:
            return self._mask_rebound_env(arg)
        if any(ch.isspace() or ch in "*?[{},"
               for value in resolved for ch in value):
            return arg
        values = list(dict.fromkeys(resolved))
        if len(values) == 1:
            return values[0]
        return "{" + ",".join(values) + "}"

    def _mask_rebound_env(self, arg):
        """`arg` with each HOME / TMPDIR reference (and a leading `~`) the
        line may rebind replaced by the substitution placeholder, so the
        rule layer reads it as unresolved instead of expanding it from the
        environment."""
        if arg.startswith("~") and (arg == "~" or arg.startswith("~/")) \
                and not self._env_var_ok("HOME"):
            arg = SUBSTITUTION_PLACEHOLDER + arg[1:]

        def repl(m):
            name = m.group(1) or m.group(2)
            if name in _ENV_PATH_VARS and not self._env_var_ok(name):
                return SUBSTITUTION_PLACEHOLDER
            return m.group(0)
        return _VAR_REF_RE.sub(repl, arg)

    def _target_is_safe_write(self, target):
        """Match `target` against rules/shell.json#safe_write_targets. The
        rule layer's matcher, so redirects and command write-args agree."""
        return _path_matches_safe_write_targets(target, self.safe_write_targets)

    def _target_is_unsafe_write(self, target):
        """Match `target` against rules/shell.json#unsafe_write_targets --
        dotfile / config / startup paths dangerous enough to classify
        unsafe (ask with a specific reason) rather than unknown. Checked
        before the safe list so an entry here overrides a broader safe
        glob (the ~/.claude/settings.json carve-out)."""
        return _path_matches_target_list(target, self.unsafe_write_targets)

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
        if result.get("unresolved"):
            return (DECISION_UNKNOWN, "python {}: {}".format(
                description, result.get("reason", "delegated subprocess argv")))
        return (DECISION_UNSAFE, "python {}: {}".format(
            description, result.get("reason", "destructive call"),
        ))

    def _bash_inline_analyzer(self, script, depth):
        """Used by RuleClassifier for `bash -c <script>` interpreters."""
        return self.classify(script, _depth=depth)

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
        # The gh surface that still classifies after Phase 3 (#100). This
        # map used to hold `pr` and `issue`, which that phase delegated to
        # auto mode -- leaving a hint generator that could only fire for
        # commands the hook no longer has an opinion about.
        allowed = {
            "release": {"create", "delete"},
            "repo": {"fork"},
            "run": {"cancel"},
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


def build_classifier(rules, python_analyzer_factory=None, cwd=None):
    """The one construction point for a classifier that will be asked to
    `classify()`. Every entry point goes through here.

    It exists because the plain constructor is too easy to call
    incompletely, and incompletely is indistinguishable from correctly.
    The deny layer is parasitic -- it narrows an existing `unsafe` and can
    never originate a verdict -- so a classifier built without `policy=`
    does not error, does not warn, and does not return anything a caller
    could tell apart from a real answer. It just quietly never denies.

    That shipped: through v2.0.0 the CLI answered `unsafe` for
    `git push --force origin master` while the hook answered `deny`, and a
    downstream consumer built deny handling against it that could not fire
    (#143). The same mistake had already been made once in the replay
    harness during #100. Two instances of one shape is the argument for a
    factory rather than a third fix.

    `cwd` stays explicit rather than defaulting to `os.getcwd()` here: the
    hook takes it from the host payload and legitimately passes `None` when
    the host did not supply one, and silently substituting this process's
    directory would judge a command against the wrong repository."""
    from git_policy import load_policies

    retval = GrammarClassifier(
        rules,
        python_analyzer_factory=python_analyzer_factory,
        cwd=cwd,
        policy=load_policies(rules),
    )
    return retval


def classify_command(command, rules, python_analyzer_factory=None, cwd=None):
    """Module-level convenience wrapper."""
    classifier = build_classifier(
        rules,
        python_analyzer_factory=python_analyzer_factory,
        cwd=cwd,
    )
    retval = classifier.classify(command)
    return retval


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

    # `--cwd DIR` says which directory the command would run in. The git
    # deny predicates need it: which branch a `git push` targets, and who
    # authored the commits it would move, are properties of a repository,
    # not of the command text. Defaults to this process's directory, which
    # is right for a shell wrapper and wrong for a service classifying on
    # behalf of somebody else -- so it is overridable. A directory that is
    # not a repository is safe: every probe fails, every predicate reads
    # UNDETERMINED, and no deny can be produced from a failed probe.
    cwd = os.getcwd()
    if "--cwd" in argv:
        i = argv.index("--cwd")
        if i + 1 >= len(argv):
            print("--cwd needs a directory", file=sys.stderr)
            sys.exit(1)
        cwd = argv[i + 1]
        argv = argv[:i] + argv[i + 2:]

    if not argv:
        print(
            "Usage: grammar_classifier.py [--no-user-allow] [--cwd DIR] "
            "'<shell command>'",
            file=sys.stderr,
        )
        sys.exit(1)

    if argv[0].startswith("--"):
        # An unrecognized leading flag used to be consumed AS the command.
        # `--cwd` on a build predating it classified as `no rule: --cwd`,
        # and `--no-user-allow` did the same before 1.2.0 -- so every
        # verdict became a verdict about the flag string. That is silent,
        # and for a consumer treating anything but `safe` as a refusal it
        # parks every command with nothing to diagnose. It also hides the
        # real command: `--dry-run "rm -rf /tmp/x"` read `unknown` because
        # the `rm` was never examined, not because it was judged. A shell
        # command does not begin with `--`, so reject it loudly instead.
        print(
            "unrecognized option {!r}: expected a shell command. "
            "Supported options are --no-user-allow and --cwd DIR.".format(
                argv[0]),
            file=sys.stderr,
        )
        sys.exit(1)

    command = argv[0]
    yolt_dir = Path(__file__).resolve().parent.parent
    rules = load_shell_rules(
        rules_dir=yolt_dir / "rules",
        user_overrides_path=Path.home() / ".claude" / "yolt" / "shell.json",
    )

    # `--no-user-allow` is accepted and does nothing, deliberately. Phase 1
    # removed the allow path entirely, so there is no inherited allow-pattern
    # surface left for it to switch off -- the behaviour it asked for is now
    # unconditional. It stays in the signature because consumers pass it
    # unconditionally, and a removed flag would be read as the command,
    # turning every verdict into a verdict about the string
    # "--no-user-allow". See the 2.0.0 compatibility note.
    _ = no_user_allow

    # Python analyzer factory — lazy import so this CLI works without
    # the rule data dir for python rules.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from yolt_analyzer import SafetyAnalyzer, load_rules as load_py_rules

    py_rules = load_py_rules(
        rules_dir=yolt_dir / "rules",
        user_overrides_path=Path.home() / ".claude" / "yolt" / "rules.json",
    )

    def factory():
        # A python-free RuleClassifier for argv inspection. It cannot recurse
        # into this analyzer because it has no python_analyzer_factory, and it
        # reads the same shell rules, so a literal `subprocess.run([...])` argv
        # is judged exactly as the equivalent shell command. Issue #162.
        return SafetyAnalyzer(
            py_rules, argv_classify=RuleClassifier(rules).classify_tokens)

    decision, reason = classify_command(
        command,
        rules,
        python_analyzer_factory=factory,
        cwd=cwd,
    )

    # The CLI never reports `safe`. A static reading of a shell command
    # cannot vouch that it runs no code: the shell decides that at run time,
    # through more routes than rule data can enumerate. A consumer that
    # auto-runs `safe` would be trusting a claim this tool cannot back.
    # `unknown` says what is true, that yolt has no objection, and leaves the
    # decision to the consumer's own gate. The hook is unaffected: there
    # `safe` and `unknown` were already the same silent exit.
    if decision == DECISION_SAFE:
        decision, reason = DECISION_UNKNOWN, "no objection: {}".format(reason)

    # How many allow patterns were in play is part of the verdict's meaning: the
    # same command classifies differently under a different settings file, and
    # without this a consumer cannot see -- or log at startup -- how large the
    # inherited auto-run surface is.
    print(json.dumps(
        # `allow_patterns` is retained and is honestly 0: Phase 1 removed the
        # allow path, so no allow pattern is ever in play for any verdict.
        # Kept because a consumer asserting it is 0 at startup is asserting
        # something true about 2.0.0, which is a better contract than trusting
        # a flag to stay a no-op. See the 2.0.0 compatibility note.
        {"decision": decision, "reason": reason, "allow_patterns": 0},
        indent=2,
    ))
    sys.exit(0)


if __name__ == "__main__":
    run_cli()
