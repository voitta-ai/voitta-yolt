#!/usr/bin/env python3
"""YOLT self-improvement reviewer (issue #44).

Mines the YOLT decision log (`~/.claude/yolt.log`) and the ran-record log
(`~/.claude/yolt-ran.log`, written by the PostToolUse hook) for recurring
friction and wasted hook startups, then writes a human-reviewable markdown
doc plus a machine-readable suggestion state file:

- `~/.claude/yolt/review.md` -- the doc the user reads/edits.
- `~/.claude/yolt/suggestions.json` -- suggestion ids with
  pending/applied/dismissed status that survives regeneration.

Buckets:

- ``friction-unsafe`` -- YOLT said `ask` repeatedly; a ran-record after the
  decision means the user approved at the prompt.
- ``friction-unknown`` -- YOLT fell through to Claude Code's default prompt
  repeatedly (rules gap or personal CLI).
- ``fastpath`` -- YOLT auto-allowed at high frequency; a `settings.json`
  allow glob would bypass the hook startup entirely (a static allow rule
  bypasses PreToolUse hooks natively).

Grouping is a conservative token heuristic (no tree-sitter dependency, so
the reviewer works even where the grammar deps failed to bootstrap).
Compound commands (pipes, substitutions, loops) are counted but not turned
into suggestions -- prefix globs cannot express them; rules / user
overrides handle those (see issue #45).

Stdlib only. Subcommands:

    --generate [--quiet]   parse logs, merge state, write doc + state
    --status               print {"pending": N, ...} JSON
    --nudge                SessionStart helper: emit additionalContext JSON
                           when pending > 0, throttled to once per
                           NUDGE_INTERVAL_HOURS
    --list                 dump the full suggestion state JSON
    --applied ID [ID ...]  mark suggestions applied
    --dismiss ID [ID ...]  mark suggestions dismissed
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import shlex
import sys
from fnmatch import fnmatch
from pathlib import Path

# Override writing (issue #45) needs the classifier's merge + validation so a
# fragment is checked against the same merge the hook performs. The import is
# guarded: the rest of the reviewer (parse / status / nudge) is stdlib-only and
# must keep working even if rule_classifier cannot be imported, so a failure
# here only disables `--write-override`, not the whole tool.
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from rule_classifier import (
        load_shell_rules,
        merge_shell_overrides,
        validate_shell_rules,
    )
    _RULES_AVAILABLE = True
except ImportError:
    load_shell_rules = None
    merge_shell_overrides = None
    validate_shell_rules = None
    _RULES_AVAILABLE = False

DEFAULT_LOG_PATH = Path.home() / ".claude" / "yolt.log"
DEFAULT_RAN_LOG_PATH = Path.home() / ".claude" / "yolt-ran.log"
DEFAULT_STATE_DIR = Path.home() / ".claude" / "yolt"
DEFAULT_RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
# The shell-override file the classifier loads (grammar_classifier hard-codes
# this path) and that `--write-override` writes. Kept independent of the state
# dir so the reviewer writes exactly the file the hook reads.
DEFAULT_SHELL_OVERRIDE_PATH = Path.home() / ".claude" / "yolt" / "shell.json"

DOC_NAME = "review.md"
STATE_NAME = "suggestions.json"
STATE_VERSION = 1

MIN_FIRES_FRICTION = 3
MIN_FIRES_FASTPATH = 10
MAX_GROUP_DEPTH = 3
MAX_EXAMPLES = 3
MAX_EXAMPLE_CHARS = 200
MAX_PER_BUCKET = 20
NUDGE_INTERVAL_HOURS = 24
RAN_MATCH_SKEW_SECONDS = 5
# Upper bound on how long after a prompt a ran-record may still count as
# that prompt's approval. PostToolUse stamps completion time, so this
# must cover think-time plus command runtime, but stay well below "a
# separate later invocation": without it, a run an hour later (e.g. once
# the command became statically allowed) would back-credit an old denied
# prompt. Undercounting a genuinely-approved slow command is the safe
# direction -- better than fabricating an approval.
RAN_MATCH_WINDOW_SECONDS = 600

KIND_UNSAFE = "friction-unsafe"
KIND_UNKNOWN = "friction-unknown"
KIND_FASTPATH = "fastpath"

# Order matters for the doc.
KINDS = [KIND_UNSAFE, KIND_UNKNOWN, KIND_FASTPATH]

KIND_TITLES = {
    KIND_UNSAFE: "Friction: YOLT prompted (`ask`)",
    KIND_UNKNOWN: "Friction: unknown (Claude Code default prompt)",
    KIND_FASTPATH: "Fast-path candidates (safe, high-frequency)",
}

# Shell metacharacters that mark a command as compound / not expressible
# as a prefix glob. Conservative: any hit disqualifies the command from
# suggestion grouping.
COMPOUND_RE = re.compile(r"[|;&<>`$\n]")
SUBCOMMAND_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

# CLIs common enough that a repeated `unknown` on them suggests a rules
# gap worth an upstream issue on voitta-ai/voitta-yolt (as opposed to a
# personal/internal tool, which only warrants a local setting/override).
UPSTREAM_CLIS = {
    "aws", "az", "bazel", "brew", "cargo", "docker", "gcloud", "gh",
    "git", "go", "gradle", "helm", "kubectl", "mvn", "npm", "terraform",
}


def resolve_log_path(cli_value):
    """Decision log path: --log flag > YOLT_LOG_FILE > default.
    Empty string means logging is opted out."""
    retval = None
    if cli_value:
        retval = Path(cli_value)
    else:
        env_value = os.environ.get("YOLT_LOG_FILE")
        if env_value is None:
            retval = DEFAULT_LOG_PATH
        elif env_value == "":
            retval = None
        else:
            retval = Path(env_value)
    return retval


def resolve_ran_log_path(cli_value):
    """Ran log path: --ran-log flag > YOLT_RAN_LOG_FILE > default.
    Empty string means ran-capture is opted out."""
    retval = None
    if cli_value:
        retval = Path(cli_value)
    else:
        env_value = os.environ.get("YOLT_RAN_LOG_FILE")
        if env_value is None:
            retval = DEFAULT_RAN_LOG_PATH
        elif env_value == "":
            retval = None
        else:
            retval = Path(env_value)
    return retval


def resolve_state_dir(cli_value):
    """State dir: --state-dir flag > YOLT_STATE_DIR > ~/.claude/yolt."""
    retval = None
    if cli_value:
        retval = Path(cli_value)
    else:
        env_value = os.environ.get("YOLT_STATE_DIR")
        if env_value:
            retval = Path(env_value)
        else:
            retval = DEFAULT_STATE_DIR
    return retval


def resolve_rules_dir(cli_value):
    """Bundled rules dir: --rules-dir flag > YOLT_RULES_DIR > <plugin>/rules."""
    retval = None
    if cli_value:
        retval = Path(cli_value)
    else:
        env_value = os.environ.get("YOLT_RULES_DIR")
        if env_value:
            retval = Path(env_value)
        else:
            retval = DEFAULT_RULES_DIR
    return retval


def resolve_shell_override_path(cli_value):
    """User shell-override file the hook reads and `--write-override` writes:
    --shell-override flag > YOLT_SHELL_OVERRIDE > ~/.claude/yolt/shell.json."""
    retval = None
    if cli_value:
        retval = Path(cli_value)
    else:
        env_value = os.environ.get("YOLT_SHELL_OVERRIDE")
        if env_value:
            retval = Path(env_value)
        else:
            retval = DEFAULT_SHELL_OVERRIDE_PATH
    return retval


def load_known_clis(rules_dir):
    """Names the bundled shell rules already classify (commands +
    interpreters + safe builtins, plus the common-CLI backstop). A
    friction-unknown on one of these is a rules gap worth an upstream issue,
    not a personal CLI to shadow with a frozen local copy of the bundled
    spec. Returns None when the rules cannot be loaded (override writing then
    stays disabled rather than mistaking a bundled CLI for a personal one)."""
    if not _RULES_AVAILABLE:
        return None
    try:
        rules = load_shell_rules(rules_dir, user_overrides_path=None,
                                 validate=False)
    except (OSError, ValueError):
        return None
    names = set()
    names.update(rules.get("commands", {}).keys())
    names.update(rules.get("interpreters", {}).keys())
    names.update(rules.get("shell_builtins_safe", []))
    names.update(UPSTREAM_CLIS)
    return names


def build_override_fragment(subs):
    """The minimal per-command spec (the value of `commands.<cli>`) asserting
    the observed subcommand is read-only. One subcommand token -> top-level
    `safe_subcommands`; two -> `nested_subcommand.<group>.safe_subcommands`
    (matching the depth-3 grouping a `cli group sub` prefix produces).
    `default: subcommand` keeps every other subcommand at `unknown` (still
    prompted), so the assertion is strictly additive — it never marks the
    whole CLI safe."""
    if len(subs) == 1:
        retval = {"default": "subcommand", "safe_subcommands": [subs[0]]}
    else:
        group, sub = subs[0], subs[1]
        retval = {
            "default": "subcommand",
            "nested_subcommand": {group: {"safe_subcommands": [sub]}},
        }
    return retval


def compute_override(prefix, known_clis):
    """Decide whether the reviewer may write a `safe_subcommands` override for
    a friction-unknown `prefix`, and with what fragment. Writable only for a
    personal CLI (no bundled rule) with at least one subcommand token; the
    fragment asserts that one observed subcommand is read-only. Returns a dict
    the doc renders and `--write-override` consumes."""
    parts = prefix.split(" ")
    cli = parts[0]
    subs = parts[1:]
    if not subs:
        retval = {
            "writable": False,
            "reason": "no subcommand to scope safe; only mark the whole "
                      "command safe by hand if it is read-only regardless of "
                      "arguments",
        }
        return retval
    if known_clis is None:
        retval = {
            "writable": False,
            "reason": "default rules unavailable; cannot confirm this is a "
                      "personal CLI",
        }
        return retval
    if cli in known_clis:
        retval = {
            "writable": False,
            "reason": "{} has bundled rules; a gap here is upstream-worthy (a "
                      "local override would freeze a copy of the bundled "
                      "spec)".format(cli),
        }
        return retval
    fragment = build_override_fragment(subs)
    label = "commands.{}".format(cli)
    if len(subs) > 1:
        label = "commands.{}.nested_subcommand.{}".format(cli, subs[0])
    retval = {"writable": True, "cli": cli, "fragment": fragment, "label": label}
    return retval


def merge_command_fragment(existing_spec, fragment):
    """Union our minimal fragment shape (default + safe_subcommands and/or
    nested_subcommand.<group>.safe_subcommands) into an existing per-command
    spec, preserving everything already there. Never removes a subcommand; it
    only adds the observed read-only one, so re-running is idempotent and an
    existing user spec is never clobbered."""
    spec = json.loads(json.dumps(existing_spec))  # deep copy; don't mutate caller
    spec.setdefault("default", fragment.get("default", "subcommand"))
    for sub in fragment.get("safe_subcommands", []):
        bucket = spec.setdefault("safe_subcommands", [])
        if sub not in bucket:
            bucket.append(sub)
    nested = fragment.get("nested_subcommand")
    if nested:
        dst_nested = spec.setdefault("nested_subcommand", {})
        if not isinstance(dst_nested, dict):
            dst_nested = {}
            spec["nested_subcommand"] = dst_nested
        for group, group_spec in nested.items():
            dst_group = dst_nested.setdefault(group, {})
            if not isinstance(dst_group, dict):
                dst_group = {}
                dst_nested[group] = dst_group
            bucket = dst_group.setdefault("safe_subcommands", [])
            for sub in group_spec.get("safe_subcommands", []):
                if sub not in bucket:
                    bucket.append(sub)
    return spec


def read_jsonl(path):
    """Read a JSONL file plus its rotated `.old` generation. Returns a
    list of dict records; malformed lines and missing files are skipped."""
    retval = []
    if path is None:
        return retval
    candidates = [path.with_suffix(path.suffix + ".old"), path]
    for candidate in candidates:
        try:
            with open(candidate, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(record, dict):
                        retval.append(record)
        except OSError:
            continue
    return retval


def parse_ts(value):
    """Parse an ISO timestamp; None when missing/unparseable."""
    retval = None
    if isinstance(value, str) and value:
        try:
            retval = datetime.datetime.fromisoformat(value)
        except ValueError:
            retval = None
    return retval


def is_compound(command):
    """True when the command contains shell metacharacters that a prefix
    glob cannot express (pipes, lists, redirects, substitutions, ...)."""
    retval = bool(COMPOUND_RE.search(command))
    return retval


def split_tokens(command):
    """Tokenize a simple command. shlex first; on unbalanced quoting fall
    back to whitespace split. Leading env assignments are dropped, same
    as the grammar walker does."""
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    while tokens and ENV_ASSIGN_RE.match(tokens[0]):
        tokens = tokens[1:]
    retval = tokens
    return retval


def group_key(command):
    """Conservative grouping prefix: argv[0] plus subcommand-looking
    tokens (lowercase/alnum/dash, no slash) up to MAX_GROUP_DEPTH deep,
    stopping at the first flag or value-looking token. None for compound
    or empty commands."""
    retval = None
    if not is_compound(command):
        tokens = split_tokens(command)
        if tokens:
            parts = [tokens[0]]
            for token in tokens[1:]:
                if len(parts) >= MAX_GROUP_DEPTH:
                    break
                if token.startswith("-"):
                    break
                if "/" in token:
                    break
                if not SUBCOMMAND_RE.match(token):
                    break
                parts.append(token)
            retval = " ".join(parts)
    return retval


def redact_command(command):
    """Reduce a command to its shape: argv head + subcommand tokens +
    flag names; every value token becomes `<...>`. This is the only form
    that may leave the machine (upstream issue drafts) -- raw log lines
    carry real paths / account ids / occasionally secrets."""
    retval = "(compound command)"
    if not is_compound(command):
        tokens = split_tokens(command)
        if tokens:
            parts = []
            in_subcommand_run = True
            depth = 0
            for index, token in enumerate(tokens):
                if index == 0:
                    parts.append(token)
                    depth = 1
                    continue
                if token.startswith("-"):
                    in_subcommand_run = False
                    if "=" in token:
                        flag_name = token.split("=", 1)[0]
                        parts.append(flag_name + "=<...>")
                    else:
                        parts.append(token)
                    continue
                if (
                    in_subcommand_run
                    and depth < MAX_GROUP_DEPTH
                    and "/" not in token
                    and SUBCOMMAND_RE.match(token)
                ):
                    parts.append(token)
                    depth += 1
                    continue
                in_subcommand_run = False
                parts.append("<...>")
            retval = " ".join(parts)
    return retval


def suggestion_id(kind, prefix):
    """Stable id so applied/dismissed status survives regeneration."""
    digest = hashlib.sha256("{}|{}".format(kind, prefix).encode("utf-8"))
    retval = digest.hexdigest()[:12]
    return retval


def build_ran_index(ran_records):
    """Map truncated command string -> sorted list of ran timestamps."""
    retval = {}
    for record in ran_records:
        command = record.get("command")
        ts = parse_ts(record.get("ts"))
        if not command or ts is None:
            continue
        retval.setdefault(command, []).append(ts)
    for timestamps in retval.values():
        timestamps.sort()
    return retval


def correlate_approvals(records, ran_index):
    """Match friction prompt-records to ran-records one-to-one, per command.

    A command YOLT returned `ask`/`unknown` on only reaches PostToolUse
    (and thus the ran log) if the user approved it at the prompt. Two
    constraints keep the correlation honest:

    - One-to-one: a single ran-record must not credit more than one
      prompt. With prompts at t10 and t20 and a lone ran at t21, only one
      prompt was actually approved.
    - Bounded: a ran-record only counts for a prompt if it lands in
      `[prompt_ts - skew, prompt_ts + window]`. Without the upper bound a
      run long after the prompt (e.g. once the command became statically
      allowed) would back-credit an old denied prompt.

    For each command we walk prompts in time order and consume the
    earliest still-unclaimed ran-record inside that window; a ran-record
    beyond a prompt's window is left for a later prompt.

    Returns the set of record indices (into `records`) that were
    approved."""
    by_command = {}
    for index, record in enumerate(records):
        if record.get("decision") not in ("unsafe", "unknown"):
            continue
        command = (record.get("command") or "").strip()
        ts = parse_ts(record.get("ts"))
        if not command or ts is None:
            continue
        by_command.setdefault(command, []).append((ts, index))

    skew = datetime.timedelta(seconds=RAN_MATCH_SKEW_SECONDS)
    window = datetime.timedelta(seconds=RAN_MATCH_WINDOW_SECONDS)
    approved = set()
    for command, prompts in by_command.items():
        rans = ran_index.get(command)
        if not rans:
            continue
        prompts.sort(key=lambda p: p[0])
        ran_pos = 0
        count = len(rans)
        for prompt_ts, index in prompts:
            low = prompt_ts - skew
            high = prompt_ts + window
            # Advance past ran-records that can help neither this prompt
            # nor any later one: those before `low` (later prompts have a
            # larger low), or tz-incomparable (hand-edited lines). The tz
            # check short-circuits before the order comparison so
            # aware/naive values are never compared.
            while ran_pos < count and (
                (rans[ran_pos].tzinfo is None) != (low.tzinfo is None)
                or rans[ran_pos] < low
            ):
                ran_pos += 1
            # The earliest in-range ran approves this prompt and is
            # consumed. If it sits beyond `high`, leave it for a later
            # prompt (whose window extends further) -- this prompt is
            # unapproved.
            if ran_pos < count and rans[ran_pos] <= high:
                approved.add(index)
                ran_pos += 1
    return approved


def annotate_glob_collisions(suggestion, nonsafe_commands, own_commands=None):
    """Record any known-unsafe/unknown command that the suggestion's
    `Bash(prefix*)` glob would ALSO match -- excluding the suggestion's
    own group commands.

    This is the safety gate for fast-path suggestions: `gh api` is
    read-only but `gh api -X POST` is not, and both match `gh api*`.
    Promoting that glob to `permissions.allow` would bypass YOLT for the
    POST too (a static allow rule bypasses PreToolUse hooks entirely).
    Matching uses fnmatch against the real glob, so the warning reflects
    exactly what Claude Code's matcher would allow. `gh pr view*` does
    NOT collide with `gh pr merge`, so partially-overlapping namespaces
    stay suggestable.

    `own_commands` are the (stripped) commands that formed THIS group; a
    friction suggestion's own examples live in `nonsafe_commands`, and a
    glob trivially matches the very commands it was derived from. Counting
    those as collisions would veto every `friction-unsafe` /
    `friction-unknown` suggestion against itself, so they are excluded:
    only a genuinely different non-safe command swept in by the glob is a
    collision."""
    own = own_commands or set()
    pattern = suggestion["prefix"] + "*"
    collisions = []
    for command in nonsafe_commands:
        if command in own:
            continue
        if fnmatch(command, pattern):
            collisions.append(command[:MAX_EXAMPLE_CHARS])
            if len(collisions) >= MAX_EXAMPLES:
                break
    suggestion["glob_collisions"] = collisions
    return suggestion


def build_groups(records, ran_index, min_fires, min_fires_safe, known_clis=None):
    """Aggregate log records into suggestion groups. Returns
    (suggestions, stats). `known_clis` is the set of CLIs the bundled rules
    already classify (None when unavailable); it gates whether a
    friction-unknown suggestion can carry a writable `safe_subcommands`
    override (issue #45)."""
    decision_to_kind = {
        "unsafe": KIND_UNSAFE,
        "unknown": KIND_UNKNOWN,
        "safe": KIND_FASTPATH,
    }
    groups = {}
    # Every distinct command YOLT did NOT classify safe. Used to veto
    # fast-path settings.json globs that would also cover a known-unsafe
    # command (see annotate_glob_collisions): suggesting `Bash(gh api*)`
    # when `gh api -X POST` is in this set would silently defeat YOLT.
    nonsafe_commands = set()
    stats = {
        "records": len(records),
        "compound_friction": 0,
        "broken_install": 0,
        "first_ts": None,
        "last_ts": None,
    }
    approved_indices = correlate_approvals(records, ran_index)
    for index, record in enumerate(records):
        decision = record.get("decision")
        command = record.get("command") or ""
        ts = parse_ts(record.get("ts"))
        if ts is not None:
            if stats["first_ts"] is None or ts < stats["first_ts"]:
                stats["first_ts"] = ts
            if stats["last_ts"] is None or ts > stats["last_ts"]:
                stats["last_ts"] = ts
        if decision in ("import-error", "rules-validation-error"):
            stats["broken_install"] += 1
            continue
        kind = decision_to_kind.get(decision)
        if kind is None or not command.strip():
            continue
        if kind in (KIND_UNSAFE, KIND_UNKNOWN):
            nonsafe_commands.add(command.strip())
        prefix = group_key(command)
        if prefix is None:
            if kind in (KIND_UNSAFE, KIND_UNKNOWN):
                stats["compound_friction"] += 1
            continue
        key = (kind, prefix)
        group = groups.get(key)
        if group is None:
            group = {
                "kind": kind,
                "prefix": prefix,
                "fires": 0,
                "approved": 0,
                "first_ts": None,
                "last_ts": None,
                "examples": [],
                "reasons": {},
                "commands": set(),
            }
            groups[key] = group
        group["fires"] += 1
        group["commands"].add(command.strip())
        if ts is not None:
            if group["first_ts"] is None or ts < group["first_ts"]:
                group["first_ts"] = ts
            if group["last_ts"] is None or ts > group["last_ts"]:
                group["last_ts"] = ts
        reason = record.get("reason") or ""
        if reason:
            group["reasons"][reason] = group["reasons"].get(reason, 0) + 1
        if index in approved_indices:
            group["approved"] += 1
        example = command[:MAX_EXAMPLE_CHARS]
        if example not in group["examples"] and len(group["examples"]) < MAX_EXAMPLES:
            group["examples"].append(example)

    suggestions = []
    for (kind, prefix), group in groups.items():
        threshold = min_fires_safe if kind == KIND_FASTPATH else min_fires
        if group["fires"] < threshold:
            continue
        top_reason = ""
        if group["reasons"]:
            top_reason = max(group["reasons"].items(), key=lambda kv: kv[1])[0]
        argv0 = prefix.split(" ", 1)[0]
        upstream = bool(kind == KIND_UNKNOWN and argv0 in UPSTREAM_CLIS)
        suggestion = {
            "id": suggestion_id(kind, prefix),
            "kind": kind,
            "prefix": prefix,
            "fires": group["fires"],
            "approved": group["approved"],
            "first_ts": group["first_ts"].isoformat() if group["first_ts"] else None,
            "last_ts": group["last_ts"].isoformat() if group["last_ts"] else None,
            "settings_pattern": "Bash({}*)".format(prefix),
            "upstream_candidate": upstream,
            "top_reason": top_reason,
            "shape": redact_command(group["examples"][0]) if group["examples"] else prefix,
            "examples": group["examples"],
            "glob_collisions": [],
            "status": "pending",
        }
        annotate_glob_collisions(suggestion, nonsafe_commands,
                                 own_commands=group["commands"])
        if kind == KIND_UNKNOWN:
            suggestion["override"] = compute_override(prefix, known_clis)
        suggestions.append(suggestion)

    suggestions.sort(key=lambda s: (KINDS.index(s["kind"]), -s["fires"], s["prefix"]))

    # Cap per bucket so the doc stays reviewable.
    capped = []
    bucket_counts = {}
    dropped = 0
    for suggestion in suggestions:
        count = bucket_counts.get(suggestion["kind"], 0)
        if count >= MAX_PER_BUCKET:
            dropped += 1
            continue
        bucket_counts[suggestion["kind"]] = count + 1
        capped.append(suggestion)
    stats["dropped_over_cap"] = dropped
    retval = (capped, stats)
    return retval


def load_state(state_path):
    """Load suggestions.json; empty scaffold when missing/corrupt."""
    retval = {
        "version": STATE_VERSION,
        "generated": None,
        "last_nudged": None,
        "stats": {},
        "suggestions": [],
    }
    try:
        with open(state_path, "r") as f:
            data = json.load(f)
        if isinstance(data, dict) and isinstance(data.get("suggestions"), list):
            retval = data
    except (OSError, ValueError):
        pass
    return retval


def save_state(state_path, state):
    state_path.parent.mkdir(parents=True, exist_ok=True)
    with open(state_path, "w") as f:
        json.dump(state, f, indent=2)
        f.write("\n")


def merge_state(old_state, new_suggestions, stats):
    """Recompute counts but preserve applied/dismissed status by id.
    Suggestions that no longer regenerate (rules updated, log rotated
    out) are dropped."""
    old_status = {}
    for suggestion in old_state.get("suggestions", []):
        sid = suggestion.get("id")
        status = suggestion.get("status")
        if sid and status in ("applied", "dismissed"):
            old_status[sid] = status
    for suggestion in new_suggestions:
        preserved = old_status.get(suggestion["id"])
        if preserved:
            suggestion["status"] = preserved
    json_stats = dict(stats)
    for key in ("first_ts", "last_ts"):
        if isinstance(json_stats.get(key), datetime.datetime):
            json_stats[key] = json_stats[key].isoformat()
    retval = {
        "version": STATE_VERSION,
        "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "last_nudged": old_state.get("last_nudged"),
        "stats": json_stats,
        "suggestions": new_suggestions,
    }
    return retval


def render_doc(state, log_path, ran_log_path):
    """Render the human-reviewable markdown doc."""
    lines = []
    stats = state.get("stats", {})
    lines.append("# YOLT review")
    lines.append("")
    lines.append(
        "Generated {} from `{}` ({} records{}) and `{}`."
        .format(
            state.get("generated", "?"),
            log_path,
            stats.get("records", 0),
            ", since {}".format(stats["first_ts"]) if stats.get("first_ts") else "",
            ran_log_path if ran_log_path else "(ran-capture opted out)",
        )
    )
    lines.append("")
    lines.append(
        "Apply / dismiss via `/yolt:review`, or by hand: add the pattern to"
        " `permissions.allow` in `~/.claude/settings.json`, then"
        " `python3 hooks/yolt_review.py --applied <id>`."
    )
    lines.append("")
    lines.append(
        "> Privacy: `Examples` lines are raw log data and stay local."
        " Only the redacted `Shape` line may be used in upstream issues."
    )

    pending = [s for s in state.get("suggestions", []) if s.get("status") == "pending"]
    handled = [s for s in state.get("suggestions", []) if s.get("status") != "pending"]

    for kind in KINDS:
        bucket = [s for s in pending if s.get("kind") == kind]
        if not bucket:
            continue
        lines.append("")
        lines.append("## {}".format(KIND_TITLES[kind]))
        for suggestion in bucket:
            lines.append("")
            approved_part = ""
            if kind != KIND_FASTPATH:
                approved_part = ", {} approved at the prompt".format(
                    suggestion.get("approved", 0))
            lines.append("### `{}` — {} fires{} (id: `{}`)".format(
                suggestion["prefix"], suggestion["fires"], approved_part,
                suggestion["id"]))
            lines.append("")
            if suggestion.get("top_reason"):
                lines.append("- Reason: {}".format(suggestion["top_reason"]))
            collisions = suggestion.get("glob_collisions") or []
            if kind == KIND_FASTPATH:
                if collisions:
                    lines.append(
                        "- DO NOT whitelist `\"{}\"` — that glob would also"
                        " match these known non-safe commands, silently"
                        " bypassing YOLT for them:".format(
                            suggestion["settings_pattern"]))
                    for collision in collisions:
                        lines.append("  - Would also allow: `{}`".format(collision))
                    lines.append(
                        "  Route this to a `~/.claude/yolt/shell.json` rule"
                        " instead (issue #45), which keeps the AST walk in"
                        " the loop.")
                else:
                    lines.append(
                        "- Already auto-allowed by YOLT; `\"{}\"` in"
                        " `permissions.allow` skips the hook startup entirely"
                        " (static allows bypass PreToolUse hooks).".format(
                            suggestion["settings_pattern"]))
            else:
                override = suggestion.get("override") or {}
                if collisions:
                    lines.append(
                        "- DO NOT whitelist `\"{}\"` — that glob would also"
                        " match known non-safe commands (e.g. `{}`); use a"
                        " `~/.claude/yolt/shell.json` rule (issue #45).".format(
                            suggestion["settings_pattern"], collisions[0]))
                else:
                    lines.append(
                        "- settings.json route: `\"{}\"` — only if this command"
                        " is read-only regardless of flags; a static allow"
                        " bypasses YOLT's redirect/substitution checks.".format(
                            suggestion["settings_pattern"]))
                if override.get("writable"):
                    lines.append(
                        "- Override route (recommended): `python3"
                        " hooks/yolt_review.py --write-override {}` writes `{}`"
                        " to `~/.claude/yolt/shell.json` (validated before"
                        " write; keeps the AST walk in the loop).".format(
                            suggestion["id"], override["label"]))
                    fragment = {"commands": {override["cli"]: override["fragment"]}}
                    lines.append("  - Fragment: `{}`".format(json.dumps(fragment)))
                elif override.get("reason"):
                    lines.append(
                        "- Override route: {} — hand-write a"
                        " `~/.claude/yolt/shell.json` rule (issue #45).".format(
                            override["reason"]))
                else:
                    lines.append(
                        "- Override route: `~/.claude/yolt/shell.json` /"
                        " `rules.json` for flag-conditional or verb-class rules"
                        " (issue #45).")
            if suggestion.get("upstream_candidate"):
                lines.append(
                    "- Upstream candidate: common CLI fell through to"
                    " `unknown` — likely a rules gap worth an issue on"
                    " voitta-ai/voitta-yolt (redacted shape only).")
            lines.append("- Shape: `{}`".format(suggestion["shape"]))
            for example in suggestion.get("examples", []):
                lines.append("  - Example: `{}`".format(example))

    if not pending:
        lines.append("")
        lines.append("No pending suggestions.")

    if handled:
        lines.append("")
        lines.append("## Previously handled")
        lines.append("")
        for suggestion in handled:
            lines.append("- `{}` ({}) — {} (id: `{}`)".format(
                suggestion["prefix"], suggestion["kind"],
                suggestion["status"], suggestion["id"]))

    skipped_parts = []
    if stats.get("compound_friction"):
        skipped_parts.append(
            "{} compound friction commands (prefix globs cannot express"
            " these; rules / user overrides handle them — issue #45)"
            .format(stats["compound_friction"]))
    if stats.get("broken_install"):
        skipped_parts.append(
            "{} import-error / rules-validation-error records".format(
                stats["broken_install"]))
    if stats.get("dropped_over_cap"):
        skipped_parts.append(
            "{} suggestions over the per-bucket cap of {}".format(
                stats["dropped_over_cap"], MAX_PER_BUCKET))
    if skipped_parts:
        lines.append("")
        lines.append("## Not shown")
        lines.append("")
        for part in skipped_parts:
            lines.append("- {}".format(part))

    lines.append("")
    retval = "\n".join(lines)
    return retval


def _log_is_stale(log_path, state_path):
    """True when the doc should be regenerated: the decision log is newer
    than the last state write, or no state exists yet. Used by
    --if-stale (SessionEnd) to make the common no-change case a no-op
    rather than re-parsing the whole log. Errs on the side of
    regenerating (returns True) when an mtime cannot be read."""
    retval = True
    try:
        state_mtime = state_path.stat().st_mtime
    except OSError:
        return retval
    newest = 0.0
    found = False
    for candidate in (log_path, log_path.with_suffix(log_path.suffix + ".old")):
        try:
            mtime = candidate.stat().st_mtime
        except OSError:
            continue
        found = True
        if mtime > newest:
            newest = mtime
    if found:
        retval = newest > state_mtime
    return retval


def cmd_generate(args):
    log_path = resolve_log_path(args.log)
    ran_log_path = resolve_ran_log_path(args.ran_log)
    state_dir = resolve_state_dir(args.state_dir)
    if log_path is None:
        if not args.quiet:
            print("yolt-review: decision logging is opted out; nothing to do")
        return 0
    if args.if_stale and not _log_is_stale(log_path, state_dir / STATE_NAME):
        if not args.quiet:
            print("yolt-review: log unchanged since last run; skipping")
        return 0
    records = read_jsonl(log_path)
    if not records:
        if not args.quiet:
            print("yolt-review: no log records at {}".format(log_path))
        return 0
    ran_index = build_ran_index(read_jsonl(ran_log_path))
    known_clis = load_known_clis(resolve_rules_dir(args.rules_dir))
    suggestions, stats = build_groups(
        records, ran_index, args.min_fires, args.min_fires_safe,
        known_clis=known_clis)
    state_path = state_dir / STATE_NAME
    state = merge_state(load_state(state_path), suggestions, stats)
    save_state(state_path, state)
    doc_path = state_dir / DOC_NAME
    doc = render_doc(state, log_path, ran_log_path)
    with open(doc_path, "w") as f:
        f.write(doc)
    if not args.quiet:
        pending = len([s for s in state["suggestions"] if s["status"] == "pending"])
        print("yolt-review: {} pending suggestion(s); doc: {}".format(
            pending, doc_path))
    return 0


def cmd_status(args):
    state_dir = resolve_state_dir(args.state_dir)
    state = load_state(state_dir / STATE_NAME)
    pending = len([s for s in state.get("suggestions", [])
                   if s.get("status") == "pending"])
    print(json.dumps({
        "pending": pending,
        "generated": state.get("generated"),
        "last_nudged": state.get("last_nudged"),
        "doc": str(state_dir / DOC_NAME),
    }))
    return 0


def cmd_nudge(args):
    """SessionStart helper. Prints additionalContext JSON when there are
    pending suggestions and the user has not been nudged within
    NUDGE_INTERVAL_HOURS; silent otherwise."""
    state_dir = resolve_state_dir(args.state_dir)
    state_path = state_dir / STATE_NAME
    state = load_state(state_path)
    pending = len([s for s in state.get("suggestions", [])
                   if s.get("status") == "pending"])
    if pending == 0:
        return 0
    now = datetime.datetime.now(datetime.timezone.utc)
    last_nudged = parse_ts(state.get("last_nudged"))
    if last_nudged is not None and last_nudged.tzinfo is not None:
        age = now - last_nudged
        if age < datetime.timedelta(hours=NUDGE_INTERVAL_HOURS):
            return 0
    message = (
        "YOLT has {} pending whitelist/rule suggestion(s) distilled from"
        " your recent Bash friction - run /yolt:review to triage them"
        " (doc: {})."
    ).format(pending, state_dir / DOC_NAME)
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": message,
        }
    }))
    state["last_nudged"] = now.isoformat()
    try:
        save_state(state_path, state)
    except OSError:
        pass
    return 0


def cmd_list(args):
    state_dir = resolve_state_dir(args.state_dir)
    state = load_state(state_dir / STATE_NAME)
    print(json.dumps(state, indent=2))
    return 0


def cmd_mark(args, status):
    state_dir = resolve_state_dir(args.state_dir)
    state_path = state_dir / STATE_NAME
    state = load_state(state_path)
    by_id = {s.get("id"): s for s in state.get("suggestions", [])}
    missing = []
    for sid in args.ids:
        suggestion = by_id.get(sid)
        if suggestion is None:
            missing.append(sid)
        else:
            suggestion["status"] = status
    save_state(state_path, state)
    log_path = resolve_log_path(args.log)
    ran_log_path = resolve_ran_log_path(args.ran_log)
    doc = render_doc(state, log_path, ran_log_path)
    with open(state_dir / DOC_NAME, "w") as f:
        f.write(doc)
    if missing:
        print("yolt-review: unknown id(s): {}".format(", ".join(missing)),
              file=sys.stderr)
        return 1
    print("yolt-review: marked {} suggestion(s) {}".format(
        len(args.ids), status))
    return 0


def _load_json_obj(path):
    """Load a JSON object from `path`; {} when missing. Raises ValueError on
    corrupt content or a non-object so the writer refuses rather than
    clobbering a file it cannot parse."""
    retval = {}
    if path.exists():
        with open(path, "r") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("{} is not a JSON object".format(path))
        retval = data
    return retval


def _atomic_write_json(path, obj):
    """Write `obj` as pretty JSON to `path` via a temp file + os.replace, so a
    crash mid-write cannot leave a half-written shell.json that bricks the
    classifier."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2)
        f.write("\n")
    os.replace(tmp, path)


def cmd_write_override(args):
    """Write `safe_subcommands` overrides for the given suggestion ids to the
    user shell-override file (issue #45). Reads the existing file, merges each
    writable fragment in (read-modify-write, never clobbering existing
    entries), validates the result against the bundled rules with
    `validate_shell_rules`, and only then writes — a malformed override would
    downgrade the whole hook to `rules-validation-error`. Marks the written
    suggestions applied and regenerates the doc."""
    if not _RULES_AVAILABLE:
        print("yolt-review: rule_classifier unavailable; cannot validate or "
              "write overrides", file=sys.stderr)
        return 1

    state_dir = resolve_state_dir(args.state_dir)
    state_path = state_dir / STATE_NAME
    state = load_state(state_path)
    by_id = {s.get("id"): s for s in state.get("suggestions", [])}

    missing = []
    not_writable = []
    targets = []  # (cli, fragment, suggestion)
    for sid in args.ids:
        suggestion = by_id.get(sid)
        if suggestion is None:
            missing.append(sid)
            continue
        override = suggestion.get("override") or {}
        if not override.get("writable"):
            not_writable.append(
                (sid, override.get("reason", "not an override-writable suggestion")))
            continue
        targets.append((override["cli"], override["fragment"], suggestion))

    for sid in missing:
        print("yolt-review: unknown id: {}".format(sid), file=sys.stderr)
    for sid, reason in not_writable:
        print("yolt-review: {} is not override-writable: {}".format(sid, reason),
              file=sys.stderr)
    if not targets:
        print("yolt-review: nothing to write", file=sys.stderr)
        return 1

    override_path = resolve_shell_override_path(args.shell_override)
    try:
        user_override = _load_json_obj(override_path)
    except (OSError, ValueError) as e:
        print("yolt-review: cannot read existing override {}: {}".format(
            override_path, e), file=sys.stderr)
        return 1

    commands = user_override.setdefault("commands", {})
    if not isinstance(commands, dict):
        print("yolt-review: existing {} has a non-dict 'commands'; refusing to "
              "edit".format(override_path), file=sys.stderr)
        return 1
    # Refuse before mutating if any target CLI already has a non-dict spec:
    # silently replacing it with {} would clobber a (malformed) user entry and
    # hide it from the post-merge validation, violating the contract that a
    # malformed preexisting override is refused and left untouched. The user
    # must fix the file by hand first.
    clobbered = sorted({cli for cli, _, _ in targets
                        if cli in commands and not isinstance(commands[cli], dict)})
    if clobbered:
        print("yolt-review: refusing to edit {} — existing non-dict command "
              "spec(s): {} (fix the file by hand first)".format(
                  override_path, ", ".join(clobbered)), file=sys.stderr)
        return 1
    for cli, fragment, _ in targets:
        existing_spec = commands.get(cli)
        if not isinstance(existing_spec, dict):
            existing_spec = {}
        commands[cli] = merge_command_fragment(existing_spec, fragment)

    # Validate the merged-with-defaults result before writing: the hook loads
    # default rules ∪ this override and a single bad key downgrades it all to
    # rules-validation-error. Reuse merge_shell_overrides so this check runs
    # the exact merge the hook performs.
    rules_dir = resolve_rules_dir(args.rules_dir)
    try:
        default_rules = load_shell_rules(rules_dir, user_overrides_path=None,
                                         validate=False)
    except (OSError, ValueError) as e:
        print("yolt-review: cannot load default rules from {}: {}".format(
            rules_dir, e), file=sys.stderr)
        return 1
    merged = json.loads(json.dumps(default_rules))  # deep copy
    merge_shell_overrides(merged, user_override)
    errors = validate_shell_rules(merged)
    if errors:
        print("yolt-review: refusing to write {} — merged rules fail "
              "validation:".format(override_path), file=sys.stderr)
        for err in errors:
            print("  - {}".format(err), file=sys.stderr)
        return 1

    _atomic_write_json(override_path, user_override)

    for _, _, suggestion in targets:
        suggestion["status"] = "applied"
    save_state(state_path, state)
    doc = render_doc(state, resolve_log_path(args.log),
                     resolve_ran_log_path(args.ran_log))
    with open(state_dir / DOC_NAME, "w") as f:
        f.write(doc)

    print("yolt-review: wrote {} override(s) to {}; marked {} applied".format(
        len(targets), override_path, len(targets)))
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="YOLT self-improvement reviewer (issue #44)")
    parser.add_argument("--log", help="decision log path override")
    parser.add_argument("--ran-log", help="ran log path override")
    parser.add_argument("--state-dir", help="state dir override")
    parser.add_argument("--rules-dir", help="bundled rules dir override")
    parser.add_argument("--shell-override",
                        help="user shell-override file path override")
    parser.add_argument("--min-fires", type=int, default=MIN_FIRES_FRICTION)
    parser.add_argument("--min-fires-safe", type=int, default=MIN_FIRES_FASTPATH)
    parser.add_argument(
        "--if-stale", action="store_true",
        help="with --generate: no-op when the log is unchanged since the "
             "last run (SessionEnd auto-regeneration)")
    parser.add_argument("--quiet", action="store_true")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--generate", action="store_true")
    group.add_argument("--status", action="store_true")
    group.add_argument("--nudge", action="store_true")
    group.add_argument("--list", action="store_true")
    group.add_argument("--applied", nargs="+", metavar="ID", dest="applied_ids")
    group.add_argument("--dismiss", nargs="+", metavar="ID", dest="dismiss_ids")
    group.add_argument("--write-override", nargs="+", metavar="ID",
                       dest="write_override_ids",
                       help="write safe_subcommands override(s) for the given "
                            "suggestion id(s) to ~/.claude/yolt/shell.json")
    args = parser.parse_args()

    retval = 0
    if args.generate:
        retval = cmd_generate(args)
    elif args.status:
        retval = cmd_status(args)
    elif args.nudge:
        retval = cmd_nudge(args)
    elif args.list:
        retval = cmd_list(args)
    elif args.applied_ids:
        args.ids = args.applied_ids
        retval = cmd_mark(args, "applied")
    elif args.dismiss_ids:
        args.ids = args.dismiss_ids
        retval = cmd_mark(args, "dismissed")
    elif args.write_override_ids:
        args.ids = args.write_override_ids
        retval = cmd_write_override(args)
    return retval


if __name__ == "__main__":
    sys.exit(main())
