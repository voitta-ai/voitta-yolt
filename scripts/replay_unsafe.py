#!/usr/bin/env python3
"""Replay a YOLT decision log through a classifier and report the `unsafe` set.

This is the gate for Phase 3 (#100), and the artifact for its "capture the
retired judgement before deleting it" requirement.

WHY A REPLAY AND NOT A WINDOW

  Post-Phase-1 the decision mapping is:

      safe    -> exit silently, same as unknown
      unsafe  -> permissionDecision: ask (deny inside a subagent)
      unknown -> exit silently

  `safe` and `unknown` are indistinguishable to the host. So deleting the
  per-CLI subcommand tables -- the bulk of what Phase 3 removes -- moves
  commands from `safe` to `unknown`, which is a no-op at the host. It changes
  the log and nothing else.

  The one behavioral risk is the opposite direction: a command that is
  `unsafe` today losing its classification and becoming `unknown`. That is an
  `ask` silently disappearing, and it is the only way Phase 3 can change what
  the operator experiences. It is fully enumerable offline against a corpus
  that already exists, so this needs no measurement window at all.

USAGE

  Baseline, against the build that produced the corpus:

    python3 replay_unsafe.py \
        --hooks-dir ~/g/git.voitta/voitta-yolt.worktrees/auto-mode-realignment/hooks \
        --json > baseline.json

  Candidate, against a Phase 3 branch, reporting what would lose its `ask`:

    python3 replay_unsafe.py --hooks-dir <phase3>/hooks --diff baseline.json

THE AGREEMENT CHECK IS LOAD-BEARING

  The log records the decision each command actually received. Replaying
  should reproduce it. The agreement rate is printed first and is the signal
  that the harness is pointed at the right code: a baseline run that does not
  agree with its own corpus is measuring some other build, and every number
  after it is meaningless.

  Allow-pattern resolution is OFF by default. `run_hook` reads the operator's
  real `~/.claude/settings.json`, which would make results machine-specific
  (the hermeticity problem in #75). Pass --allow-patterns to opt in.
"""

import argparse
import collections
import inspect
import json
import sys
from pathlib import Path


def load_corpus(log_path, cap, include_truncated):
    """Unique commands from a YOLT decision log, with their logged decision.

    Later records win: a command reclassified after a rules change should be
    compared against the newer verdict, not the stale one.

    Commands at exactly `cap` characters were TRUNCATED by the log writer
    (`_log_hook_decision` stores `command[:500]`). They are excluded by
    default and this is not a nicety: a cut compound command loses its
    trailing segments, and those are disproportionately the mutating ones
    (`&& git push`, `&& gh pr merge`). Replaying them reproduces the logged
    verdict only 55% of the time against 99.6% for intact commands, so
    including them buries a correct result under an artifact of the log
    format.
    """
    seen = {}
    truncated = 0
    with open(log_path, errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            command = record.get("command")
            decision = record.get("decision")
            # Internal bookkeeping rows (import-error, rules-validation-error)
            # carry no classification and must not dilute the agreement rate.
            if not command or decision not in ("safe", "unsafe", "unknown"):
                continue
            if len(command) >= cap:
                truncated += 1
                if not include_truncated:
                    continue
            seen[command] = decision
    retval = (seen, truncated)
    return retval


def build_classifier(hooks_dir, rules_dir, use_allow_patterns):
    """Import the classifier from an arbitrary checkout and wire it up."""
    sys.path.insert(0, str(hooks_dir))
    from grammar_classifier import GrammarClassifier
    from rule_classifier import load_shell_rules, load_allow_patterns
    from yolt_analyzer import SafetyAnalyzer, load_rules

    shell_rules = load_shell_rules(rules_dir=rules_dir)
    py_rules = load_rules(rules_dir=rules_dir)

    kwargs = {"python_analyzer_factory": lambda: SafetyAnalyzer(py_rules)}

    # Phase 1 (#98) removed the allow-pattern wiring from GrammarClassifier,
    # since nothing emits `allow` any more. Probe the signature rather than
    # assume: this harness has to run against pre- and post-Phase-1 builds to
    # be useful, and the whole point is comparing two of them.
    accepts_allow = "allow_patterns" in inspect.signature(
        GrammarClassifier.__init__).parameters
    if use_allow_patterns and not accepts_allow:
        print("note: this build has no allow-pattern wiring; "
              "--allow-patterns ignored", file=sys.stderr)
    if accepts_allow:
        kwargs["allow_patterns"] = load_allow_patterns([
            Path.home() / ".claude" / "settings.json",
        ]) if use_allow_patterns else None

    classifier = GrammarClassifier(shell_rules, **kwargs)
    retval = classifier
    return retval


def replay(classifier, corpus):
    """Classify every command; return {command: (decision, reason)}."""
    results = {}
    for command in corpus:
        try:
            decision, reason = classifier.classify(command)
        except Exception as exc:  # noqa: BLE001 - a crash is a result too
            decision, reason = "error", f"{type(exc).__name__}: {exc}"
        results[command] = (decision, reason)
    retval = results
    return retval


def agreement(corpus, results):
    matched = sum(1 for cmd, logged in corpus.items()
                  if results[cmd][0] == logged)
    retval = (matched, len(corpus))
    return retval


def unsafe_by_reason(results):
    grouped = collections.defaultdict(list)
    for command, (decision, reason) in results.items():
        if decision == "unsafe":
            grouped[reason].append(command)
    retval = grouped
    return retval


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--log",
        default=str(Path.home() / ".claude" / "yolt-measure.log"),
        help="YOLT decision log to replay (default: ~/.claude/yolt-measure.log)",
    )
    parser.add_argument(
        "--hooks-dir",
        required=True,
        help="hooks/ of the checkout whose classifier to run",
    )
    parser.add_argument(
        "--rules-dir",
        help="rules/ to load (default: sibling of --hooks-dir)",
    )
    parser.add_argument(
        "--allow-patterns",
        action="store_true",
        help="resolve the operator's real permissions.allow (machine-specific)",
    )
    parser.add_argument(
        "--diff",
        metavar="BASELINE.json",
        help="report commands that were unsafe in BASELINE and are not now",
    )
    parser.add_argument(
        "--truncation-cap",
        type=int,
        default=500,
        help="log writer's command cap; records at this length are truncated",
    )
    parser.add_argument(
        "--include-truncated",
        action="store_true",
        help="replay truncated records too (they cannot agree; see --help)",
    )
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument(
        "--examples",
        type=int,
        default=3,
        help="example commands to print per reason (default 3)",
    )
    args = parser.parse_args()

    hooks_dir = Path(args.hooks_dir).expanduser().resolve()
    rules_dir = Path(args.rules_dir).expanduser().resolve() if args.rules_dir \
        else hooks_dir.parent / "rules"

    corpus, truncated = load_corpus(
        Path(args.log).expanduser(), args.truncation_cap,
        args.include_truncated)
    if not corpus:
        print(f"no classified records in {args.log}", file=sys.stderr)
        return 1

    classifier = build_classifier(hooks_dir, rules_dir, args.allow_patterns)
    results = replay(classifier, corpus)
    matched, total = agreement(corpus, results)
    grouped = unsafe_by_reason(results)
    unsafe_commands = sorted(
        cmd for cmd, (decision, _r) in results.items() if decision == "unsafe"
    )

    lost = None
    if args.diff:
        baseline = json.loads(Path(args.diff).read_text())
        was_unsafe = set(baseline.get("unsafe_commands", []))
        lost = sorted(
            cmd for cmd in was_unsafe
            if results.get(cmd, ("absent", ""))[0] != "unsafe"
        )

    if args.as_json:
        payload = {
            "log": str(args.log),
            "hooks_dir": str(hooks_dir),
            "rules_dir": str(rules_dir),
            "commands": total,
            "truncated_records": truncated,
            "included_truncated": args.include_truncated,
            "agreement": {"matched": matched, "total": total},
            "unsafe_commands": unsafe_commands,
            "unsafe_by_reason": {r: sorted(c) for r, c in grouped.items()},
        }
        if lost is not None:
            payload["lost_unsafe"] = lost
        print(json.dumps(payload, indent=2))
        return 0

    pct = 100.0 * matched / total if total else 0.0
    kept = "including" if args.include_truncated else "excluding"
    print(f"corpus:    {total} unique commands from {args.log}")
    print(f"           {truncated} truncated at {args.truncation_cap} chars "
          f"({kept} them)")
    print(f"classifier: {hooks_dir}")
    print(f"rules:      {rules_dir}")
    print(f"agreement with logged decision: {matched}/{total} ({pct:.1f}%)")
    if pct < 99.0:
        print("  WARNING: low agreement -- is --hooks-dir the build that "
              "produced this log?")
    print()
    print(f"unsafe: {len(unsafe_commands)} commands across "
          f"{len(grouped)} distinct reasons")
    print()
    for reason, commands in sorted(grouped.items(),
                                   key=lambda kv: -len(kv[1])):
        print(f"  {len(commands):>5}  {reason}")
        for command in sorted(commands)[:args.examples]:
            flat = " ".join(command.split())
            print(f"         {flat[:96]}")
        if len(commands) > args.examples:
            print(f"         ... {len(commands) - args.examples} more")

    if lost is not None:
        print()
        print(f"LOST unsafe vs {args.diff}: {len(lost)} commands")
        print("Each one is an `ask` that silently disappears. Review every "
              "shape before shipping.")
        for command in lost[:40]:
            flat = " ".join(command.split())
            print(f"  {flat[:110]}")
        if len(lost) > 40:
            print(f"  ... {len(lost) - 40} more (use --json for the full set)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
