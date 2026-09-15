#!/usr/bin/env python3
"""Auto-mode refusal rate, from the local transcript store.

The successor measurement to `permission_baseline.py`, and the gate that
replaces the operator-judgment criterion retired in #98.

WHAT THIS COUNTS, AND WHY IT IS NOT WHAT permission_baseline.py COUNTS

  `permission_baseline.py` counts *operator* rejections -- the human was
  prompted and said no ("Permission denied by user"). This script counts
  *auto mode* refusals -- the host's own classifier declined the call and
  the operator was never asked.

  They are different populations and their counts must never be mixed. On
  the same store in 2026-08 the operator-rejection instrument reported 10
  hits across 53 active days while this one reported 20; neither number is
  wrong, they are answering different questions.

WHY THE AUTO-MODE REFUSAL IS THE USEFUL SIGNAL NOW

  `permission_baseline.py` established that prompt volume is unrecoverable:
  an approved prompt is indistinguishable from an ungated call. That killed
  the direct measurement of "did friction rise", and the fallback was an
  operator judgment recorded at the end of each day. That criterion failed
  to produce a result twice (#98) and is retired.

  Auto-mode refusals survive in the transcript as `tool_result` blocks, so
  they are recoverable retrospectively and need nobody to remember anything.
  They are the observable tail of the same distribution: before Phase 1, a
  YOLT `allow` short-circuited the permission check and auto mode never saw
  the call; after Phase 1 it does, and refuses some fraction of what it sees.

  The tail is not the body. This does not give prompt volume. It gives the
  direction and rough magnitude of the change, which is what the gate needs.

NORMALIZATION

  Denials are reported per 1,000 transcript records rather than per day,
  because daily work volume varies by more than an order of magnitude and
  raw daily counts are dominated by that rather than by any policy change.

Usage:
  python3 denial_rate.py                       # per-day table + pre/post split
  python3 denial_rate.py --switch 2026-08-17   # set the before/after boundary
  python3 denial_rate.py --detail              # also list what was refused
  python3 denial_rate.py --json
"""

import argparse
import collections
import datetime
import json
from pathlib import Path

HOME = Path.home()
PROJECTS = HOME / ".claude" / "projects"

# The refusal text the host writes into the tool_result. Matched anchored at
# the start of the block, with the optional "Error: " prefix the host adds on
# some paths. An unanchored substring match also hits transcripts that merely
# *discuss* the refusal -- this file's own docstring would match one.
MARKER = "Permission for this action was denied by the Claude Code auto mode"
PREFIXES = ("", "Error: ")
ANCHORS = tuple(prefix + MARKER for prefix in PREFIXES)


def local_day(stamp):
    """Bucket an ISO timestamp into a LOCAL calendar day.

    UTC bucketing splits a working evening across two days, which silently
    halves the count on whichever day the operator worked latest.
    """
    parsed = datetime.datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    retval = parsed.astimezone().date()
    return retval


def block_text(block):
    """Flatten a tool_result body, which is either a string or a block list."""
    body = block.get("content")
    if isinstance(body, list):
        body = "".join(
            part.get("text", "") for part in body if isinstance(part, dict)
        )
    retval = body if isinstance(body, str) else ""
    return retval


def scan():
    """Walk every transcript once, returning (records, denials, detail)."""
    records = collections.Counter()
    denials = collections.Counter()
    detail = []

    for transcript in sorted(PROJECTS.rglob("*.jsonl")):
        try:
            text = transcript.read_text(errors="replace")
        except OSError:
            continue

        # tool_use blocks arrive before the tool_result that references them,
        # so a single forward pass can resolve every id it needs.
        pending = {}
        for line in text.splitlines():
            if '"timestamp"' not in line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            stamp = record.get("timestamp")
            if not stamp:
                continue

            day = local_day(stamp)
            records[day] += 1

            content = (record.get("message") or {}).get("content")
            if not isinstance(content, list):
                continue

            for block in content:
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "tool_use":
                    pending[block.get("id")] = (
                        block.get("name"),
                        block.get("input") or {},
                    )
                    continue
                if block.get("type") != "tool_result":
                    continue
                if not block_text(block).startswith(ANCHORS):
                    continue

                denials[day] += 1
                tool, args = pending.get(block.get("tool_use_id"), ("?", {}))
                target = args.get("command") or args.get("file_path") or ""
                detail.append((day, tool, str(target)))

    retval = (records, denials, detail)
    return retval


def per_1k(denials, records):
    retval = 1000.0 * denials / records if records else 0.0
    return retval


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--switch",
        metavar="YYYY-MM-DD",
        help="boundary date; days on or after it count as 'after'",
    )
    parser.add_argument(
        "--detail",
        action="store_true",
        help="list each refused call",
    )
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args()

    boundary = None
    if args.switch:
        boundary = datetime.date.fromisoformat(args.switch)

    records, denials, detail = scan()
    if not records:
        print(f"no transcripts under {PROJECTS}")
        return

    days = sorted(records)
    rows = [
        {
            "day": day.isoformat(),
            "records": records[day],
            "denials": denials[day],
            "per_1k": round(per_1k(denials[day], records[day]), 3),
        }
        for day in days
    ]

    split = None
    if boundary:
        before = [day for day in days if day < boundary]
        after = [day for day in days if day >= boundary]
        split = {}
        for label, group in (("before", before), ("after", after)):
            group_records = sum(records[day] for day in group)
            group_denials = sum(denials[day] for day in group)
            split[label] = {
                "days": len(group),
                "records": group_records,
                "denials": group_denials,
                "per_1k": round(per_1k(group_denials, group_records), 3),
            }
        if split["before"]["per_1k"]:
            split["ratio"] = round(
                split["after"]["per_1k"] / split["before"]["per_1k"], 1
            )

    if args.as_json:
        payload = {"days": rows, "split": split}
        if args.detail:
            payload["detail"] = [
                {"day": day.isoformat(), "tool": tool, "target": target}
                for day, tool, target in sorted(detail)
            ]
        print(json.dumps(payload, indent=2))
        return

    print(f"{'day':<12}{'records':>9}{'denials':>9}{'per 1k':>9}")
    for row in rows:
        print(
            f"{row['day']:<12}{row['records']:>9}"
            f"{row['denials']:>9}{row['per_1k']:>9.2f}"
        )

    if split:
        print()
        for label in ("before", "after"):
            side = split[label]
            print(
                f"{label:<7} {args.switch}: {side['denials']:>4} denials"
                f" / {side['records']:>7} records"
                f" = {side['per_1k']:.3f} per 1k"
                f"  ({side['days']} days)"
            )
        if "ratio" in split:
            print(f"ratio:  {split['ratio']}x")

    if args.detail:
        print()
        for day, tool, target in sorted(detail):
            print(f"{day.isoformat()}  {tool:<8} {target[:110]}")


if __name__ == "__main__":
    main()
