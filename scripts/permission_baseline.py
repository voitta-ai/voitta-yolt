#!/usr/bin/env python3
"""Permission-friction baseline from local Claude Code artifacts.

Measures what is actually recoverable, and is explicit about what is not.

RECOVERABLE
  - tool calls          : every `tool_use` block in the transcripts (denominator)
  - rejections          : the operator was prompted and said NO
                          ("Permission denied by user", "user doesn't want to proceed")
  - YOLT decisions      : from yolt.log, incl. how many were `unsafe` (YOLT's own asks)

NOT RECOVERABLE, and this is the whole methodological point
  - prompt volume. A prompt the operator APPROVED is indistinguishable in
    every local artifact from a call that was never gated at all: the tool
    simply runs and the transcript records a normal result. Claude Code
    keeps no local counter either (`tengu_auto_mode_config.outcomeVisibility`
    is false, and no statsig/telemetry store exists on disk).

    So "how often was I interrupted" cannot be counted after the fact. Any
    gate built on it has to use the rejection rate as a proxy plus an
    operator judgment recorded at the time.

Usage: python3 baseline.py [--since YYYY-MM-DD] [--json]
"""

import argparse
import collections
import json
import os
import sys
from pathlib import Path

HOME = Path.home()
PROJECTS = HOME / ".claude" / "projects"
YOLT_LOG = HOME / ".claude" / "yolt.log"

REJECTION_MARKERS = (
    "permission denied by user",
    "the user doesn't want to proceed with this tool use",
)

# Workload classes. Friction is not uniform across them: infra work is
# aws/kubectl/terraform/gh heavy, which is where the gated commands live.
# Measuring on the wrong class gives a number that does not transfer.
def workload_class(project_dir):
    name = project_dir.name
    if "git-clickagy" in name:
        return "infra"
    if "voitta-yolt" in name:
        return "yolt-itself"
    return "other"


def iter_records(path):
    try:
        fh = open(path, errors="replace")
    except OSError:
        return
    with fh:
        for line in fh:
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue


def day_of(record):
    ts = record.get("timestamp") or ""
    return ts[:10]


def collect(since=None, exclude_session=None):
    stats = collections.defaultdict(lambda: collections.Counter())
    per_tool_calls = collections.Counter()
    per_tool_rejects = collections.Counter()
    days = set()
    files = 0

    for project in sorted(PROJECTS.glob("*")):
        if not project.is_dir():
            continue
        klass = workload_class(project)
        for transcript in project.glob("*.jsonl"):
            if exclude_session and exclude_session in transcript.name:
                continue
            files += 1
            for rec in iter_records(transcript):
                day = day_of(rec)
                if since and day and day < since:
                    continue
                if day:
                    days.add(day)

                msg = rec.get("message") or {}
                content = msg.get("content")
                if isinstance(content, list):
                    for block in content:
                        if isinstance(block, dict) and block.get("type") == "tool_use":
                            stats[klass]["tool_calls"] += 1
                            per_tool_calls[block.get("name") or "?"] += 1

                tur = rec.get("toolUseResult")
                if tur is None:
                    continue
                text = tur if isinstance(tur, str) else json.dumps(tur)
                low = text.lower()
                if any(m in low for m in REJECTION_MARKERS):
                    stats[klass]["rejections"] += 1
                    # attribute to the tool whose result this is
                    name = None
                    if isinstance(content, list):
                        for block in content:
                            if isinstance(block, dict) and block.get("type") == "tool_result":
                                name = block.get("name")
                    per_tool_rejects[name or "?"] += 1

    return stats, per_tool_calls, per_tool_rejects, sorted(days), files


def yolt_baseline(since=None):
    counts = collections.Counter()
    per_day = collections.Counter()
    if not YOLT_LOG.exists():
        return counts, per_day
    for rec in iter_records(YOLT_LOG):
        day = (rec.get("ts") or "")[:10]
        if since and day and day < since:
            continue
        decision = rec.get("decision")
        if decision in ("safe", "unsafe", "unknown"):
            counts[decision] += 1
            if day:
                per_day[day] += 1
    return counts, per_day


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--since", default=None, help="YYYY-MM-DD lower bound")
    ap.add_argument("--exclude-session", default=None)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    stats, tool_calls, tool_rejects, days, files = collect(
        args.since, args.exclude_session)
    ydec, yday = yolt_baseline(args.since)

    total_calls = sum(s["tool_calls"] for s in stats.values())
    total_rej = sum(s["rejections"] for s in stats.values())

    out = {
        "window": {"first_day": days[0] if days else None,
                   "last_day": days[-1] if days else None,
                   "distinct_days": len(days),
                   "transcripts": files},
        "totals": {"tool_calls": total_calls, "rejections": total_rej,
                   "rejections_per_100_calls":
                       round(100.0 * total_rej / total_calls, 3) if total_calls else None},
        "by_workload": {
            k: {"tool_calls": v["tool_calls"],
                "rejections": v["rejections"],
                "rejections_per_100_calls":
                    round(100.0 * v["rejections"] / v["tool_calls"], 3)
                    if v["tool_calls"] else None}
            for k, v in sorted(stats.items())
        },
        "top_tools_by_calls": tool_calls.most_common(12),
        "yolt_log": {
            "decisions": dict(ydec),
            "unsafe_share":
                round(100.0 * ydec["unsafe"] / sum(ydec.values()), 2)
                if sum(ydec.values()) else None,
            "active_days": len(yday),
        },
        "not_measurable": [
            "prompt volume (approved prompts are indistinguishable from "
            "ungated calls in every local artifact)",
        ],
    }

    if args.json:
        print(json.dumps(out, indent=2))
        return

    w = out["window"]
    print("PERMISSION-FRICTION BASELINE")
    print("=" * 60)
    print("window        : {} .. {}  ({} distinct days, {} transcripts)".format(
        w["first_day"], w["last_day"], w["distinct_days"], w["transcripts"]))
    print("tool calls    : {:,}".format(out["totals"]["tool_calls"]))
    print("rejections    : {:,}   ({} per 100 calls)".format(
        out["totals"]["rejections"], out["totals"]["rejections_per_100_calls"]))
    print()
    print("BY WORKLOAD (friction is not uniform; measure on the right one)")
    print("-" * 60)
    print("  {:14s} {:>10s} {:>12s} {:>12s}".format(
        "class", "calls", "rejections", "per 100"))
    for k, v in out["by_workload"].items():
        print("  {:14s} {:>10,} {:>12,} {:>12}".format(
            k, v["tool_calls"], v["rejections"], v["rejections_per_100_calls"]))
    print()
    print("TOP TOOLS BY CALL VOLUME")
    print("-" * 60)
    for name, n in out["top_tools_by_calls"]:
        print("  {:28s} {:>8,}".format(name, n))
    print()
    print("YOLT LOG (bucket B proxy: YOLT's own objections)")
    print("-" * 60)
    y = out["yolt_log"]
    for k, v in sorted(y["decisions"].items()):
        print("  {:10s} {:>8,}".format(k, v))
    print("  unsafe share: {}%   over {} active days".format(
        y["unsafe_share"], y["active_days"]))
    print()
    print("NOT MEASURABLE")
    print("-" * 60)
    for item in out["not_measurable"]:
        print("  - " + item)


if __name__ == "__main__":
    main()
