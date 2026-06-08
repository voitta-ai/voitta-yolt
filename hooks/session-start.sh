#!/bin/bash
# YOLT (You Only Live Twice) - SessionStart hook for Claude Code.
#
# Reads the suggestion state written by hooks/yolt_review.py (issue #44)
# and, when there are pending suggestions that have not been surfaced in
# the last NUDGE_INTERVAL_HOURS, prints a one-line additionalContext
# nudge pointing the user at /yolt:review. Silent otherwise.
#
# Deliberately cheap: it only reads the small state JSON, never parses
# the decision log (that happens at SessionEnd). Needs no grammar deps.
# Best-effort: any failure exits silently so SessionStart never breaks.
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

exec python3 "$SCRIPT_DIR/yolt_review.py" --nudge
