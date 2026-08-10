#!/bin/bash
# YOLT (You Only Live Twice) - UserPromptSubmit hook for Claude Code.
#
# Offers /yolt:contribute once per session, when THIS session has hit
# enough distinct Bash friction to be worth looking at while the context
# that produced it is still in the window. That timing is the whole point:
# a log line records that `foo bar` prompted, but only the live session
# still knows what you were doing and why the prompt was wrong.
#
# The SessionStart nudge (--nudge) is the other half and points at
# accumulated, already-distilled suggestions via /yolt:review. This one is
# about the session you are in.
#
# It is an offer. The injected context says so, and says explicitly that a
# declined offer is dropped for the rest of the session.
#
# Cheap by construction: reads the decision log from a stored byte offset,
# never from the top, and fires at most once per session. Best-effort --
# any failure exits silently so a prompt is never blocked.
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

exec python3 "$SCRIPT_DIR/yolt_review.py" --session-nudge
