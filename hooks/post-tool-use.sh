#!/bin/bash
# YOLT (You Only Live Twice) - PostToolUse hook for Claude Code.
#
# Records that a Bash command actually executed, to ~/.claude/yolt-ran.log.
# Paired with the PreToolUse decision log (~/.claude/yolt.log), this lets
# the self-improvement reviewer (hooks/yolt_review.py, issue #44) tell
# "YOLT prompted and the user approved anyway" (friction worth an
# allowlist/rule) apart from "YOLT prompted and the user declined"
# (working as intended): a command that was denied at the prompt never
# reaches PostToolUse, so its absence here is the signal.
#
# Unlike the PreToolUse hook this needs no grammar deps, so it skips the
# bootstrap entirely and just appends a JSON line. Best-effort: any
# failure exits silently so PostToolUse never breaks the session.
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

exec python3 "$SCRIPT_DIR/yolt_analyzer.py" --ran-hook
