#!/bin/bash
# YOLT (You Only Live Twice) - SessionEnd hook for Claude Code.
#
# Regenerates the self-improvement review doc + suggestion state from the
# session's accumulated decision log (hooks/yolt_review.py, issue #44).
# Guarded by --if-stale: if the decision log has not changed since the
# last generation, this is a no-op and no Python parse happens beyond the
# mtime check, so quiet sessions cost almost nothing.
#
# SessionEnd output is ignored by Claude Code; this runs purely for its
# side effect. Best-effort: any failure exits silently.
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

exec python3 "$SCRIPT_DIR/yolt_review.py" --generate --if-stale --quiet
