#!/bin/bash
# YOLT (You Only Live Twice) - PreToolUse hook for Claude Code
# Delegates to yolt_analyzer.py for Python script safety analysis
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$SCRIPT_DIR/yolt_analyzer.py" --hook
