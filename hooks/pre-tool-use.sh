#!/bin/bash
# YOLT (You Only Live Twice) - PreToolUse hook for Claude Code.
#
# Two responsibilities:
#   1. Bootstrap the two grammar deps (tree-sitter, tree-sitter-bash) on
#      first run, so plugin install gives users a working hook out of
#      the box without a separate `pip install` step. The bootstrap runs
#      once per requirements.txt content hash, marker lives under
#      $HOME/.cache/yolt/ so it survives plugin reinstalls.
#   2. Exec the Python analyzer to actually classify the command.
#
# The bootstrap is best-effort: if it fails (pip locked down, no network,
# unsupported platform), the analyzer is still invoked. yolt_analyzer.py
# records the ImportError in $YOLT_LOG_FILE so the user can see why YOLT
# silently no-ops.
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
YOLT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REQS="$YOLT_ROOT/requirements.txt"

bootstrap_deps() {
    # Marker is keyed to requirements.txt content so a dep bump triggers
    # re-bootstrap. Once set, subsequent hook fires skip even the import
    # probe — bash file-exists test only, ~ms.
    local cache_dir="$HOME/.cache/yolt"
    local sha
    if command -v shasum >/dev/null 2>&1; then
        sha="$(shasum -a 256 "$REQS" 2>/dev/null | awk '{print substr($1,1,12)}')"
    elif command -v sha256sum >/dev/null 2>&1; then
        sha="$(sha256sum "$REQS" 2>/dev/null | awk '{print substr($1,1,12)}')"
    else
        sha="nohash"
    fi
    local marker="$cache_dir/deps-installed-$sha"

    # Hot path: marker exists, trust it. If the user removed the package
    # since the marker was set (venv switch, manual uninstall), the
    # analyzer will ImportError and log import-error to YOLT_LOG_FILE —
    # the user can delete the marker to force re-bootstrap.
    if [[ -f "$marker" ]]; then
        return 0
    fi

    mkdir -p "$cache_dir" 2>/dev/null

    # Already importable from a previous manual install? Record marker,
    # done. Costs one python3 startup the first time, never again.
    if python3 -c "import tree_sitter, tree_sitter_bash" 2>/dev/null; then
        touch "$marker"
        return 0
    fi

    # Try `--user` first (works on most setups). Fall back to
    # `--break-system-packages` for PEP 668 environments (recent Debian,
    # Homebrew Python on macOS). All output discarded; pip is noisy.
    if python3 -m pip install --quiet --user --disable-pip-version-check \
            -r "$REQS" >/dev/null 2>&1; then
        touch "$marker"
        return 0
    fi
    if python3 -m pip install --quiet --user --disable-pip-version-check \
            --break-system-packages -r "$REQS" >/dev/null 2>&1; then
        touch "$marker"
        return 0
    fi

    # Bootstrap failed. Don't mark; retry next time. Hook still execs
    # the analyzer below, which logs ImportError to YOLT_LOG_FILE.
    return 1
}

bootstrap_deps || true

exec python3 "$SCRIPT_DIR/yolt_analyzer.py" --hook
