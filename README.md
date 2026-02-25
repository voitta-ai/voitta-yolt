# YOLT - You Only Live Twice

A Claude Code hook that statically analyzes Python scripts before execution,
auto-allowing safe scripts and flagging destructive ones for review.

## How it works

YOLT registers as a `PreToolUse` hook on the `Bash` tool. When Claude Code
runs `python3 script.py`, YOLT:

1. Extracts the script path (or `-c` inline code)
2. Parses the Python AST (zero external dependencies)
3. Walks all function calls, checking against configurable safety rules
4. **Safe** scripts get auto-allowed (no permission prompt)
5. **Destructive** scripts prompt for user review with details on what was detected

## Install

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "/path/to/voitta-yolt/hooks/pre-tool-use.sh"
          }
        ]
      }
    ]
  }
}
```

## Rules

Default rules cover:

- **AWS boto3** - `describe/list/get/head` safe; `delete/put/create/terminate` destructive
- **File I/O** - `open()` write modes, `os.remove`, `shutil.rmtree`, etc.
- **Subprocess** - `subprocess.run`, `os.system`, etc. (always flagged)
- **Network** - `requests.get` safe; `requests.post/put/delete` destructive
- **Database** - connection creation flagged for review

Rules use `trigger_imports` to scope checks. For example, boto3 patterns only
apply when `boto3` is imported, so `cache.delete_item()` in a non-AWS script
won't false-positive.

## Custom rules

Create `~/.claude/yolt/rules.json` to override defaults:

```json
{
  "_safe_imports": ["pandas", "numpy"],
  "aws_boto3": {
    "safe_methods": ["start_query_execution"]
  },
  "my_sdk": {
    "trigger_imports": ["my_sdk"],
    "safe_methods": ["fetch_*"],
    "destructive_methods": ["drop_*"]
  }
}
```

User overrides merge with (and override) defaults per-key.

## CLI usage

Analyze a script directly:

```bash
python3 hooks/yolt_analyzer.py script.py
```

Returns JSON with `safe: true/false`, findings, and import analysis.

## Design principles

- **Zero dependencies** - stdlib only (`ast`, `json`, `fnmatch`, `shlex`)
- **False positives OK, false negatives not** - when in doubt, ask
- **Configurable** - rules are data, not code
- **Fast** - AST parsing is near-instant for typical scripts
