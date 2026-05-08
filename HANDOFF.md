# YOLT — Handoff

WIP. Major rewrite landed; dogfood QA pending.

## Current state of `master`

| Commit | Title |
| --- | --- |
| `e661abf` | Default YOLT_LOG_FILE to ~/.claude/yolt.log (#7) |
| `f349de1` | Add YOLT_LOG_FILE for dogfood / QA visibility (#6) |
| `37de4da` | Rewrite shell decomposition on tree-sitter-bash AST (#5) |
| `8d93b32` | Fix marketplace.json source path |
| `9c10009` | Fix marketplace.json source path to use ./ prefix |
| `d05939c` | Update demo to use master |
| `966fc41` | Document update + manual-to-plugin migration in README |
| `85a8545` | Ship YOLT as a Claude Code plugin |

Tests: 140 passing locally.

## Architecture (post-rewrite)

```
hooks/grammar_classifier.py   tree-sitter-bash AST visitor (public entry)
hooks/rule_classifier.py      argv-level rule lookup (rules/shell.json)
hooks/yolt_analyzer.py        Python AST analyzer + hook entry
hooks/pre-tool-use.sh         plugin hook entry
hooks/hooks.json              registers PreToolUse on Bash
rules/shell.json              shell rule data
rules/default.json            python rule data
requirements.txt              tree-sitter, tree-sitter-bash
.claude-plugin/marketplace.json  plugin metadata
```

The hook flow:

1. Claude Code fires `PreToolUse` → `hooks/pre-tool-use.sh` → `python3 hooks/yolt_analyzer.py --hook`.
2. Hook reads JSON payload from stdin. If non-Bash or empty command, exit 0.
3. Try to import `grammar_classifier` (which imports `tree_sitter_bash`).
   - On `ImportError` (tree-sitter-bash missing on host), log `import-error` to `~/.claude/yolt.log` and exit 0 silently. Claude Code falls through to its default prompt.
4. Otherwise, parse and walk the AST. Classify each `command` node, aggregate decisions per `unsafe > unknown > safe`.
5. Emit hook response: `allow` / `ask` / silent fallthrough. Append a JSON record to `~/.claude/yolt.log` regardless.

## What's tested

- 140 unit tests, all green. Coverage:
  - argv-level helpers (`tests/test_rule_classifier.py`)
  - end-to-end via `GrammarClassifier.classify()` (`tests/test_grammar_classifier.py`)
  - subprocess hook entry (`tests/test_yolt_hook.py`)
  - log file: safe/unsafe/unknown decisions, append, default location, opt-out, command truncation, unwritable path.
- Smoke test against the hook subprocess produces correct decisions on:
  - bash `'\''` quote idiom inside `$(...)` — the trigger bug for the rewrite.
  - process-substitution destructive inner (`diff <(ls /a) <(rm -rf /a)` → unsafe).
  - heredoc python body (safe / unsafe paths classify correctly).
  - bash -c re-parse and recurse.
  - aws CLI service overrides.

## What's NOT tested (the QA plan)

Real Claude Code session, fresh install, on commands the user actually types.

The Claude Code UI hides YOLT's contribution when `permissions.allow` already covers a command, so the log is the ground truth:

```bash
tail -f ~/.claude/yolt.log
```

### QA test plan

In a fresh Claude Code session (after `/plugin install yolt@voitta-yolt`):

1. **Step 0 — verify deps.** Run `python3 -c "import tree_sitter_bash"` once. If `ModuleNotFoundError`, install: `pip3 install --user -r ~/.claude/plugins/marketplaces/voitta-yolt/yolt/requirements.txt` (path may differ — `find ~/.claude -name requirements.txt -path '*yolt*'`). Without these, the log records `decision: "import-error"`.

2. **Step 1 — outer-matcher-proof shapes** (categorically force YOLT past your `permissions.allow`):

   ```bash
   bash -c "ls /tmp"                          # -> safe
   for x in 1 2 3; do echo $x; done           # -> safe
   diff <(echo a) <(echo b)                   # -> safe
   diff <(ls /tmp) <(rm -rf /tmp/yolt-qa-fake)  # -> unsafe (inner rm)
   ```

3. **Step 2 — trigger bug fix.** This is the whole reason for PR #5.

   ```bash
   TOKEN=$(grep -E '^GRAFANA' ~/.bash_profile | head -1 | sed 's/^GRAFANA=//; s/"//g; s/'\''//g'); echo "len=${#TOKEN}"
   ```
   Expected: log shows `decision: "safe"`, `reason` mentions grep / head / sed read-only.

4. **Step 3 — heredoc.**
   ```bash
   python3 << 'EOF'
   import json
   print(json.dumps({"status": "ok"}))
   EOF
   ```
   Expected: `safe`, reason `python: python3 <<heredoc`.

   ```bash
   python3 << EOF
   import os
   os.system("echo would-rm")
   EOF
   ```
   Expected: `unsafe`, reason includes `L2: os.system`.

5. **Step 4 — real session.** Run for an hour. Read the log. Look for surprises.

### What to capture if YOLT misbehaves

- The exact command (copy from log's `command` field, truncated at 500 chars).
- The `decision` and `reason` from the log.
- Open an issue on `voitta-ai/voitta-yolt` with the repro:
  ```bash
  cd ~/g/git.voitta/voitta-yolt
  python3 hooks/grammar_classifier.py '<paste cmd>'
  ```
  prints `{"decision": ..., "reason": ...}`. Include that output in the issue.

## Known limitations

- **Plugin install does not auto-install Python deps.** Until the bootstrap PR lands, users must manually `pip install -r requirements.txt` after `/plugin install yolt@voitta-yolt`. Without it, the hook silently no-ops (visible only in the log as `import-error`).
- **`python3 -m <mod>` is not first-class.** Falls through to `unknown` unless allowlisted. `python3 -m json.tool` is benign but YOLT can't tell.
- **Argv reconstruction for deeply-nested `bash -c` keeps literal escape sequences.** E.g. `bash -c "ls; bash -c \"rm\""` may not classify the deepest `rm` correctly because `\"` survives in argv. Real-world `bash -c` rarely nests this deep.
- **Log grows unbounded.** No rotation. Truncate manually if it gets uncomfortable.
- **Tree-sitter parse errors → unknown.** Conservative; some malformed-but-clearly-safe commands (e.g. unterminated quotes) won't auto-allow. Acceptable bias.

## Open follow-ups

| Priority | Work |
| --- | --- |
| High | Bootstrap pip install in `pre-tool-use.sh` so plugin install is one-click. Cache success in a marker file. Fall back to silent-exit on pip failure. |
| Medium | First-class `python3 -m` rules (safe list: `json.tool`, `http.server` is unsafe, etc.). |
| Medium | Log rotation when file > 5MB. |
| Low | Argv reconstruction: decode shell escapes during string concatenation so deeply-nested `bash -c` works correctly. |

## How to repro any decision locally

```bash
cd ~/g/git.voitta/voitta-yolt
python3 hooks/grammar_classifier.py '<paste cmd verbatim>'
# Output: {"decision": "...", "reason": "..."}
```

Same code path as the hook minus the I/O. Faithful repro.

## Test commands

```bash
pip install -r requirements.txt          # one-time
python3 -m unittest discover -v tests    # 140 tests, ~1.7s
./examples/demo.sh                       # visual scan
```

## Pointers

- Design rationale + survey of bash parser options: [issue #4](https://github.com/voitta-ai/voitta-yolt/issues/4)
- Rewrite PR (closed #4): [#5](https://github.com/voitta-ai/voitta-yolt/pull/5)
- Log feature: [#6](https://github.com/voitta-ai/voitta-yolt/pull/6)
- Default log path: [#7](https://github.com/voitta-ai/voitta-yolt/pull/7)
