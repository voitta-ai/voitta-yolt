---
description: Triage YOLT friction into settings.json whitelist entries, local rule overrides, or upstream issues
---

# /yolt:review

Walk the user through the YOLT self-improvement review (issue #44): turn
recurring Bash friction (commands YOLT repeatedly prompted on, or
repeatedly auto-allowed at the cost of hook startup) into concrete
remediations.

The generator (`hooks/yolt_review.py`) does the parsing and bookkeeping;
your job is to present its output, get the user's decisions, and apply
them. Do NOT re-derive suggestions by reading the raw log yourself.

## Steps

1. **Regenerate and load state.** Run, from the plugin's hooks dir:

   ```bash
   python3 "${CLAUDE_PLUGIN_ROOT}/hooks/yolt_review.py" --generate
   python3 "${CLAUDE_PLUGIN_ROOT}/hooks/yolt_review.py" --list
   ```

   `--list` prints the full suggestion JSON. Work from that, not the
   markdown doc. If there are zero pending suggestions, tell the user and
   stop.

2. **Present pending suggestions, grouped by bucket**, in this order:
   - `fastpath` — already auto-allowed; an whitelist entry only saves
     hook startup.
   - `friction-unsafe` — YOLT prompted (`ask`). Sort the user's attention
     by `approved` (how many times they approved at the prompt anyway):
     high `approved` = real friction; `approved` 0 = YOLT very likely
     doing its job, lean toward dismiss.
   - `friction-unknown` — fell through to Claude Code's default prompt.

   For each, show `prefix`, `fires`, `approved` (friction buckets), and
   the recommended destination.

3. **Honor the routing — this is the safety-critical part:**
   - A suggestion with a non-empty `glob_collisions` list MUST NOT be
     written to `settings.json`. Its `Bash(prefix*)` glob would also
     match a known non-safe command (shown in `glob_collisions`), which
     would silently bypass YOLT for that command. Route it to a
     `~/.claude/yolt/shell.json` rule instead (issue #45) and say why.
   - A `fastpath` suggestion with no collisions → offer to add
     `settings_pattern` to `permissions.allow` in
     `~/.claude/settings.json`.
   - A friction suggestion with no collisions that the user confirms is
     read-only regardless of flags → same settings.json route.
   - A friction suggestion that is flag-conditional or verb-class → a
     `~/.claude/yolt/shell.json` / `rules.json` override (issue #45).
   - `upstream_candidate: true` → offer to file an issue on
     voitta-ai/voitta-yolt.

4. **Apply what the user accepts.**
   - settings.json: read `~/.claude/settings.json`, add the pattern to
     `permissions.allow` (create the array if absent), write it back.
     Confirm the exact diff with the user before writing.
   - Local override: edit `~/.claude/yolt/shell.json` per the README's
     "Shell rules" schema. (Direct generation of these is tracked in
     issue #45; for now, hand-write the minimal fragment.)
   - After each accepted suggestion is applied, record it:

     ```bash
     python3 "${CLAUDE_PLUGIN_ROOT}/hooks/yolt_review.py" --applied <id> [<id> ...]
     ```

   - For suggestions the user rejects:

     ```bash
     python3 "${CLAUDE_PLUGIN_ROOT}/hooks/yolt_review.py" --dismiss <id> [<id> ...]
     ```

5. **Upstream issues (only on explicit confirmation).** For
   `upstream_candidate` suggestions the user wants to report:
   - Use ONLY the redacted `shape` field and flag names — never the raw
     `examples`, which contain real paths / account ids / possibly
     secrets. State this to the user.
   - Draft the issue title and body, show it, and create it only after
     the user approves:

     ```bash
     gh issue create --repo voitta-ai/voitta-yolt --title "..." --body-file <tmpfile>
     ```

6. **Summarize**: what was added to settings.json, what overrides were
   written, what was dismissed, what was filed upstream.

## Notes

- A static allow rule in `settings.json` bypasses YOLT's PreToolUse hook
  entirely (including its redirect and command-substitution checks), so
  keep every pattern narrow. This is exactly why collisions are vetoed.
- The reviewer is read-mostly: it only writes its own state files under
  `~/.claude/yolt/`. All edits to `settings.json` and override files go
  through you, with the user's confirmation.
