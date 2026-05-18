# Inline Review Comments Guide

This reference provides the exact process for creating accurate inline review comments on pull request diffs.

## Step 1: Get the Annotated Diff

**Always run this first** to get exact line numbers. Save this script to a file and execute it — do NOT try to inline the awk in a one-liner (escaping breaks it):

```bash
DIFF_SCRIPT=$(mktemp /tmp/annotate-diff-XXXXXX.sh)
cat > "$DIFF_SCRIPT" << 'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
# Usage: bash <script> <pr-number>
# Outputs: file | line=N | +/space content
if [ -z "${1:-}" ]; then
  echo "Error: PR number is required" >&2
  exit 1
fi
gh pr diff "$1" | awk '
/^diff --git/ { in_hunk=0; file="" }
/^\+\+\+ b\// { file=substr($0,7) }
/^@@ / {
  split($3, a, ",")
  right_ln = int(substr(a[1], 2))
  in_hunk=1  # reset on diff --git, not here — diff --git always precedes +++ b/
  next
}
!in_hunk || file=="" { next }
/^\\/ || /^-/ { next }
{
  prefix = (substr($0,1,1) == "+") ? "+" : " "
  printf "%s | line=%-4d | %s %s\n", file, right_ln, prefix, substr($0,2)
  right_ln++
}'
SCRIPT
bash "$DIFF_SCRIPT" "$1"
```

Example output:
```
src/utils.js | line=10   |   const a = 1;       ← context line
src/utils.js | line=11   |   const b = 2;       ← context line
src/utils.js | line=12   | + const d = 4;       ← added line
src/utils.js | line=13   |   const e = 5;       ← context line
```

**Use ONLY the `line` values from this output** when constructing inline comments.

## Step 2: Build the JSON Payload

Write the full review payload to a temp file. Each comment uses `path`, `line`, `side`, and `body`.

The `event` field must be exactly one of: `APPROVE`, `REQUEST_CHANGES`, or `COMMENT` (not `APPROVED`, `REQUESTED_CHANGES`, etc.).

```bash
REVIEW_PAYLOAD=$(mktemp /tmp/review-payload-XXXXXX.json)
cat > "$REVIEW_PAYLOAD" << 'REVIEW_JSON'
{
  "event": "COMMENT",
  "body": "## Review Summary\n\nYour review body here.",
  "comments": [
    {
      "path": "src/utils.js",
      "line": 12,
      "side": "RIGHT",
      "body": "Comment text here"
    }
  ]
}
REVIEW_JSON
```

### Comment fields

| Field | Required | Value |
|---|---|---|
| `path` | Yes | File path exactly as shown in the diff |
| `line` | Yes | The `line` value from the annotated diff output in Step 1 |
| `side` | Yes | Always `"RIGHT"` |
| `body` | Yes | Comment text (supports markdown and suggestion blocks) |

**Do NOT include `subject_type`** — it is not supported on GitHub Enterprise Server and causes 422 errors.

**Do NOT submit the review from this guide.** Return to the SKILL.md instructions for the submission step.

## Suggestion Blocks (Single-Line Only)

Use GitHub's suggestion syntax to provide one-click applicable fixes. **Only single-line suggestions are allowed** — multi-line suggestions frequently produce broken code when applied.

A suggestion replaces the single line targeted by `line`:

````markdown
This should handle the empty case:

```suggestion
  if (items != null && !items.isEmpty()) {
```
````

Example comment object:
```json
{
  "path": "src/service.java",
  "line": 42,
  "side": "RIGHT",
  "body": "This should handle the empty case:\n\n```suggestion\n  if (items != null && !items.isEmpty()) {\n```"
}
```

### Suggestion rules

- **Single-line only** — each suggestion replaces exactly one line (the line at `line`). If a fix spans multiple lines, describe the full fix in the comment body text but only put the most critical single line in the ` ```suggestion ` block, or skip the suggestion block entirely.
- **Preserve indentation** — match the original line's indentation exactly.
- **One suggestion per comment** — if multiple lines need fixing, create separate comments.
- **Always explain first** — include a brief description before the ` ```suggestion ` block.

## Common Pitfalls

| Pitfall | Result | Fix |
|---|---|---|
| Including `subject_type` field | 422 error on GHE, triggers retry loop | Never include `subject_type` — it's not supported on GHE |
| Inlining the awk script in a command | Escape errors, script fails | Save to a temp file first (via `mktemp`), then execute |
| Piping `gh api` output to python/jq | Parse errors on success, agent thinks it failed and retries | Check the submission approach in SKILL.md |
| Using `-f` flags instead of `--input` | `side` not nested correctly | Write full JSON to file, use `--input` only |
| Making multiple API calls / retrying | Each call creates a new review with duplicate comments | NEVER retry — see SKILL.md |
| Also posting via `/pulls/{n}/comments` | Duplicate comments | Only use the reviews endpoint |
| Multi-line suggestions | Broken code when applied | Only use single-line suggestions |
| Getting line numbers from full file | Wrong lines | Run the annotated diff script, use `line` values only |
| Targeting a line not in the diff | API error | If not in diff output, mention in the review body instead |
| Using `APPROVED` instead of `APPROVE` | 422 validation error | Valid events are exactly: `APPROVE`, `REQUEST_CHANGES`, `COMMENT` |
