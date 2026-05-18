---
name: code-review-default
description: This skill must be used when the user mentions "User @username requested a review from you on PR '#123'" or asks to "review this PR" or "code review". Performs comprehensive code reviews covering quality, security, best practices, testing, and documentation.
---

# Pull Request Review Skill

Use this skill when asked to review a pull request or provide feedback on code changes.

## Pre-Review Checklist

### 1. Discover and Invoke Additional Code Review Skills (MANDATORY)

Before proceeding, check if other code-review skills are available and invoke them:

```bash
ls .claude/skills/ 2>/dev/null
```

Look for any skill directories with names containing `code-review` or `review` (other than `code-review-default`). For each one found, invoke it using the Skill tool. These specialized skills take precedence over or supplement the guidelines in this skill.

**Check CLAUDE.md for review guidelines** — read `CLAUDE.md` and `.claude/CLAUDE.md` (if they exist) and look for any section related to code review, PR review, or review standards. If found, treat those guidelines as mandatory requirements that override or extend the defaults in this skill.

### 2. Decide if Search Tools Are Needed
Search tools are required when the PR:
- Introduces new technologies/libraries to the codebase
- Adds integrations with external APIs or services
- Implements patterns that might exist in golden repos

**Skip search tools for:**
- Trivial changes: typos, formatting, comments, README updates
- Simple changes: adding logs, renaming variables, version bumps
- Bug fixes with clear solutions

### 3. Search for Standards (if needed)

#### Documentation Search
Query internal ZoomInfo engineering documentation for relevant standards.

**See:** [Documentation Search Best Practices](../_shared/references/documentation-search.md) for effective query strategies.

#### Sourcegraph Code Search
Search golden repos for similar implementations.

**See:** [Sourcegraph Search Guidelines](../_shared/references/sourcegraph-search.md) for code search techniques.

## Review Guidelines

### Creating the Review with Inline Comments

Use the [Inline Review Comments Guide](./references/inline-review-comments.md) to:
1. Save and run the annotated diff script (from a `.sh` file, not inlined) to get exact line numbers
2. Build the JSON payload with `line` and `side: "RIGHT"` for each comment (do NOT include `subject_type` — it's not supported on GHE)

Then submit **exactly one** API call — this is the **only** place you submit the review:

```bash
gh api "/repos/{owner}/{repo}/pulls/{pull_number}/reviews" \
  --method POST \
  --input "$REVIEW_PAYLOAD"
```

**CRITICAL — do NOT modify the command above:**
- Run it exactly as shown — do NOT pipe the output to `python3`, `jq`, `head`, or any other command
- Do NOT wrap it in a script that parses the response
- If the command exits with code 0, the review was created — you are done
- **NEVER retry or resubmit** — even if the output looks unexpected, even if you're unsure it worked. Each call creates a new review. If you call it twice, every comment appears twice.

**Submission rules:**
- **Use `--input` only** — do NOT use `-f`, `-F`, or `--raw-field` flags; pass the `$REVIEW_PAYLOAD` path from Step 2
- The `event` field in the JSON payload must be **exactly** one of these three values (case-sensitive, no variations):
  - `COMMENT` — when the issues found are **not critical** but are still worth addressing, or for general feedback and suggestions
  - `REQUEST_CHANGES` — only when the review uncovers **critical issues** that **must** be addressed before merging (e.g., bugs, security vulnerabilities, data loss risks, broken functionality)
  - `APPROVE` — when the PR looks good overall, even if there are minor issues that would be nice to improve but are not blocking
  - ⚠️ **Common mistake**: Do NOT use `APPROVED`, `REQUESTED_CHANGES`, `COMMENTED`, or any other variation — these will cause a 422 validation error.
- Do NOT also post comments through other endpoints (`/pulls/{number}/comments` etc.)
- Do NOT add a separate comment to the PR summarizing the review — the review body IS the summary
- Include `` ```suggestion `` blocks with one-click fixes when applicable — **single-line suggestions only** (multi-line produce broken code)

### Review Quality
- **Avoid nitpicking** - focus on significant issues and improvements
- **Only comment on code that needs to change** - every inline comment must identify a problem or request a specific change. Do NOT comment on code that is already correct, well-written, or improved. Users treat review comments as a to-do list; comments that don't require action waste their time.
- Focus on: bugs, security issues, logic errors, performance problems
- Skip: style preferences, minor formatting, subjective opinions
- Provide actionable feedback with specific suggestions
- Include reference links when searches were used

### Logging Review
When reviewing code that adds or modifies log statements, evaluate each log entry critically:
- **Log level appropriateness**: Ensure `ERROR` is not used for expected/recoverable conditions, `WARN` for truly exceptional cases only, and `INFO`/`DEBUG` for routine flow. Avoid elevating levels unnecessarily.
- **Log volume risk**: Flag any logs inside loops, frequently-called methods, hot code paths, or event listeners that could produce high-frequency output under normal production load.
- **Cardinality risk**: Warn about logs that include unbounded dynamic values (e.g., user IDs, request IDs, raw payloads) that could cause high cardinality in Datadog and inflate indexing costs.
- **Redundancy**: Identify duplicate or near-duplicate log lines that convey the same event (e.g., logging both entry and exit of a trivial method with no meaningful data).
- **Sensitive data**: Flag any log that may include PII, credentials, tokens, or other sensitive data that should never appear in log sinks.
- **Cost awareness**: Explicitly call out patterns that could lead to **log flooding** or **unexpected Datadog ingestion cost spikes** — e.g., logging full request/response bodies, logging on every retry attempt without a cap, or verbose debug logs left enabled in production configuration.

When flagging logging issues, suggest a concrete fix (e.g., remove the log, lower the level, add a rate-limit guard, or move outside a loop).

### Response Format
- Be concise and direct
- Group related feedback together
- Prioritize issues by severity
- Include code snippets for suggested fixes when helpful
