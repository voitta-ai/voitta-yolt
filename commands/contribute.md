---
description: Interview the user about this session's YOLT friction and, if it is a real rules gap, open an issue and a PR on voitta-ai/voitta-yolt
---

# /yolt:contribute

`/yolt:review` triages friction into *your* settings and *your* overrides.
This command is for the other outcome: the friction is a gap in the
**bundled** rules, so the fix belongs upstream where every YOLT user gets
it.

You are the author here, not the maintainer. The output is an issue and a
PR for the YOLT maintainers to review — never a merge.

This command may be invoked directly, or offered by the UserPromptSubmit
nudge after a session accumulates friction. **If the user declines at any
step, stop and say nothing further about it.**

## Step 1 — Gather

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/hooks/yolt_review.py" --generate
python3 "${CLAUDE_PLUGIN_ROOT}/hooks/yolt_review.py" --list
```

Work from the `--list` JSON. Do not re-derive suggestions by reading the
raw log.

Candidates for this command are the suggestions where the *bundled rules*
are wrong or missing:

- `upstream_candidate: true` — a common CLI repeatedly hitting `unknown`.
- `friction-unsafe` with a high `approved` count — YOLT prompted, and the
  user approved anyway, every time. That is a rule that is too broad.
- A `friction-unknown` on a shape rather than a tool: an invocation form
  the grammar walker does not model (a wrapper, an interpreter flag, a
  redirect target class).

Explicitly **not** candidates, route these to `/yolt:review` instead:

- A personal or internal CLI nobody else has. That is a local override.
- `friction-unsafe` with `approved: 0` — YOLT prompted and the user
  declined. YOLT was right.
- A `fastpath` suggestion. That is a `settings.json` question.

If nothing qualifies, say so in one line and stop.

## Step 2 — Interview

Do not skip to drafting. A rules PR that encodes a wrong generalization is
worse than the prompt it removes, and the answers below are what separate
the two. Ask, in order, and stop early if an answer disqualifies the case:

1. **What were you doing?** The command shape alone does not say whether
   `foo deploy --dry-run` is read-only. The user's intent does.
2. **Is it read-only under every flag, or only some?** This picks the fix:
   a whole-command `default: "safe"`, a `safe_subcommands` entry, or a
   flag-conditional rule (`unsafe_flag_values`, `unsafe_flag_any_value`,
   ...). If the answer is "only some", get the mutating flags by name.
3. **Can it be made to write with a flag you did not use?** Almost every
   read verb has one (`--output`, `-o`, `--save`, `--export`). If so, the
   rule needs `write_flag_value_targets` or the flag on an unsafe list —
   not a blanket safe.
4. **Would you want this for someone else's machine?** The bundled rules
   ship to everyone. "I always run this in a scratch dir" is a local
   override, not an upstream rule.
5. **What is the narrowest fix that removes the prompt?** Prefer a
   subcommand entry over a whole-command default; prefer a flag rule over
   a subcommand entry when the mutation is flag-driven.

Summarize the answers back in three or four lines and get an explicit
"yes, file it" before Step 3. If the interview shows the fix is really a
local one, say so and point at `/yolt:review`.

## Step 3 — Redaction (before anything leaves the machine)

Only the redacted `shape` field (argv head plus flag names, every value
stripped to `<...>`) may go upstream. The `examples` field is raw log data
— real paths, account ids, possibly secrets — and stays local.

Say this to the user, and show them the exact `shape` strings that will
appear in the issue and PR before creating either.

## Step 4 — Issue

```bash
gh issue create --repo voitta-ai/voitta-yolt \
  --title "rules: <cli> <subcommand> classifies unknown/unsafe but is read-only" \
  --body-file <tmpfile>
```

The body should carry: the redacted shape(s), the fire count, what the
current decision is and what it should be, the flag conditions from the
interview (especially any flag that *would* make it mutating), and the
proposed rule shape. Show the draft and create it only on approval.

## Step 5 — PR

Follow the repo's own conventions — they are in its `CLAUDE.md`, read it
first.

1. **Worktree, not a branch in the repo dir.** The repo stays on its
   default branch:

   ```bash
   git -C <yolt-repo> fetch origin
   git -C <yolt-repo> worktree add <yolt-repo>.worktrees/<branch> -b <branch> origin/master
   ```

   Locate the repo before cloning; the user may already have it checked
   out. If not, ask where to put it rather than picking a directory.

2. **Edit `rules/shell.json`** with the narrowest fix from the interview.
   Add a `_note` explaining *why*, including the flag conditions — the
   next person to touch that entry needs the reasoning, not just the verb.

3. **Verify the classification actually flipped**, both directions:

   ```bash
   python3 hooks/grammar_classifier.py '<the read-only invocation>'   # expect safe
   python3 hooks/grammar_classifier.py '<the mutating variant>'       # expect unsafe/unknown
   ```

   Include both in the PR body. A rules PR without the negative case is
   not reviewable.

4. **Run the suite** and report the result honestly, including any
   pre-existing failures:

   ```bash
   python3 -m unittest discover tests
   ```

5. **Bump `.claude-plugin/plugin.json#version`** in the PR itself. A rules
   change is a MINOR bump. This is not optional — see the repo's
   `CLAUDE.md` for why an unbumped version means nobody receives the fix.

6. **Open the PR**, linking the issue from Step 4:

   ```bash
   gh pr create --repo voitta-ai/voitta-yolt --base master \
     --title "..." --body-file <tmpfile>
   ```

## Step 6 — Record and report

Mark the suggestions so they stop resurfacing:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/hooks/yolt_review.py" --applied <id> [<id> ...]
```

Then tell the user, in a few lines: the issue URL, the PR URL, what the
rule now says, and what still prompts (the negative case). Say plainly
that the PR is pending maintainer review and is not merged.

## Notes

- The user can decline at every step. A declined offer is dropped for the
  session; do not re-raise it.
- The nudge that offers this command fires at most once per session, when
  the session hit at least `YOLT_SESSION_NUDGE_MIN` (default 3) *distinct*
  friction prefixes. Set it higher for fewer offers.
- Nothing here writes to the user's `settings.json` or
  `~/.claude/yolt/shell.json`. That is `/yolt:review`'s job, and the two
  are deliberately separate: a local override is yours, a rules change is
  everyone's.
