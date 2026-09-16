# YOLT — You Only Live Twice

> *YOLO* — "You Only Live Once" — is the
> [vibe-coder's mantra](https://www.reddit.com/r/vibecoding/comments/1qyuvwe/the_transition_from_vibe_coding_to_yolo_coding/) for shipping fast and dealing with
> consequences later.
>
> *YOLT* — "You Only Live Twice" — is the
> [for James Bond ](https://www.youtube.com/watch?v=hs8uYxTJ530) in the rest of us.
> The hook gives the agent a second pass before the destructive Bash actually runs.

## Contents

- [Status: Claude Code auto mode changed what this is for](#status-claude-code-auto-mode-changed-what-this-is-for)
- [Introduction](#introduction)
- [Example use cases](#example-use-cases)
- [How it works](#how-it-works)
- [Tools other than Bash](#tools-other-than-bash)
- [Install](#install)
  - [Updating](#updating)
  - [Releasing (maintainers)](#releasing-maintainers)
  - [Migrating from manual to plugin install](#migrating-from-manual-to-plugin-install)
  - [Manual install (without the plugin system)](#manual-install-without-the-plugin-system)
- [User whitelist (removed in the auto-mode realignment)](#user-whitelist-removed-in-the-auto-mode-realignment)
- [Dependencies](#dependencies)
- [What the grammar classifier handles](#what-the-grammar-classifier-handles)
- [SQL CLIs (removed in Phase 3)](#sql-clis-removed-in-phase-3)
- [Python rules (interpreter delegate)](#python-rules-interpreter-delegate)
- [Custom rules](#custom-rules)
  - [Python rules — `~/.claude/yolt/rules.json`](#python-rules---claudeyoltrulesjson)
  - [Shell rules — `~/.claude/yolt/shell.json`](#shell-rules---claudeyoltshelljson)
- [Credentials in the command line (advisory)](#credentials-in-the-command-line-advisory)
- [Debug / dogfood log](#debug--dogfood-log)
  - [Credential redaction](#credential-redaction)
- [Self-improvement loop (removed in Phase 3)](#self-improvement-loop-removed-in-phase-3)
- [CLI usage](#cli-usage)
- [Tests and demo](#tests-and-demo)
- [Analysis boundaries](#analysis-boundaries)
- [Design principles](#design-principles)

## Status: Claude Code auto mode changed what this is for

Claude Code now ships **auto mode** as its default permission mode: a
classifier vets every tool call — not just Bash — and decides whether it
runs. That is the job the first half of this README describes YOLT doing,
and the platform now does it for every tool, with no rules to maintain.

**What that means for YOLT.** The auto-allow half is superseded. YOLT is
being narrowed to two things the platform does not do:

- a **deny-only** guard over a short list of decisions that should not be
  delegated to a probabilistic classifier — it withholds approval and
  never grants it;
- **credential hygiene** — catching secrets on a command line before they
  are scattered across transcripts, logs and history, and keeping them out
  of YOLT's own records. See
  [Credentials in the command line](#credentials-in-the-command-line-advisory)
  and [Credential redaction](#credential-redaction).

The realignment is tracked in
[#102](https://github.com/voitta-ai/voitta-yolt/issues/102) and lands in
v2.0.0.

> **The classifier bypass is gone.** Up to v1.0.1 YOLT returned `allow`
> for commands it classified as safe, and Claude Code honors a hook's
> decision — so on those commands YOLT answered *instead of* auto mode's
> classifier. That is the same bypass `/auto-mode-setup` looks for in your
> `permissions.allow` and offers to remove, except a hook is invisible to
> that check. As of
> [#98](https://github.com/voitta-ai/voitta-yolt/issues/98) YOLT never
> emits `allow` from any path, and no longer reads your settings files at
> all. Every command it does not object to is vetted by auto mode.

The remaining phases shrink the rule set and widen the guard past `Bash`;
until they land, the rules documentation below still describes the full
classifier.

## Introduction

A Claude Code hook that statically analyzes script invocations before
execution and flags mutating ones for review. It withholds approval; it
never grants it.

> **Superseded framing.** The two gaps below were real when the built-in
> whitelist matcher was the only thing standing between an agent and a
> command. Auto mode closes both of them by reading intent rather than
> matching patterns — there is no whitelist to widen. They are kept here
> because they explain why the code is shaped the way it is.

1. **Arbitrary-execution wrappers.** Interpreters (`bash`, `python3`,
   `node`, ...) and dual-use CLIs (`gh api`, `curl`, `kubectl`, ...) can't
   be whitelisted with a wildcard without granting arbitrary execution,
   so a long tail of clearly read-only invocations prompt every time.
2. **Compound shell commands.** The built-in matcher sees the outer wrapper
   (`for`, `while`, `bash -c "..."`, `$(...)`), not the inner commands it
   runs, so loops and command substitutions prompt even when every inner
   command would be whitelisted on its own.

The decomposition those gaps motivated is not going away. Seeing into a
`bash -c`, a heredoc or a `$(...)` is how a credential hidden inside one
gets found, so the grammar walker outlives the classification job it was
built for.

The hook entry is one piece, with two specialized followers:

- **Grammar classifier** (`hooks/grammar_classifier.py`) — parses the
  Bash invocation with [tree-sitter-bash][ts-bash] and walks the resulting
  AST, dispatching per node kind. This replaced the earlier hand-rolled
  string walker (see [issue #4][issue-4] for the design rationale and the
  migration's trigger bug).
- **Rule classifier** (`hooks/rule_classifier.py`) — takes the argv tokens
  the grammar walker reconstructs from each `command` node and looks them
  up in `rules/shell.json`.

When the Bash invocation invokes an interpreter inline — `bash -c '...'`,
`sh -c '...'`, `python3 -c '...'`, `python3 file.py`,
`python3 <<EOF ... EOF` — the grammar classifier delegates the inner
source to a per-language analyzer:

- `bash`, `sh` → re-enter the grammar walker on the inline script.
- `python3` → `hooks/yolt_analyzer.py` walks the Python source via the
  stdlib `ast` module against `rules/default.json`.

Other interpreters (`node`, `ruby`, ...) are not analyzed inline today;
they fall through to `unknown`. Adding one means writing an analyzer of
the same shape and registering it in `rules/shell.json`.

[ts-bash]: https://github.com/tree-sitter/tree-sitter-bash
[issue-4]: https://github.com/voitta-ai/voitta-yolt/issues/4

## Example use cases

> The first entry is kept for the record only — it describes what YOLT did
> before [#98](https://github.com/voitta-ai/voitta-yolt/issues/98). The rest
> are current, because they are about *seeing into* a command rather than
> about approving it.

- **~~Stop prompt fatigue on read-only work.~~** *(removed in #98 — auto
  mode does this.)* Read-only exploration used to be auto-allowed by YOLT;
  it now falls through to the host untouched. A mutating
  `git push --force` or `aws s3 rm s3://bucket --recursive` still stops for
  review.
- **See into wrapper commands the built-in allowlist can't.** A
  `for f in *.log; do rm "$f"; done` loop, a `bash -c "..."`, a piped
  `curl ... | sh`, or a heredoc is decomposed to its inner commands, so the
  mutating one inside is flagged instead of the outer wrapper being
  rubber-stamped.
- **Catch destructive SQL inside CLI flags.** `psql -c "DROP TABLE users"`
  or `athena ... "DELETE FROM ..."` is flagged for review, while a
  `SELECT ...` query classifies safe and passes through silently.
- **Analyze inline Python by AST, not string match.** `python3 -c "..."`
  and `python3 <<EOF` snippets are walked with the stdlib `ast` module: a
  read-only `json.load` + `print` classifies safe and passes through
  silently, while a snippet that writes a file, calls `os.system`, or
  spawns a subprocess prompts.

## How it works

YOLT registers as a `PreToolUse` hook on the `Bash` tool. For every Bash
invocation the hook parses the command with tree-sitter-bash and walks
the AST. Visitor dispatch:

- `command` node — reconstruct argv from the typed argument children
  (`word`, `string`, `raw_string`, `concatenation`, `simple_expansion`,
  ...) and classify via `rules/shell.json`. Pre-command env assignments
  (`FOO=bar baz`) are skipped, not folded into argv.
- `pipeline`, `list`, `negated_command`, `subshell`, `compound_statement`
  — recurse into children.
- `if_statement`, `for_statement`, `while_statement`, `case_statement`,
  `do_group` — recurse into bodies. No manual keyword stripping required;
  the grammar already separates control-flow tokens from commands.
- `redirected_statement` — check redirect targets against two glob
  lists in `rules/shell.json`. The `unsafe_write_targets` deny list
  (dotfiles / config / startup paths like `~/.bashrc`,
  `~/.ssh/authorized_keys`, `/etc/*`) is checked first: a match
  classifies `unsafe` (ask with a specific reason). It is checked
  *before* `safe_write_targets`, so a deny entry overrides a broader
  safe glob — `~/.claude/settings.json` is unsafe even though
  `~/.claude/*` is a safe-write target, because settings.json can
  disable this hook. The `safe_write_targets` white list (defaults
  include `/dev/null`, `/tmp/*`, `/var/folders/*`, `~/.cache/*`,
  `~/.claude/*`, etc.) makes a write benign. Anything on neither list
  falls through to `unknown` so Claude Code default-prompts. The same
  deny list also routes the write-target arguments of
  `tee` / `cp` / `mv` / `install` / `dd` / `find -fprint*`. For
  `python3 << ... <<EOF` heredocs, the body goes to the Python
  analyzer.
- `command_substitution` (`$(...)`, `` `...` ``) and `process_substitution`
  (`<(...)`) — recurse and classify the inner command separately. A
  destructive substitution surfaces even when the outer command is safe
  on its own.
- `variable_assignment` — assignment is benign; only the RHS is walked
  for nested substitutions.
- `function_definition` — defining a function is not running it; the
  body is dormant.

After visiting, decisions are aggregated with precedence
`unsafe > unknown > safe`, and the hook emits one of:

- `safe` → **nothing.** The hook exits silently and the host decides,
  exactly as for `unknown`. YOLT withholds approval; it does not grant it
  ([#98](https://github.com/voitta-ai/voitta-yolt/issues/98)). The `safe`
  classification is still written to the decision log, where it is what
  the classifier's accuracy is measured from.
- `unsafe` → `permissionDecision: ask` with the specific reason — or
  `deny` when the hook payload carries an `agent_id`, i.e. the call came
  from a background subagent. No operator is reachable there, so an `ask`
  dialog never surfaces and never times out: the agent hangs indefinitely.
  `deny` is strictly more restrictive than `ask`, and it fails in seconds
  with a reason the agent can report to its orchestrator. The fix is the
  same either way — add the suggested `permissions.allow` entry, or re-run
  from the main session.
- `unknown` → silent exit; Claude Code falls through to its default.

Argv is dispatched per-`command_name`: safe builtins → safe;
interpreters delegate inline scripts (see lead-in); `python3 -m <mod>`
consults the `safe_modules` / `unsafe_modules` / `nested_modules` lists
in `rules/shell.json#interpreters.python3` (so e.g. `python3 -m pip list`
is safe but `python3 -m pip install` is unsafe); known CLIs use their
`rules/shell.json` spec; wrappers (`time`, `xargs`, `timeout`, `env`,
`nice`, `watch`, ...) re-classify the wrapped command; anything else →
unknown.

## Tools other than Bash

The PreToolUse matcher is `*`, not `Bash`
([#99](https://github.com/voitta-ai/voitta-yolt/issues/99)). The reason is
empirical rather than tidy: the subagent wedge investigated in
[#80](https://github.com/voitta-ai/voitta-yolt/issues/80) hung on a
`Write`, so YOLT was never in its path. A guard registered on one tool is
not a guard.

A structured tool has no argv, no shell and no rule lookup, so exactly two
things happen for it:

1. **The agent-steering write check.** If the call writes to a path in
   `rules/shell.json#unsafe_write_targets` — settings, hooks, skills,
   commands, agents, memory, MCP config — it is `unsafe`. That is the
   self-modification shape, and it is the one thing on the non-delegable
   list a structured tool can reach today.
2. **The credential advisory**, over every string in the payload, so a
   token in a `Write` body or an MCP argument is caught the same as one on
   a command line. The wording drops the `argv` / `ps` framing there,
   because neither applies.

Everything else is `unknown` and the host decides.

The write-target field list is **closed** — `Write`, `Edit`, `MultiEdit`
and `NotebookEdit`, by their documented path fields. Guessing which field
of an arbitrary MCP payload is a write target eventually guesses wrong,
and a wrong guess is a false `deny` inside a subagent, which is the exact
failure this is meant to prevent. This is deliberately not a second
classifier for structured tools: the host's own vetting covers the general
case.

> **“YOLT denies in subagents” is not “subagent wedges are handled.”**
> The deny converts *YOLT's own* `ask` into a fast failure. Any other
> gated call in a background subagent still hangs with no prompt and no
> timeout — 2h37m with no result in the #80 probe. The general fix belongs
> in Claude Code, where a subagent permission request should surface or
> time out rather than hang.

The conversion is skipped under `bypassPermissions` and `dontAsk`, where
the operator blanket-authorised ahead of time and there was no prompt to
hang on. It is **not** skipped under `auto`: auto mode delegates the
decision to a classifier, it does not put an operator behind a hook's
`ask`, so a subagent that receives one still has nobody to answer it.

## Install

YOLT ships as a [Claude Code plugin](https://code.claude.com/docs/en/plugins).
This repo is its own marketplace, so the install is two slash commands:

```
/plugin marketplace add voitta-ai/voitta-yolt
/plugin install yolt@voitta-yolt
```

On first Bash invocation after install, the hook bootstraps the two
Python deps (`tree-sitter`, `tree-sitter-bash`) into your user
site-packages automatically — no separate `pip install` step needed.
See [Dependencies](#dependencies) for the bootstrap details and
fallback behavior on locked-down Python environments.

The plugin's `hooks/hooks.json` registers the `PreToolUse` hook on
`Bash` automatically — no manual `settings.json` edit needed. Run
`/plugin uninstall yolt@voitta-yolt` to remove.

### Updating

- **Plugin install:** `/plugin marketplace update voitta-yolt` pulls
  the latest code into your local marketplace clone. Then either
  `/reload-plugins` or restart Claude Code so the running session
  picks up the new code. (Some Claude Code versions don't have a
  `/plugin update` subcommand — `marketplace update` + reload is the
  reliable path.)
- **Manual install:** `git pull` in your local clone of this repo. The
  hook script in your `settings.json` already points at
  `<clone>/hooks/pre-tool-use.sh`, so the next Bash invocation picks up
  the new code without further action.

### Releasing (maintainers)

YOLT publishes to two marketplaces off the same repo:

- **This repo's own marketplace (`voitta-yolt`)** — the repo IS the
  marketplace, so there is nothing to onboard; a pushed release is live.
- **Anthropic's community marketplace (`claude-plugins-community`)** —
  Anthropic-hosted and submission-gated; needs a one-time submission
  (below). The curated `claude-plugins-official` is invite-only, with no
  submission path.

**Every merge that ships — bump the version.** `.claude-plugin/plugin.json`
holds the version, and Claude Code's plugin cache is keyed by it, so
`claude plugin update` on an unchanged version reports "up to date" and
re-extracts nothing: users keep running the old code. Not hypothetical —
the version sat at `0.1.0` from the initial ship through issue #78 and
every change in between was invisible to installed copies.

`CLAUDE.md` has the full convention: which semver part to bump for what.
Tagging and release notes are automatic — a workflow fails any PR into
master whose version does not advance, then tags and cuts the release
from master's squash commit. The only manual step is editing the version
field inside the PR.

**One-time — to list on Anthropic's community marketplace.** Validate
(the same check Anthropic runs on submit), then submit the repo once:

```
claude plugin validate . --strict
claude plugin validate .claude-plugin/plugin.json --strict
```

Submit through the plugin form — [Console](https://platform.claude.com/plugins/submit),
or [claude.ai](https://claude.ai/admin-settings/directory/submissions/plugins/new)
for Team/Enterprise orgs — and pass Anthropic's automated screening. On
approval the plugin is pinned to a commit SHA in
[`anthropics/claude-plugins-community`](https://github.com/anthropics/claude-plugins-community);
the catalog then syncs nightly (~24h) and CI re-pins on later pushes, so
there is no per-release step beyond the version bump above. Users install
with `/plugin install yolt@claude-community`.

### Migrating from manual to plugin install

If you already have the manual hook block in `~/.claude/settings.json`
from an earlier install and want to switch to the plugin form:

1. Remove the `hooks.PreToolUse` entry that points at
   `voitta-yolt/hooks/pre-tool-use.sh` from your `settings.json`.
2. Run `/plugin marketplace add voitta-ai/voitta-yolt` and
   `/plugin install yolt@voitta-yolt`.

Both forms run the same code; the plugin form removes the manual edit
and lets you upgrade with `/plugin marketplace update voitta-yolt` plus
a reload.

### Manual install (without the plugin system)

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

> **Important:** A static allow rule in `settings.json` / `settings.local.json`
> bypasses `PreToolUse` hooks. Do not whitelist `Bash(python3:*)`,
> `Bash(aws:*)`, `Bash(gh:*)`, etc. with wildcards - YOLT's classifier
> will never fire and mutating invocations will run without review. Narrow
> whitelist patterns that don't cover mutating operations (e.g.
> `Bash(aws ecs list-services*)`) are fine; they just short-circuit YOLT
> for the matching subset.

## User whitelist (removed in the auto-mode realignment)

YOLT used to read your `permissions.allow` Bash() entries from
`~/.claude/settings.json` and the project settings, and upgrade any
matching `unknown` or `unsafe` node to `safe`. That was the second way it
granted approval — sourced from your config rather than its own rules, but
a grant all the same.

It is gone
([#98](https://github.com/voitta-ai/voitta-yolt/issues/98)). Under auto
mode a hook that answers on the host's behalf is a classifier bypass the
host cannot see, and that is as true of a grant you configured as of one
YOLT decided. **YOLT no longer reads your settings files at all.**

### Compatibility for consumers that passed `--no-user-allow`

`--no-user-allow` was added in 1.2.0 for consumers that are not the
interactive terminal those settings were written for -- a service classifying
commands on behalf of whoever can message it inherited the operator's personal
permissions otherwise.

**2.0.0 still accepts the flag, and it now does nothing**, because the
behaviour it asked for is unconditional: there is no allow path left to switch
off. It is retained rather than removed because consumers pass it
unconditionally, and a rejected flag would be read as the command itself,
turning every verdict into a verdict about the string `--no-user-allow`.

The `allow_patterns` key is likewise retained in the JSON output and is
always `0`:

    python3 hooks/grammar_classifier.py --no-user-allow 'gh pr merge 1 --squash'
    {"decision": "unsafe", "reason": "gh pr merge: mutating", "allow_patterns": 0}

That `0` is true rather than a placeholder. A consumer asserting it at startup
is asserting something real about 2.0.0, which is a better contract than
trusting a flag to remain a no-op.


Your `permissions.allow` entries are Claude Code's to honor, which is the
appropriate place for them — but **under auto mode it does not honor the
Bash ones.** Auto mode runs with `classifyAllShell` active, and it then
ignores every `Bash(...)` and PowerShell allow rule at runtime; outside auto
mode those same rules apply normally. So a standing `Bash(gh pr merge*)` is
authoritative in one mode and inert in the other, with nothing at the prompt
saying which mode you are in.

Two consequences worth stating plainly, because both have been hit:

- A rule you added to stop being asked about a command will stop working the
  moment you turn auto mode on, and the denial you get will not mention the
  rule.
- YOLT's paste-ready `Bash(...)` suggestion below is subject to the same
  thing. Adding it fixes the prompt outside auto mode and changes nothing
  inside it.

For common workflow writes (`git push`, `git commit`, `gh issue create`,
`gh pr comment`, ...), YOLT's `ask` message still includes a paste-ready
`Bash(...)` suggestion. It is advice to you, not a grant: nothing happens
until you add it yourself, and Claude Code — not YOLT — is what acts on it,
subject to the auto-mode caveat above.

## One verdict, two consumers that read it oppositely

YOLT has two kinds of caller, and they disagree about what a non-`safe`
verdict means. The realignment was designed against both, so the difference
is worth stating before reading any decision table.

**The Claude Code `PreToolUse` hook.** `safe` and `unknown` are the same
event: YOLT exits 0 with no `permissionDecision` and the host decides.
Delegating a command to the host is therefore free — indistinguishable, on
the wire, from judging it safe.

**A fail-closed programmatic consumer.**
[shmobster](https://github.com/voitta-ai/shmobster) — a self-hosted Slack
agent — runs `grammar_classifier.py` as a subprocess and compares
`== "safe"`, never `== "unsafe"`, so that a verdict it does not recognize
lands on the restrictive side. For it, `safe` and `unknown` are *opposites*.
Anything not literally `safe` ends the model's turn and parks the command on
a Slack approval card until a trusted human returns, which may be hours.
Delegating a command costs one asynchronous human interrupt.

This is the whole of
[#144](https://github.com/voitta-ai/voitta-yolt/issues/144): 2.0.0 collapses
*we deliberately delegate this* and *we could not classify this* into a
single `unknown`. The hook cannot tell those apart and does not need to. A
consumer that must fail closed on the second has no way to avoid failing
closed on the first, so ordinary reads — `cat`, `ls`, `grep`, `git status`,
`gh pr list` — park. shmobster pins `>= 1.6.0, < 2.0.0` at startup for this
reason, and the pin lifts when the two are distinguishable.

The general rule, for anyone writing a consumer: **decide what an
unrecognized verdict means before you add one.** Comparing against `safe` is
what makes a new verdict fail safely; comparing against `unsafe` is what
makes a new verdict fail open.

### Delegation is absence, not a tier

There is no retained list of what YOLT delegates. From `rules/shell.json`:

> A command absent from `commands`, or a subcommand on no list here,
> classifies `unknown` and is delegated to the host by design.

So `unknown` on `cat` and `unknown` on a command YOLT has never heard of are
the same verdict for the same reason — absence — and they are byte-identical
in the reason string too (`no rule: cat`, `no rule: frobnicate`). YOLT cannot
tell you which is which because YOLT does not know.

This bounds what #144 can be. A fix cannot surface a distinction YOLT
already has; it would mean restoring a positive read-only list, which is the
realignment's thesis in reverse. **A consumer that cannot afford to delegate
has to supply its own safe list** — in its own reviewable config, consulted
only on `unknown`, never over `unsafe` or `deny`, so it can promote but never
override. That is the appropriate place for it, and it is the same conclusion
the auto-mode caveat above reaches from the other direction: an inherited
allow-list is one the host itself discards.

### Pass `--cwd` if you are not running where the command would run

The `deny` predicates are about repository state, so they are properties of a
directory, not of the command text. The CLI defaults to its own process's
directory, which is right for a shell wrapper and wrong for a service:

    $ python3 hooks/grammar_classifier.py 'git push origin master'      # in the repo
    {"decision": "deny", "reason": "git push: would push to the default branch (master)", ...}

    $ cd /tmp/elsewhere && python3 .../grammar_classifier.py 'git push origin master'
    {"decision": "unsafe", "reason": "git push: mutating", ...}

Both answers are correct for their directory. But a consumer that subprocesses
the classifier without setting the directory gets the second one — or worse,
a `deny` citing *its own* branch for a command destined for another
repository. Pass `--cwd DIR`, which restores the deny from anywhere:

    $ cd /tmp/elsewhere && python3 .../grammar_classifier.py --cwd /path/to/repo 'git push origin master'
    {"decision": "deny", "reason": "git push: would push to the default branch (master)", ...}

A consumer that does not pass it has a silently inert deny layer.

## Dependencies

Two pure-Python deps via wheels:

- [`tree-sitter`](https://pypi.org/project/tree-sitter/) — parser runtime.
- [`tree-sitter-bash`](https://pypi.org/project/tree-sitter-bash/) — bash grammar.

`hooks/pre-tool-use.sh` bootstraps these on first run: probes the import,
and if missing, runs `pip install --user -r requirements.txt` (falling
back to `--break-system-packages` for PEP 668 environments). A marker
under `~/.cache/yolt/deps-installed-<sha>` records success and is keyed
to the `requirements.txt` content hash, so a dep bump triggers re-bootstrap.
Subsequent hook fires skip the import probe entirely.

If the bootstrap fails (no network, locked-down pip, exotic Python
distribution), the hook exits silently and Claude Code falls through to
its default prompt — YOLT does not break the user's session on a broken
install. The failure is recorded in `~/.claude/yolt.log` as
`decision: "import-error"`; the user can fix manually with
`pip install -r requirements.txt` and the next hook fire picks it up.

To force re-bootstrap (after a venv switch or manual uninstall):

```bash
rm ~/.cache/yolt/deps-installed-*
```

## What the grammar classifier handles

Phase 3 ([#100](https://github.com/voitta-ai/voitta-yolt/issues/100))
replaced "classify everything" with a **non-delegable list**: the decisions
deliberately refused to a probabilistic classifier. `rules/shell.json` went
from 136 command entries to 28. Everything not on the list classifies
`unknown`, which is a silent exit — Claude Code's own auto mode decides it.

Measured against the 3,846-command dogfood corpus, that moved YOLT from
**609 asks (15.8%) to 188 (4.9%)** across 48 distinct reasons instead of 135.

The seven categories, and what they cover:

| Category | Commands |
| --- | --- |
| irreversible-fs | `rm`, `shred`, `rmdir`, `git rm`, `git clean`, `find -delete` |
| history-rewrite | `git reset --hard` only — the reflog recovers everything else |
| credential-shape | `gh api -f/-F/--field/--input`, `curl -d/--data*/-F/-T`, `curl -X POST` |
| infra-destroy | `terraform apply`, `terraform destroy`, `kubectl delete`, `aws iam` (non-read) |
| opaque-execution | `eval`, `sudo`, `find -exec`, inline Python that parses destructively or does not parse |
| process-kill | `kill`, `pkill`, `gh run cancel` |
| irrevocable-remote | `gh api -X POST/PUT/PATCH/DELETE`, `gh release create/delete`, `gh repo fork` |
| agent-steering-write | any write to `unsafe_write_targets` — by redirect, or via `cp`/`mv`/`tee`/`dd`/`install` |

Plus `git push`, which is on the list for a structural reason rather than a
risk one: see "Policy-driven CLIs" below.

Example decisions:

| Command | Decision |
| --- | --- |
| `rm -rf build` / `shred -u f` / `rmdir d` | ask |
| `git rm old.py` / `git clean -fd` | ask |
| `git reset --hard HEAD~1` | ask |
| `git reset --soft HEAD~1` / `git rebase -i master` | silent (delegated) |
| `git log` / `git status` / `git pull` / `git checkout -b x` / `git commit` | silent (delegated) |
| `git push origin feature/x` | ask (precondition for the deny policies) |
| `git push origin master` | **deny**, when the branch probe resolves |
| `gh api repos/o/r/pulls` | silent (a GET) |
| `gh api -X PUT .../merge -f m=squash` / `gh api -f title=x` | ask |
| `gh release create v1` / `gh repo fork o/r` / `gh run cancel 1` | ask |
| `gh pr merge` / `gh pr view` / `gh issue create` | silent (delegated) |
| `curl https://example.com` | silent (a GET) |
| `curl -X POST ... -d @body.json` | ask |
| `terraform apply` / `terraform destroy` | ask |
| `terraform init` / `terraform plan` / `terraform state rm` | silent (delegated) |
| `kubectl delete pod x` | ask |
| `kubectl get pods` / `kubectl exec ...` | silent (delegated) |
| `aws iam attach-role-policy ...` | ask |
| `aws iam list-users` / `aws s3 cp a b` / `aws ec2 terminate-instances` | silent (delegated) |
| `eval "$CMD"` / `sudo rm -rf /` | ask |
| `echo a \| xargs rm` / `timeout 5 rm x` / `nohup rm x` | ask (the wrapper is unwrapped first) |
| `kill -9 1234` / `pkill -f node` | ask |
| `find . -delete` / `find . -exec rm {} +` | ask |
| `find . -name '*.py'` | silent (delegated) |
| `python3 -c "print(1+1)"` | silent |
| `python3 -c "import os; os.system('rm -rf /')"` | ask |
| `cp a b` / `mv a b` / `tee out.txt` / `sed -i s/a/b/ f` | silent (delegated) |
| `cp evil.md ~/.claude/skills/x/SKILL.md` | ask (protected path) |
| `echo x > ~/.claude/settings.json` | ask (deny list beats the `~/.claude/*` safe glob) |
| `echo x > /tmp/out` | silent |
| `ls` / `cat` / `grep` / `mkdir` / `brew install` / `source ~/.bash_profile` | silent (no rule — delegated) |

"silent" means the hook exits without emitting a permission decision, which
post-Phase-1 is what both `safe` and `unknown` do.

## SQL CLIs (removed in Phase 3)

`sqlite3`, `psql`, `mysql`, `duckdb` and the cloud SQL-over-flag forms
(`aws athena start-query-execution --query-string`, `aws rds-data --sql`,
`aws redshift-data`, `aws timestream-query`) had a conservative SQL scanner
that classified `SELECT` read-only and `DROP`/`DELETE`/`INSERT` mutating.

Phase 3 ([#100](https://github.com/voitta-ai/voitta-yolt/issues/100)) removed
all of it. It is a good example of what the phase is for: a substantial,
carefully-built classifier that auto mode does at least as well, and the
half that mattered — "the scanner could not classify this string" — only
ever produced `unknown`, which is now the default for the whole surface
anyway.

An operator who wants it back can restore it through
`~/.claude/yolt/shell.json`; the `sql_cli` default and the `sql_flags` /
`sql_positional_index` / `sql_payload_flags` fields are still implemented
and still schema-validated. Nothing ships them.

## Python rules (interpreter delegate)

When the grammar walker hands a Python source body to the analyzer
(`python3 -c '...'`, `python3 file.py`, `python3 <<EOF ... EOF`), the
analyzer walks the source via the stdlib `ast` module and matches calls
against `rules/default.json`. Bash classification stays in charge — the
Python analyzer just answers "is this python body destructive?" when
asked.

`rules/default.json` covers:

- **AWS boto3** — `describe/list/get/head` safe; `delete/put/create/terminate` destructive.
- **File I/O** — `open()` write modes, `os.remove`, `shutil.rmtree`, etc.
- **Subprocess** — `subprocess.run`, `os.system`, etc. (always flagged).
- **Network** — `requests.get` safe; `requests.post/put/delete` destructive.
- **Database** — connection creation flagged for review.

Rules use `trigger_imports` to scope checks. For example, boto3 patterns
only apply when `boto3` is imported, so `cache.delete_item()` in a
non-AWS script doesn't false-positive.

The analyzer also resolves import bindings before matching, so the rule
patterns (`os.system`, `shutil.rmtree`, ...) catch the same call written
through any of the standard import forms:

- `import mod`
- `import mod as alias`
- `import mod.sub` / `import mod.sub as alias`
- `from mod import name`
- `from mod import name as alias`

For example, `from os import system; system("rm -rf /tmp/x")` and
`import os as x; x.system(...)` both normalize to `os.system` and
classify as destructive.

Bindings are collected in a pre-pass over the parsed module body before
the call walk, so traversal order does not matter — a call inside a
function defined *before* the matching import still resolves through
the binding.

Only top-of-file unconditional imports are honored. Imports nested
under control flow (`if cond: import x`, dead `if False:` branches,
`try`/`except`, `with`, or inside a function/class body) are NOT
applied — we cannot statically prove they execute. Top-level
reassignment of a bound name (`from os import system; system = print`,
including assignments inside top-level `if`/`for` blocks) drops the
binding. Function / lambda-local rebinds shadow the imported binding
within that deferred scope, but do not mutate the module-level
snapshot. Class bodies execute immediately in their own local
namespace, so class-local assignments likewise shadow imported names
for later direct class-body calls.

Module-scope calls resolve against the binding snapshot effective at
their source line, so a call that appears *before* a later rebind /
re-import still sees its original binding. For example:

```python
from os import system
system("rm -rf /tmp/x")          # unsafe (resolves to os.system)
system = print                   # later rebind does not retroactively
                                 # un-flag the earlier call
```

Calls in deferred positions — `def` / `async def` / `lambda` bodies —
resolve against the *final* module snapshot, since those bodies execute
when the function is invoked rather than at module-load time. Calls in
positions that unconditionally run at module load — class bodies,
decorators, default and keyword-default argument values — resolve
against the position-aware snapshot like any other module-scope call.

Annotation expressions (parameter and return) are intentionally not
analyzed. Under `from __future__ import annotations` (PEP 563) the
annotation is stored as a string at runtime and never evaluated; PEP
649 makes lazy annotation evaluation the default in newer Python.
Flagging annotations would create false positives for modules that
opted into deferred annotations, and a destructive call hidden inside
a type hint is not a credible attack pattern.

Still out of scope: variable rebinding via attribute access,
`from mod import *`, and relative imports (`from . import x`).
Anything the analyzer cannot resolve statically is left at its surface
name rather than guessed.

## Custom rules

### Python rules - `~/.claude/yolt/rules.json`

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

### Shell rules - `~/.claude/yolt/shell.json`

```json
{
  "commands": {
    "mycli": {
      "default": "subcommand",
      "safe_subcommands": ["status", "show"],
      "unsafe_subcommands": ["apply", "reset"]
    }
  },
  "shell_builtins_safe": ["my-safe-wrapper"],

  "safe_write_targets": [
    "/dev/null",
    "/tmp/*",
    "/var/folders/*",
    "~/.cache/*",
    "~/.claude/*",
    "/scratch/*"
  ],

  "unsafe_write_targets": [
    "~/.bashrc",
    "~/.ssh/authorized_keys",
    "/etc/*",
    "~/.claude/settings.json"
  ],

  "interpreters": {
    "python3": {
      "inline_flag": "-c",
      "module_flag": "-m",
      "delegate": "python",
      "read_script_file": true,
      "safe_modules": ["json.tool", "my_internal_tool"],
      "unsafe_modules": ["http.server"],
      "nested_modules": {
        "my_cli": {
          "safe_subcommands": ["list", "show"],
          "unsafe_subcommands": ["delete"]
        }
      }
    }
  }
}
```

User overrides merge with (and override) defaults per top-level key, so
overriding `safe_write_targets` or `unsafe_write_targets` replaces the
entire list; if you want to add `/scratch/*` while keeping the defaults,
copy the default list through. `unsafe_write_targets` is checked before
`safe_write_targets`, so a deny entry wins over a broader safe glob.
Examples: `examples/user-overrides.json`, `examples/shell-overrides.json`.

Since Phase 3 this file is also **how you get a deleted rule back.** The
schema did not shrink with the rule set: `safe_subcommands`, `sql_cli`,
`nested_modules` and the rest are all still implemented and still
validated. If auto mode keeps letting through something you want a hard
prompt on, add it here rather than reopening the treadmill upstream.

## Credentials in the command line (advisory)

YOLT already parses every Bash command for safety, which makes
`PreToolUse` the natural place to catch a hazard it is otherwise blind
to: **a credential sitting in the command string itself.** Issue
[#85](https://github.com/voitta-ai/voitta-yolt/issues/85).

The motivating case is not a mistake:

```bash
curl -H "X-Api-Key: <value>" https://service/endpoint
```

The key was fetched correctly from a secret manager. Nothing about the
command is unsafe by YOLT's lights. But that string then lands in the
session transcript, in session memory (usually embedded and searchable,
so it can resurface in a *later* session's context), in any spilled tool
output, in YOLT's own logs, and in `permissions.allow` if the approved
command string contained it — copies with different lifetimes, none in
git, most never swept. `argv` is also world-readable to anything that
can run `ps` while the process lives.

`PreToolUse` is the only point where that is preventable rather than
cleanable. Once the command has run, every one of those copies exists.

So YOLT warns — and only warns:

```
YOLT: possible credential on this command line (github-token at char 24). Not blocked.
It will persist in the transcript, session memory and the allowlist, and `argv` is
visible to `ps`. Keep it out of `argv`:
  KEY="$(fetch-secret)" sh -c 'curl -H "X-Api-Key: $KEY" https://service/endpoint'
```

Three lines, deliberately. It rides along with a permission prompt the
user is already reading, and a paragraph of security prose on every
credential-bearing command is the fastest route to the whole feature
being switched off.

Properties, all deliberate:

- **Advisory, never blocking.** The warning attaches to whatever
  decision was already reached (`allow`, `ask`, `deny`, and the silent
  `unknown` fallthrough alike) and never changes it. A control that
  false-positives on legitimate work gets switched off and then protects
  nothing.
- **Suggests the fix.** Delivered as both `systemMessage` (you see it)
  and `additionalContext` (Claude sees it, so the remediation is
  actionable rather than decorative).
- **Reports shape and offset, never the value.** A warning that quotes
  the secret puts the secret straight into the transcript it is warning
  about.
- **Structured prefixes first**, assignment shapes second with a
  literal-value guard — the same matcher as [credential
  redaction](#credential-redaction), so `--token $API_KEY` and
  `--token some-resource-name` do not trip it.

- **Never breaks the hook.** The scan runs in the critical path of every
  Bash call, so a bug in a credential pattern costs the warning and
  nothing else — the safety decision is already made by that point, and
  it matters more than the advisory.

To disable, set `YOLT_SECRET_WARN` to any of `0`, `false`, `no`, `off`,
`n`, `disable`, `disabled` (case and surrounding space ignored). The
generous list is on purpose: an exact `=0` test looks precise and
behaves as a trap, since someone silencing a noisy control reaches for
`false` or `off` first and would conclude the switch is broken.

Note the division of labour: this stops the secret reaching the command
line; redaction stops YOLT persisting one it already saw. They are
independent, and redaction is worth having regardless. Neither is a
guarantee — see the [known gaps](#credential-redaction).

## Debug / dogfood log

YOLT logs every examined Bash invocation by default to
`~/.claude/yolt.log`. Each line is a JSON record:

```json
{"ts": "2026-05-08T14:00:00.000+00:00", "decision": "safe", "reason": "ls: read-only", "command": "ls /tmp", "permission_mode": "default", "agent_id": null}
```

`decision` is one of `safe`, `unsafe`, `unknown`, `import-error` (the
tree-sitter dependency is missing), or `rules-validation-error` (the
bundled or user-override `shell.json` failed schema validation; the
`reason` field carries the list of offending keys / defaults so the
user can fix the override). The `command` field is truncated to 500
characters. `permission_mode` and `agent_id` are copied from the hook
payload: `agent_id` is set only when the call came from a subagent (so
it doubles as per-agent attribution when several agents run in
parallel), and `permission_mode` is not observable anywhere else. Both
are `null` when the payload omits them. Logging failures are swallowed
— the hook never breaks the session because of an unwritable log path.

```bash
tail -f ~/.claude/yolt.log
```

This is the cleanest way to QA YOLT against your own session: the
Claude Code UI hides the hook's contribution when your `permissions.allow`
already covers the command, but the log records every fire.

To override the log location, set `YOLT_LOG_FILE` to an absolute path.
To opt out entirely, set `YOLT_LOG_FILE=""` (empty string).

YOLT rotates the log when it grows past 5 MB by renaming it to
`<log>.old`, clobbering any previous `.old`. One generation is
preserved. `YOLT_LOG_MAX_BYTES` overrides the threshold; set
`YOLT_LOG_MAX_BYTES=0` to disable rotation.

### Credential redaction

Credentials land on command lines routinely — `curl -H "X-Api-Key: ..."`,
`--token`, connection strings — and the log is append-only, so anything
written to it should be assumed permanent. Before a record is written,
credential-shaped substrings in `command` (and in `reason`) are replaced
with a `[REDACTED:<shape>]` marker naming the shape only, never the
value. Issue [#84](https://github.com/voitta-ai/voitta-yolt/issues/84).

This happens at **write time**, which is the whole shape of the
mitigation and its limit: the risk being closed is the file on disk, and
lines written before #84 landed are still plaintext. Phase 3 removed the
second sink (`~/.claude/yolt-ran.log`) along with the reviewer that read
it, so `~/.claude/yolt.log` is now the only log YOLT writes — but any
`yolt-ran.log` already on your machine stays exactly as it was.

```json
{"ts": "...", "decision": "unsafe", "reason": "curl: mutating", "command": "curl -H \"Authorization: Bearer [REDACTED:github-token]\" https://api.github.com", "permission_mode": "default", "agent_id": null}
```

Two match families (`hooks/secret_redact.py`):

- **Structured prefixes** — `ghp_`/`gho_`/`ghs_`/`ghr_`/`ghu_`,
  `github_pat_`, `glpat-`, `xox[baprse]-`, `xapp-`, `AKIA`/`ASIA`,
  `sk-`/`sk_`/`rk_`, `dckr_pat_`, `npm_`, `hf_`, `glc_`, `shpat_`,
  `AIza`, bare JWTs (`eyJ….eyJ….`), PEM `PRIVATE KEY` blocks, and the
  password field of `scheme://user:secret@host`. Self-identifying, so
  these are matched wherever they appear.
- **Contextual shapes**, where only the surrounding text identifies the
  value — `--token X`, `Authorization: X`, `FOO_TOKEN=X`,
  `curl -u user:X`, `?password=X` in a query string, and bare
  `aws_secret_access_key X` (the AWS *secret* key, unlike the `AKIA` id,
  has no prefix of its own). Quoted values are captured whole, so
  `--password "correct horse battery staple"` does not lose everything
  after the first space. Only the *value* is redacted, and only when it
  passes a literal-shape guard.

That guard is a **deny**-list: it rejects shell expansions
(`--token $API_KEY`, `$(…)`, backticks) and values too short or too
monotonous to be keys (`--token some-resource-name`). It deliberately
does *not* restrict which characters a value may contain — an earlier
allow-list ran backwards, dismissing `Tr0ub4dor&3!…` precisely because
the punctuation that made it strong was not on the list.

Two tests carry that decision. Past 28 characters the "must mix letters
and digits" rule is waived, which catches passphrases like
`CORRECTHORSEBATTERYSTAPLE`. Separately, any all-hex value of 20+
characters is treated as a key regardless of length, which catches
`deadbeefcafebabedeadbeef`. Keeping those two rules distinct matters:
the hex case was never about length, it is about being drawn from an
alphabet nobody names things in — and conflating them redacted ordinary
words like `authenticationprovidername`.

Residual over-redaction is accepted where it remains, e.g. a
Secret-Manager *path* in `SECRET=projects/…/secrets/db-password/…` is
redacted although a path is not a secret. The direction is deliberate: a
false positive costs one unreadable value in a debug log, a false
negative costs a credential on disk forever.

Redaction is deliberately value-only where it can be, because the
command *shape* is what the self-improvement reviewer mines — a redacted
value costs it nothing. It is also **idempotent**: re-running it over
already-redacted text is a no-op, which is what makes "re-scan and
expect zero hits" a valid way to verify a cleanup of old log files.

**This is best-effort, not a guarantee.** It removes the shapes above,
not "all credentials". A value with no self-identifying prefix and no
secret-ish context around it is indistinguishable from an ordinary
argument. Known gaps, kept open on purpose:

- `mysql -pSECRET` and friends — a `-p` rule cannot be told apart from
  `mkdir -p /var/log/app/2024/01`, and a redactor that mangles ordinary
  commands gets switched off, which protects nothing.
- A bare positional secret: `./deploy s3cr3tvalue00000000`.
- Credentials inside a file the command merely references.

So treat the logs as sensitive regardless — redaction narrows the blast
radius, it does not license leaving a credential on a command line. The
`YOLT_LOG_FILE=""` / `YOLT_RAN_LOG_FILE=""` opt-outs remain the way to
write nothing at all.

If `hooks/secret_redact.py` cannot be imported at all, the hook does not
fail and does not fall back to writing raw commands. Classification
still happens — it never needed the redactor — and the log record
carries `"command": "[WITHHELD:redactor-unavailable]"` plus a
`redactor_error` field, so the failure is visible without a credential
riding along.

Note the scope: this stops YOLT persisting a secret it already saw. It
does not stop the secret reaching `argv` in the first place, where any
process that can run `ps` sees it. Prefer keeping credentials in the
environment:

```bash
KEY="$(fetch-secret)" sh -c 'curl -H "X-Api-Key: $KEY" https://service/endpoint'
```

## Self-improvement loop (removed in Phase 3)

`hooks/yolt_review.py`, the `/yolt:review` slash command, and the SessionStart
and SessionEnd hooks that drove them are gone, along with the PostToolUse
"ran log" that fed them. Removed by Phase 3
([#100](https://github.com/voitta-ai/voitta-yolt/issues/100)) for two reasons,
the second being the stronger:

1. It mined decision-log friction to suggest new rules. It was the engine of
   the rule treadmill, and the treadmill is what Phase 3 retires.
2. **It was independently the source of two credential leaks**
   ([#91](https://github.com/voitta-ai/voitta-yolt/issues/91),
   [#94](https://github.com/voitta-ai/voitta-yolt/issues/94)). It copied raw
   log commands into `review.md` and `suggestions.json`, then — after the
   first fix — into `glob_collisions` as well, so the same credential
   appeared redacted on one line and in cleartext eight lines below.
   Deleting it removes those sinks permanently, which no further redaction
   work can match.

The PostToolUse ran log went with it: once the reviewer was gone nothing read
it, and it was a third place command lines were written to disk.

`hooks/secret_redact.py` is untouched and still runs on every log write. It
is the asset; the reviewer was its largest consumer, not its owner.

**What is left on disk is yours.** Removing the hooks stops new writes; it
does not delete `~/.claude/yolt/suggestions.json`, the generated `review.md`,
or existing `yolt.log` / `yolt-ran.log` files. Redaction has always been
write-time only, so lines written before
[#84](https://github.com/voitta-ai/voitta-yolt/issues/84) may still hold
plaintext credentials. Delete them at your own discretion — and do not grep
them to check first.

`~/.claude/yolt/rules.json` and `~/.claude/yolt/shell.json` are unaffected:
those are your overrides, still read on every hook invocation.

## CLI usage

Classify a Bash command directly — same code path as the hook:

```bash
python3 hooks/grammar_classifier.py 'for svc in $(aws ecs list-services --cluster X); do aws ecs describe-services --cluster X --services "$svc"; done'
```

Output: `{"decision": "safe|unsafe|unknown", "reason": "..."}`.

The Python analyzer is invoked through the grammar classifier in
normal use. To analyze a `.py` file in isolation (debugging the rules,
not the hook flow):

```bash
python3 hooks/yolt_analyzer.py script.py
```

## Tests and demo

Unit tests cover the rule classifier, the grammar classifier, and the
hook entry point. They use stdlib `unittest` plus the two grammar deps:

```bash
pip install -r requirements.txt
python3 -m unittest discover -v tests
```

For a visual check across a broad range of representative commands (not
asserted, just printed), run:

```bash
./examples/demo.sh
```

This prints the decision (`safe` / `unsafe` / `unknown`) for each
command, colorized when the terminal supports it.

## Analysis boundaries

YOLT is a conservative static checker. It chooses `unknown` over
guessing, so the supported surfaces matter. This section pins what
YOLT does and does not inspect.

### Bash decomposition (in scope)

The tree-sitter-bash grammar walker handles:

- pipelines, lists (`;`, `&&`, `||`), negation, subshells, compound
  statements;
- `if` / `for` / `while` / `case` bodies (no manual keyword stripping);
- command substitution (`$(...)`, `` `...` ``) and process
  substitution (`<(...)`) — recursed and classified independently of
  the outer command;
- redirections — write targets matched against the
  `unsafe_write_targets` deny list (match -> `unsafe`) first, then the
  `safe_write_targets` white list (match -> benign); a target on
  neither falls to `unknown`;
- heredocs — for the Python interpreters, the body is delegated;
- pre-command env assignments (`FOO=bar baz`) — skipped, not folded
  into argv.

### Delegated language analysis (in scope)

| Source | Routed to |
| ------ | --------- |
| `bash -c '<script>'`, `sh -c '<script>'` | Re-enters the grammar walker |
| `python3 -c '<script>'` | `hooks/yolt_analyzer.py` (stdlib `ast`) |
| `python3 file.py` | `hooks/yolt_analyzer.py` (stdlib `ast`) |
| `python3 <<EOF ... EOF` | `hooks/yolt_analyzer.py` (stdlib `ast`) |
| `python3 -m mod[.sub] ...` | `interpreters.python3.nested_modules` in `rules/shell.json` |

### Delegated language analysis (out of scope)

Other interpreters are NOT analyzed inline. Their invocations fall
through to `unknown` and Claude Code default-prompts:

- `node -e '...'`, `node file.js`
- `ruby -e '...'`, `ruby file.rb`
- `perl -e '...'`, `php -r '...'`
- `osascript`, `awk -f`, `sed` script files
- arbitrary user shebangs (`./my-script`)

Adding one means writing an analyzer of the same shape as
`yolt_analyzer.py` and registering it under `interpreters` in
`rules/shell.json`.

### SQL CLIs

Removed in Phase 3. See "SQL CLIs (removed in Phase 3)" above. The scanner
code (`classify_sql_text`) is still present and still reachable through an
operator override; nothing in the shipped rules routes to it.

### Python alias resolution (in scope)

Pre-pass over the module body collects bindings before the call
walk. Supported import forms:

- `import mod`
- `import mod as alias`
- `import mod.sub` / `import mod.sub as alias`
- `from mod import name`
- `from mod import name as alias`

Function / `lambda` body shadowing is honored via the stdlib
`symtable` analysis. Class body shadowing is honored ordered with
class-local assignments.

### Python alias resolution (out of scope)

- Nested-under-control-flow imports (`if cond: import x`,
  `try: import x`).
- `from mod import *`.
- Relative imports (`from . import x`).
- Variable rebinding through attribute access
  (`obj.attr = os.system`).
- Annotation expressions (parameter / return) — PEP 563 / 649
  store them as strings.

Anything the analyzer cannot resolve statically is left at its
surface name rather than guessed.

### Policy-driven CLIs

A small set of CLIs (`git`, `gh`, `aws`, `curl`, `kubectl`, `terraform`) are
policy-driven via `rules/shell.json`. The walker pulls a command path from
argv and matches against:

- `unsafe_subcommands` at the top level;
- `nested_subcommand` specs for namespaces with mutating verbs at depth
  (e.g. `gh api`, `git reset`);
- `service_overrides` for AWS service-specific handling (only `iam` ships);
- `unsafe_flag_values` / `unsafe_flag_any_value` /
  `unsafe_flag_value_prefix` / `unsafe_flags_without_value` for flag-driven
  mutation (e.g. `find -exec`, `gh api --input`, `git reset --hard`);
- `write_target_last_positional` / `write_target_all_positional` /
  `write_value_prefix_targets`, which route an argument through
  `unsafe_write_targets` so `cp`/`mv`/`tee`/`dd`/`install` cannot be used to
  write a steering file.

Since Phase 3 there are **no `safe_subcommands` in the shipped rules.** A
verb on no list falls to `unknown` and is delegated; that is the mechanism,
not an omission. `_match_subcommand_lists` still honours `safe_subcommands`
for operator overrides.

One coupling is worth knowing because it is silent. The git deny policies
(`policies.git`, from
[#97](https://github.com/voitta-ai/voitta-yolt/issues/97)) are **parasitic**:
a policy runs only on a command the static rules already classified `unsafe`,
so it can narrow `unsafe` to `deny` but can never originate a verdict. That
is a deliberate safety property — a failed probe lands on the pre-existing
verdict and cannot manufacture a refusal — but it means deleting a rule also
disarms every policy attached to it, with nothing reported anywhere. It is
why `git push` survived Phase 3 despite being reversible, high-volume local
workflow: delegating it would have silently turned off `default_branch_target`
and `shared_history`. Any argv named in an enabled policy must stay reachable
as `unsafe`.

### Conservative-unknown contract

Every analysis surface follows the same fallback: if YOLT cannot
prove a command is safe, it does not say so. Categories that hit
this path:

- tree-sitter parse error (`tree-sitter parse error`);
- max recursion depth on nested decomposition;
- unknown command name;
- partially-modeled CLI namespace with a verb outside the policy;
- write redirect to a path on neither `unsafe_write_targets` (which
  classifies `unsafe`) nor `safe_write_targets` (which is benign);
- SQL string the conservative scanner cannot classify as read-only;
- Python source the AST delegate fails to parse;
- `rules/shell.json` failing schema validation — the hook logs
  `rules-validation-error` and exits silently so Claude Code's
  default prompt fires.

Schema validation runs at hook load time
(`hooks/rule_classifier.py:validate_shell_rules`) on both the
bundled rules and any user override, so a typo in a policy field
becomes a hard fail at startup rather than a silent false-allow.

## Design principles

- **Grammar-driven** — Bash decomposition uses the maintained
  tree-sitter-bash grammar. Quoting, expansions, control flow, heredocs,
  and process substitution are handled by the parser, not by string
  walkers (see [issue #4][issue-4]).
- **False positives OK, false negatives not** — unknown commands fall
  through to Claude Code's default prompt rather than being auto-allowed.
- **Configurable** — rules are data (`rules/shell.json`,
  `rules/default.json`), not code.
- **Fast** — classification is purely syntactic; no subprocess fork. A
  representative compound command parses in ~1ms.
