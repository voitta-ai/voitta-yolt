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
- [SQL CLIs](#sql-clis)
- [Python rules (interpreter delegate)](#python-rules-interpreter-delegate)
- [Custom rules](#custom-rules)
  - [Python rules — `~/.claude/yolt/rules.json`](#python-rules---claudeyoltrulesjson)
  - [Shell rules — `~/.claude/yolt/shell.json`](#shell-rules---claudeyoltshelljson)
- [Credentials in the command line (advisory)](#credentials-in-the-command-line-advisory)
- [Debug / dogfood log](#debug--dogfood-log)
  - [Credential redaction](#credential-redaction)
- [Self-improvement loop](#self-improvement-loop)
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

`CLAUDE.md` has the full convention: which semver part to bump for what,
and how to tag under this repo's squash-merge policy (edit the version in
the PR; tag master's squash commit after the merge). `scripts/release.sh
<version>` rewrites and validates the field, but its commit-and-tag half
does not fit squash merges — see `CLAUDE.md`.

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

Your `permissions.allow` entries still work — Claude Code honors them
itself, which is the appropriate place for them.

For common workflow writes (`git push`, `git commit`, `gh issue create`,
`gh pr comment`, ...), YOLT's `ask` message still includes a paste-ready
`Bash(...)` suggestion. It is advice to you, not a grant: nothing happens
until you add it yourself, and Claude Code — not YOLT — is what acts on it.

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

Example decisions (see `rules/shell.json` for the full rule set):

| Command                                                      | Decision |
| ------------------------------------------------------------ | -------- |
| `aws ec2 describe-instances`                                 | allow    |
| `aws ec2 terminate-instances --instance-ids i-abc`           | ask      |
| `aws --profile prod --region us-east-1 ec2 describe-instances --no-cli-pager` | allow |
| `aws s3 ls` / `aws s3 rm s3://bucket/key`                    | allow / ask |
| `aws logs start-query --log-group-name X --query-string ...` | allow (service override: `start-query` is read-only) |
| `gh api /repos/x/y/issues`                                   | allow    |
| `gh api -X POST /repos/x/y/issues`                           | ask      |
| `gh pr list` / `gh pr merge`                                 | allow / ask |
| `curl https://api.example.com/users`                         | allow    |
| `curl -X POST ... -d ...`                                    | ask      |
| `kubectl get pods` / `kubectl exec -it pod -- bash`          | allow / ask |
| `terraform plan` / `terraform apply`                         | allow / ask |
| `terraform state list` / `terraform state rm foo`            | allow / ask |
| `git status` / `git push`                                    | allow / ask |
| `find . -name '*.py'`                                        | allow    |
| `find . -name '*.py' -delete`                                | ask      |
| `sed 's/a/b/' f` / `sed -i 's/a/b/' f`                       | allow / ask |
| `python3 -c "print(1+1)"`                                    | allow    |
| `python3 -c "import os; os.system('rm -rf /')"`              | ask      |
| `python3 -m json.tool` / `python3 -m http.server`            | allow / ask |
| `python3 -m pip list` / `python3 -m pip install requests`    | allow / ask |
| `bash -c "ls /tmp"` / `bash -c "rm /etc/passwd"`             | allow / ask |
| `for svc in $(aws ecs list-services --cluster X); do aws ecs describe-services --cluster X --services "$svc"; done` | allow |
| `echo foo \| xargs rm` / `echo foo \| xargs cat`             | ask / allow |
| `time aws ec2 describe-instances`                            | allow    |
| `cat file > /tmp/out`                                        | allow (`/tmp/*` is on the safe-write list) |
| `echo x > /etc/profile` / `echo x > ~/.bashrc`               | ask (on the `unsafe_write_targets` deny list) |
| `echo x > ~/.claude/settings.json`                           | ask (deny list overrides the `~/.claude/*` safe glob) |
| `echo x > ~/.claude/cache.json`                              | allow (`~/.claude/*` safe-write; not on the deny list) |
| `aws ec2 describe-instances > /dev/null`                     | allow    |
| `sqlite3 db.sqlite "SELECT * FROM t"`                        | allow    |
| `sqlite3 db.sqlite "DROP TABLE t"`                           | ask      |
| `sqlite3 db.sqlite ".tables"` / `... ".import f.csv t"`      | allow / ask |
| `psql -c "SELECT now()" mydb` / `psql -c "DELETE FROM t" mydb` | allow / ask |
| `mysql -e "SHOW DATABASES" mydb` / `mysql -e "DROP TABLE t" mydb` | allow / ask |

## SQL CLIs

`sqlite3`, `psql`, `mysql`, `mariadb`, and `duckdb` are classified via
the `sql_cli` default. The argv walker pulls the SQL string out
(positional for sqlite3/duckdb, `-c` / `--command` for psql, `-e` /
`--execute` for mysql/mariadb) and runs a conservative scan:

1. Strip line comments (`-- ...`), block comments (`/* ... */`), and
   string/identifier literals (`'...'`, `"..."`, `` `...` ``).
2. If any of `INSERT / UPDATE / DELETE / DROP / CREATE / ALTER /
   TRUNCATE / REPLACE / MERGE / GRANT / REVOKE / VACUUM / REINDEX /
   ATTACH / DETACH / COPY / LOAD / IMPORT / LOCK / CALL / EXEC /
   SET / RESET / BEGIN / COMMIT / ROLLBACK / ...` survives → `unsafe`.
3. Otherwise, if the first remaining keyword is `SELECT / WITH /
   EXPLAIN / SHOW / DESCRIBE / DESC / VALUES / TABLE` → `safe`.
4. `PRAGMA` is `safe` for reads, `unsafe` if it contains `=`
   (sqlite assignment form).
5. Anything else → `unknown` (Claude Code's default prompt fires).

SQL fed via file (`psql -f queries.sql`, `mysql < queries.sql`) is
opaque to a static checker and stays `unknown`. Bare `sqlite3 db.sqlite`
also stays `unknown` because it opens an interactive shell.

sqlite3 dot-commands (`.tables`, `.schema`, `.import`, `.read`, ...)
are classified separately by name — `.tables` / `.schema` / `.headers`
are safe; `.import` / `.load` / `.read` / `.shell` / `.backup` are
unsafe.

### SQL carried in cloud-CLI flags

Several AWS CLIs take a SQL string as a flag value (`aws athena
start-query-execution --query-string`, `aws rds-data execute-statement
--sql`, `aws timestream-query query --query-string`, `aws redshift-data
execute-statement --sql`). The `aws` rule names these in a
`sql_payload_flags` registry keyed by `"<service> <operation>"`; each
entry gives the SQL-carrying `flag` and a `dialect`. When the operation
matches, the flag value is pulled and run through the same SQL scanner
described above.

The verb decision is a **floor**, so payload scanning never weakens a
mutating operation on its own:

- A write verb (`start-*`, `execute-*`) stays `unsafe` regardless of
  payload. Reading the SQL only helps once the user has explicitly
  marked the operation safe — e.g. an `extra_safe_patterns` override
  for `start-query-execution`. After that, the payload governs:
  read-only `SELECT` → `safe`, destructive SQL → `unsafe`, unclassified
  SQL → `unknown`. This is the point of the registry: an override that
  used to blanket-allow every query now keeps destructive ones flagged.
- `aws timestream-query query` matches no verb pattern (so it was
  `unknown` and prompted every time); its payload now refines it to
  `safe` / `unsafe` out of the box.

`dialect` feeds the per-dialect function-side-effect scanner (see issue
#26). `presto` / `timestream` / `redshift` / `varies` have no function
deny-set yet, so only the dialect-agnostic keyword scan applies to them
today; the field is recorded so adding a deny-set later lights up
function detection for those services with no further wiring.

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
`--token`, connection strings — and both logs are append-only, so
anything written to them should be assumed permanent. Before a record is
written, credential-shaped substrings in `command` (and in `reason`) are
replaced with a `[REDACTED:<shape>]` marker naming the shape only, never
the value. This applies to `~/.claude/yolt.log` and
`~/.claude/yolt-ran.log` alike, and happens at write time — the risk
being closed is the file on disk. Issue
[#84](https://github.com/voitta-ai/voitta-yolt/issues/84).

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

## Self-improvement loop

The dogfood log is also a record of where YOLT got in your way. The
reviewer (`hooks/yolt_review.py`, issue
[#44](https://github.com/voitta-ai/voitta-yolt/issues/44)) mines that log
for recurring friction and distills it into a human-reviewable doc plus a
suggestion state file under `~/.claude/yolt/`:

- `~/.claude/yolt/review.md` — the doc you read.
- `~/.claude/yolt/suggestions.json` — suggestion ids with
  pending / applied / dismissed status that survives regeneration.

Repeated commands are grouped to a conservative prefix (argv head plus
subcommand tokens — no flags, no values, no paths) and sorted into three
buckets:

- **`friction-unsafe`** — YOLT returned `ask` on this prefix repeatedly.
- **`friction-unknown`** — the command fell through to Claude Code's
  default prompt repeatedly (a rules gap, or a personal/internal CLI).
- **`fastpath`** — YOLT auto-allowed this prefix at high frequency; a
  static `permissions.allow` glob would skip the hook startup entirely
  (a static allow rule
  [bypasses PreToolUse hooks](#install) natively).

Grouping is stdlib-only and deliberately does not depend on tree-sitter,
so the reviewer still works when the grammar deps failed to bootstrap.
Compound commands (pipes, substitutions, loops) are counted but never
turned into suggestions — a prefix glob cannot express them; rules and
user overrides handle those (issue
[#45](https://github.com/voitta-ai/voitta-yolt/issues/45)).

### Did you approve, or did YOLT?

A second log, `~/.claude/yolt-ran.log`, is written by a PostToolUse hook:
one record per Bash command that actually ran. A command that YOLT said
`ask` on only reaches PostToolUse if you approved it at the prompt (a
denied command never runs). The reviewer correlates the two logs by
timestamp, so each `friction-unsafe` suggestion carries an `approved`
count — high `approved` is real friction worth acting on; `approved` 0
means YOLT is very likely doing its job. Override with `YOLT_RAN_LOG_FILE`
(absolute path) or opt out with `YOLT_RAN_LOG_FILE=""`.

### Routing — and the collision veto

Each suggestion routes to exactly one of three remediations:

- **`settings.json` allow** — for a prefix that is read-only regardless
  of flags. Fastest, but a static allow rule bypasses YOLT's hook
  entirely (including its redirect and command-substitution checks).
- **Local override** — a `~/.claude/yolt/shell.json` rule for anything
  flag-conditional or verb-class, keeping the AST walk in the loop. For
  the narrow, additive case of a personal CLI hitting `unknown` on a
  subcommand, the reviewer writes the `safe_subcommands` override itself
  (`--write-override <id>`); deeper rules stay hand-written. See
  [Writing overrides](#writing-overrides-issue-45).
- **Upstream issue** — a common CLI repeatedly hitting `unknown` is
  likely a rules gap worth reporting on voitta-ai/voitta-yolt.

The safety-critical part is the **glob-collision veto**: a `fastpath`
prefix like `gh api` is read-only, but `gh api -X POST` is not, and both
match `Bash(gh api*)`. Promoting that glob to `permissions.allow` would
silently bypass YOLT for the POST too. Before recommending any
`settings.json` glob, the reviewer fnmatches it against every command
YOLT did *not* classify safe; any hit is recorded as a collision and the
suggestion is re-routed to a `shell.json` rule instead, never the
whitelist. Partially-overlapping namespaces stay suggestable —
`gh pr view*` does not collide with `gh pr merge`.

Only the redacted `shape` field (argv head plus flag names, every value
stripped to `<...>`) may leave the machine in an upstream issue. The
`examples` lines are raw log data and stay local.

### Surfacing and applying

- **`/yolt:review`** — the slash command that walks you through pending
  suggestions, honors the routing above, edits `settings.json` /
  `shell.json` with your confirmation, and records each as applied or
  dismissed.
- **SessionStart** prints a one-line nudge toward `/yolt:review` when
  there are pending suggestions, throttled to once per 24h. It reads only
  the small state file — it never parses the decision log.
- **SessionEnd** regenerates the doc with `--generate --if-stale`: a
  no-op (just an mtime check) when the log has not changed since the last
  run, so quiet sessions cost almost nothing.

Run it by hand the same way the hooks do:

```bash
python3 hooks/yolt_review.py --generate   # parse logs, write doc + state
python3 hooks/yolt_review.py --status     # {"pending": N, ...}
python3 hooks/yolt_review.py --list       # full suggestion JSON
python3 hooks/yolt_review.py --applied <id> [<id> ...]
python3 hooks/yolt_review.py --dismiss <id> [<id> ...]
python3 hooks/yolt_review.py --write-override <id> [<id> ...]  # see below
```

Override the state directory with `YOLT_STATE_DIR`. The reviewer only
ever writes under `~/.claude/yolt/`: its own state files, and — via
`--write-override` — the `shell.json` override the hook reads. Edits to
`settings.json` go through you. A Codex CLI parity loop is tracked in
issue [#46](https://github.com/voitta-ai/voitta-yolt/issues/46).

### Writing overrides (issue [#45](https://github.com/voitta-ai/voitta-yolt/issues/45))

`--write-override <id>` turns a `friction-unknown` suggestion into a
`~/.claude/yolt/shell.json` rule, for the one case the reviewer can infer
safely: a **personal CLI** (no bundled rule) that fell through to
`unknown` on a subcommand. It writes a `safe_subcommands` fragment
asserting that one observed subcommand is read-only —

```json
{"commands": {"mycli": {"default": "subcommand", "safe_subcommands": ["status"]}}}
```

— so `mycli status` auto-allows while every other `mycli` subcommand
still prompts (the assertion is strictly additive; it never marks the
whole CLI safe, and never flips an existing `unsafe` verdict). A
`cli group sub` prefix nests under
`nested_subcommand.<group>.safe_subcommands` instead. Each suggestion's
`override` field carries `writable`, the `label`, and the exact
`fragment`.

Three properties make the write safe:

- **Read-modify-write** — overrides merge per top-level key (a `commands`
  override replaces individual command specs), so the writer reads the
  existing file and unions the new subcommand in, never clobbering
  entries you already have.
- **Validate before write** — the merged result (bundled rules ∪ the
  override) is checked with `validate_shell_rules`; the writer refuses to
  write anything that would fail, since a malformed override downgrades
  the whole hook to `rules-validation-error`.
- **Personal-CLI only** — a `friction-unknown` on a *bundled* CLI is a
  rules gap worth an upstream issue, not a local shadow that would freeze
  a stale copy of the bundled spec. Flag-conditional, verb-class, and
  `friction-unsafe` overrides stay hand-written.

Override the paths the writer reads/writes with `YOLT_RULES_DIR` (bundled
rules) and `YOLT_SHELL_OVERRIDE` (the user override file).

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

### SQL CLIs (in scope)

`sqlite3`, `psql`, `mysql`, `mariadb`, `duckdb` — inline SQL string
extracted from argv and scanned for destructive keywords; see
[SQL CLIs](#sql-clis).

### SQL CLIs (out of scope)

- SQL fed via file (`psql -f q.sql`, `mysql < q.sql`) — opaque
  statically, stays `unknown`.
- Bare interactive invocations (`sqlite3 db.sqlite` with no SQL) —
  stay `unknown`.
- Other SQL clients (`cockroach sql`, `clickhouse-client`,
  `snowsql`, ...) — not classified by the SQL path.

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

Common CLIs (`gh`, `git`, `aws`, `curl`, `kubectl`, `helm`, `docker`,
`terraform`, ...) are policy-driven via `rules/shell.json`. The
walker pulls a command path from argv and matches against:

- `safe_subcommands` / `unsafe_subcommands` at the top level;
- `nested_subcommand` specs for namespaces with mutating verbs at
  arbitrary depth (e.g. `docker image rm`, `kubectl config
  set-context`, `helm repo add`);
- `service_overrides` for AWS service-specific reads
  (e.g. `aws logs start-query` is read-only despite the verb);
- `unsafe_flags` / `unsafe_flag_values` /
  `unsafe_flag_any_value` / `unsafe_flag_value_prefix` /
  `unsafe_flags_without_value` for flag-driven mutation
  (e.g. `find -exec`, `gh api --input`).

For namespaces that are only partially modeled, bare and unmodeled
verbs fall to `unknown` rather than silently classifying safe.

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
