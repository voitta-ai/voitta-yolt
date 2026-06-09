# YOLT — You Only Live Twice

> *YOLO* — "You Only Live Once" — is the
> [vibe-coder's mantra](https://www.reddit.com/r/vibecoding/comments/1qyuvwe/the_transition_from_vibe_coding_to_yolo_coding/) for shipping fast and dealing with
> consequences later.
>
> *YOLT* — "You Only Live Twice" — is the
> [for James Bond ](https://www.youtube.com/watch?v=hs8uYxTJ530) in the rest of us.
> The hook gives the agent a second pass before the destructive Bash actually runs.

## Contents

- [Introduction](#introduction)
- [How it works](#how-it-works)
- [Install](#install)
  - [Updating](#updating)
  - [Migrating from manual to plugin install](#migrating-from-manual-to-plugin-install)
  - [Manual install (without the plugin system)](#manual-install-without-the-plugin-system)
- [User whitelist as a secondary upgrade pass](#user-whitelist-as-a-secondary-upgrade-pass)
- [Dependencies](#dependencies)
- [What the grammar classifier handles](#what-the-grammar-classifier-handles)
- [SQL CLIs](#sql-clis)
- [Python rules (interpreter delegate)](#python-rules-interpreter-delegate)
- [Custom rules](#custom-rules)
  - [Python rules — `~/.claude/yolt/rules.json`](#python-rules---claudeyoltrulesjson)
  - [Shell rules — `~/.claude/yolt/shell.json`](#shell-rules---claudeyoltshelljson)
- [Debug / dogfood log](#debug--dogfood-log)
- [Self-improvement loop](#self-improvement-loop)
- [CLI usage](#cli-usage)
- [Tests and demo](#tests-and-demo)
- [Analysis boundaries](#analysis-boundaries)
- [Design principles](#design-principles)

## Introduction

A Claude Code hook that statically analyzes script invocations before
execution, auto-allowing read-only ones and flagging mutating ones for
review.

YOLT closes two gaps in Claude Code's built-in whitelist matcher:

1. **Arbitrary-execution wrappers.** Interpreters (`bash`, `python3`,
   `node`, ...) and dual-use CLIs (`gh api`, `curl`, `kubectl`, ...) can't
   be whitelisted with a wildcard without granting arbitrary execution,
   so a long tail of clearly read-only invocations prompt every time.
2. **Compound shell commands.** The built-in matcher sees the outer wrapper
   (`for`, `while`, `bash -c "..."`, `$(...)`), not the inner commands it
   runs, so loops and command substitutions prompt even when every inner
   command would be whitelisted on its own.

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
- `redirected_statement` — check redirect targets against the
  `safe_write_targets` glob list in `rules/shell.json` (defaults
  include `/dev/null`, `/tmp/*`, `/var/folders/*`, `~/.cache/*`,
  `~/.claude/*`, etc.). Anything not on the list falls through to
  `unknown` so Claude Code default-prompts. For
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

- `safe` → `permissionDecision: allow` with a short reason.
- `unsafe` → `permissionDecision: ask` with the specific reason.
- `unknown` → silent exit; Claude Code falls through to its default.

Argv is dispatched per-`command_name`: safe builtins → safe;
interpreters delegate inline scripts (see lead-in); `python3 -m <mod>`
consults the `safe_modules` / `unsafe_modules` / `nested_modules` lists
in `rules/shell.json#interpreters.python3` (so e.g. `python3 -m pip list`
is safe but `python3 -m pip install` is unsafe); known CLIs use their
`rules/shell.json` spec; wrappers (`time`, `xargs`, `timeout`, `env`,
`nice`, `watch`, ...) re-classify the wrapped command; anything else →
unknown.

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

## User whitelist as a secondary upgrade pass

YOLT reads your `permissions.allow` Bash() entries from
`~/.claude/settings.json`, the project's `.claude/settings.json`, and
`.claude/settings.local.json`. After the rule classifier runs on each
AST `command` node, any node that would otherwise be `unknown` or
`unsafe` is upgraded to `safe` if its reconstructed argv matches one
of those patterns.

This earns its keep on compound forms. The built-in matcher only sees
the outer wrapper, so a `for ... do CMD; done` whose `CMD` you've
already whitelisted (`Bash(mycli list*)`) still prompts. YOLT walks
into the loop body and matches each command against the whitelist.

Two rules apply:

- The match uses `fnmatch` glob semantics — the same semantics Claude
  Code's outer matcher uses. `Bash(env)` matches `env` exactly;
  `Bash(aws s3 ls*)` matches anything that starts with `aws s3 ls`.
- A match is an explicit user override. Keep patterns narrow:
  `Bash(aws ecs list-services*)` is fine; `Bash(git *)` or
  `Bash(gh *)` will allow matching mutating commands anywhere YOLT
  reconstructs the same argv, including inside compound forms.

For common self-PR workflow writes (`git push`, `git commit`,
`gh issue create`, `gh pr comment`, ...), YOLT's `ask` message now
includes a paste-ready `Bash(...)` suggestion when no allow pattern
matched yet.

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
| `cat file > /etc/profile`                                    | unknown (writes to a system path) |
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
overriding `safe_write_targets` replaces the entire list; if you want to
add `/scratch/*` while keeping the defaults, copy the default list
through. Examples: `examples/user-overrides.json`,
`examples/shell-overrides.json`.

## Debug / dogfood log

YOLT logs every examined Bash invocation by default to
`~/.claude/yolt.log`. Each line is a JSON record:

```json
{"ts": "2026-05-08T14:00:00.000+00:00", "decision": "safe", "reason": "ls: read-only", "command": "ls /tmp"}
```

`decision` is one of `safe`, `unsafe`, `unknown`, `import-error` (the
tree-sitter dependency is missing), or `rules-validation-error` (the
bundled or user-override `shell.json` failed schema validation; the
`reason` field carries the list of offending keys / defaults so the
user can fix the override). The `command` field is truncated to 500
characters. Logging failures are swallowed — the hook never breaks the
session because of an unwritable log path.

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
  flag-conditional or verb-class, keeping the AST walk in the loop
  (generating these directly is issue
  [#45](https://github.com/voitta-ai/voitta-yolt/issues/45)).
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
```

Override the state directory with `YOLT_STATE_DIR`. The reviewer is
read-mostly: it only ever writes its own files under `~/.claude/yolt/`;
all edits to `settings.json` and override files go through you. A Codex
CLI parity loop is tracked in issue
[#46](https://github.com/voitta-ai/voitta-yolt/issues/46).

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
- redirections — write targets matched against
  `safe_write_targets`; non-matching writes fall to `unknown`;
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
- write redirect to a path not on `safe_write_targets`;
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
