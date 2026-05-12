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
- [User allowlist as a secondary upgrade pass](#user-allowlist-as-a-secondary-upgrade-pass)
- [Dependencies](#dependencies)
- [What the grammar classifier handles](#what-the-grammar-classifier-handles)
- [SQL CLIs](#sql-clis)
- [Python rules (interpreter delegate)](#python-rules-interpreter-delegate)
- [Custom rules](#custom-rules)
  - [Python rules — `~/.claude/yolt/rules.json`](#python-rules---claudeyoltrulesjson)
  - [Shell rules — `~/.claude/yolt/shell.json`](#shell-rules---claudeyoltshelljson)
- [Debug / dogfood log](#debug--dogfood-log)
- [CLI usage](#cli-usage)
- [Tests and demo](#tests-and-demo)
- [Design principles](#design-principles)

## Introduction

A Claude Code hook that statically analyzes script invocations before
execution, auto-allowing read-only ones and flagging mutating ones for
review.

YOLT closes two gaps in Claude Code's built-in allowlist matcher:

1. **Arbitrary-execution wrappers.** Interpreters (`bash`, `python3`,
   `node`, ...) and dual-use CLIs (`gh api`, `curl`, `kubectl`, ...) can't
   be allowlisted with a wildcard without granting arbitrary execution,
   so a long tail of clearly read-only invocations prompt every time.
2. **Compound shell commands.** The built-in matcher sees the outer wrapper
   (`for`, `while`, `bash -c "..."`, `$(...)`), not the inner commands it
   runs, so loops and command substitutions prompt even when every inner
   command would be allowlisted on its own.

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
> bypasses `PreToolUse` hooks. Do not allowlist `Bash(python3:*)`,
> `Bash(aws:*)`, `Bash(gh:*)`, etc. with wildcards - YOLT's classifier
> will never fire and mutating invocations will run without review. Narrow
> allowlist patterns that don't cover mutating operations (e.g.
> `Bash(aws ecs list-services*)`) are fine; they just short-circuit YOLT
> for the matching subset.

## User allowlist as a secondary upgrade pass

YOLT reads your `permissions.allow` Bash() entries from
`~/.claude/settings.json`, the project's `.claude/settings.json`, and
`.claude/settings.local.json`. After the rule classifier runs on each
AST `command` node, any node that would otherwise be `unknown` is
upgraded to `safe` if its reconstructed argv matches one of those
patterns.

This earns its keep on compound forms. The built-in matcher only sees
the outer wrapper, so a `for ... do CMD; done` whose `CMD` you've
already allowlisted (`Bash(mycli list*)`) still prompts. YOLT walks
into the loop body and matches each command against the allowlist.

Two rules apply:

- The match uses `fnmatch` glob semantics — the same semantics Claude
  Code's outer matcher uses. `Bash(env)` matches `env` exactly;
  `Bash(aws s3 ls*)` matches anything that starts with `aws s3 ls`.
- A match **never weakens an `unsafe` decision**. If your rules say
  `aws iam delete-user` is mutating, a permissive `Bash(aws *)` does
  not turn it into safe — YOLT keeps flagging mutating calls.

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
binding; function-internal rebinds keep the module-level binding
intact since they have their own scope.

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
positions that run at module load — class bodies, decorators, default
and keyword-default argument values, parameter annotations (positional,
positional-only, keyword-only, `*args`, and `**kwargs`), and return
annotations — resolve against the position-aware snapshot like any
other module-scope call.

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
