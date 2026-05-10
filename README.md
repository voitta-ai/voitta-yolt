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
- `redirected_statement` — check redirect targets. A write to anything
  other than `/dev/null` falls through to `unknown` (Claude Code default
  prompt). For `python3 << ... <<EOF` heredocs, the body goes to the
  Python analyzer.
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
interpreters delegate inline scripts (see lead-in); known CLIs use
their `rules/shell.json` spec; wrappers (`time`, `xargs`, `timeout`,
`env`, `nice`, `watch`, ...) re-classify the wrapped command; anything
else → unknown.

## Install

YOLT ships as a [Claude Code plugin](https://code.claude.com/docs/en/plugins).
This repo is its own marketplace, so the install is two slash commands:

```
/plugin marketplace add voitta-ai/voitta-yolt
/plugin install yolt@voitta-yolt
```

The plugin's `hooks/hooks.json` registers the `PreToolUse` hook on `Bash`
automatically — no manual `settings.json` edit needed. Run
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

Install with `pip install -r requirements.txt`. The plugin install path
expects them on the same Python that runs `hooks/pre-tool-use.sh`. If
either is missing, the hook exits silently and Claude Code falls through
to its default prompt — YOLT does not break the user's session on a
broken install.

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
| `bash -c "ls /tmp"` / `bash -c "rm /etc/passwd"`             | allow / ask |
| `for svc in $(aws ecs list-services --cluster X); do aws ecs describe-services --cluster X --services "$svc"; done` | allow |
| `echo foo \| xargs rm` / `echo foo \| xargs cat`             | ask / allow |
| `time aws ec2 describe-instances`                            | allow    |
| `cat file > /tmp/out`                                        | unknown (writes to a file) |
| `aws ec2 describe-instances > /dev/null`                     | allow    |

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
  "shell_builtins_safe": ["my-safe-wrapper"]
}
```

User overrides merge with (and override) defaults per top-level key.
Examples: `examples/user-overrides.json`, `examples/shell-overrides.json`.

## Debug / dogfood log

YOLT logs every examined Bash invocation by default to
`~/.claude/yolt.log`. Each line is a JSON record:

```json
{"ts": "2026-05-08T14:00:00.000+00:00", "decision": "safe", "reason": "ls: read-only", "command": "ls /tmp"}
```

`decision` is one of `safe`, `unsafe`, `unknown`, or `import-error` (the
last when the tree-sitter dependency is missing). The `command` field is
truncated to 500 characters. Logging failures are swallowed — the hook
never breaks the session because of an unwritable log path.

```bash
tail -f ~/.claude/yolt.log
```

This is the cleanest way to QA YOLT against your own session: the
Claude Code UI hides the hook's contribution when your `permissions.allow`
already covers the command, but the log records every fire.

To override the log location, set `YOLT_LOG_FILE` to an absolute path.
To opt out entirely, set `YOLT_LOG_FILE=""` (empty string).

> The log grows unbounded. There is no rotation today — if the file
> gets uncomfortable, `truncate -s 0 ~/.claude/yolt.log` or rotate it
> with your tool of choice.

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
