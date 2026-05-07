# YOLT - You Only Live Twice

A Claude Code hook that statically analyzes commands before execution,
auto-allowing read-only invocations and flagging mutating ones for review.

YOLT closes two gaps in Claude Code's built-in allowlist matcher:

1. **Arbitrary-execution wrappers.** Interpreters (`python3`, `bash`, `node`,
   ...) and dual-use CLIs (`gh api`, `curl`, `kubectl`, ...) can't be
   allowlisted with a wildcard without granting arbitrary execution, so a
   long tail of clearly read-only invocations prompt every time.
2. **Compound shell commands.** The built-in matcher sees the outer wrapper
   (`for`, `while`, `bash -c "..."`, `$(...)`), not the inner commands it
   runs, so loops and command substitutions prompt even when every inner
   command would be allowlisted on its own.

YOLT ships with two analyzers that share a single `PreToolUse` hook entry:

- **Shell classifier** (`hooks/shell_classifier.py`) - decomposes compound
  commands, strips wrapper syntax, and classifies each atomic command
  against `rules/shell.json`.
- **Python analyzer** (`hooks/yolt_analyzer.py`) - parses Python source via
  the AST and walks all calls against `rules/default.json`. Invoked by the
  shell classifier for `python3 -c ...` and `python3 script.py`.

## How it works

YOLT registers as a `PreToolUse` hook on the `Bash` tool. For every Bash
invocation the hook:

1. Extracts `$(...)` and `` `...` `` substitutions, classifying each inner
   command.
2. Splits the remainder on top-level `;`, `&&`, `||`, `|`, `&`, and
   newlines into simple commands, while respecting quoting.
3. Strips leading shell keywords (`for VAR in`, `while`, `if`, `do`,
   `done`, `case PAT in`, ...) and environment-variable assignments
   (`FOO=bar cmd`).
4. Strips redirections. If any redirection writes to a file target other
   than `/dev/null`, the command is left for Claude Code's default prompt
   instead of being auto-allowed.
5. Classifies the remaining argv:
   - Safe shell builtin (`echo`, `pwd`, `test`, `[`, `cd`, ...) -> safe.
   - Known interpreter (`python3`, `bash`, ...) -> delegate to the Python
     analyzer or recurse into the shell classifier.
   - Known command with rules (`aws`, `gh`, `curl`, `kubectl`, `git`,
     `docker`, `terraform`, `find`, `sed`, ...) -> per-command rule.
   - Wrappers (`time`, `xargs`, `timeout`, `env`, `nice`, `watch`, ...) ->
     re-classify the wrapped command.
   - Anything else -> unknown.
6. Aggregates decisions with precedence `unsafe > unknown > safe`.
7. Emits a hook response:
   - `safe` -> `permissionDecision: allow` with a short reason.
   - `unsafe` -> `permissionDecision: ask` with the specific reason.
   - `unknown` -> silent exit; Claude Code falls through to its default.

## Install

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
`.claude/settings.local.json`. After the rule classifier runs, any
*decomposed segment* that would otherwise be `unknown` is upgraded to
`safe` if it matches one of those patterns.

This earns its keep on compound forms. The built-in matcher only sees
the outer wrapper, so a `for ... do CMD; done` whose `CMD` you've
already allowlisted (`Bash(mycli list*)`) still prompts. YOLT splits the
loop into atomic segments, each of which gets the allowlist match.

Two rules apply:

- The match works on the segment string after substitution extraction
  and top-level splitting, using `fnmatch` glob semantics - the same
  semantics Claude Code's outer matcher uses. `Bash(env)` matches
  `env` exactly; `Bash(aws s3 ls*)` matches anything that starts with
  `aws s3 ls`.
- A match **never weakens an `unsafe` decision**. If your rules say
  `aws iam delete-user` is mutating, a permissive `Bash(aws *)` does
  not turn it into safe - YOLT keeps flagging mutating calls.

## What the shell classifier handles

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

## Python-analyzer rules

`rules/default.json` covers:

- **AWS boto3** - `describe/list/get/head` safe; `delete/put/create/terminate` destructive
- **File I/O** - `open()` write modes, `os.remove`, `shutil.rmtree`, etc.
- **Subprocess** - `subprocess.run`, `os.system`, etc. (always flagged)
- **Network** - `requests.get` safe; `requests.post/put/delete` destructive
- **Database** - connection creation flagged for review

Rules use `trigger_imports` to scope checks. For example, boto3 patterns only
apply when `boto3` is imported, so `cache.delete_item()` in a non-AWS script
won't false-positive.

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

## CLI usage

Analyze a Python script directly:

```bash
python3 hooks/yolt_analyzer.py script.py
```

Classify a shell command directly:

```bash
python3 hooks/shell_classifier.py 'for svc in $(aws ecs list-services --cluster X); do aws ecs describe-services --cluster X --services "$svc"; done'
```

Both return JSON. The shell classifier's output shape is
`{"decision": "safe|unsafe|unknown", "reason": "..."}`.

## Tests and demo

Unit tests cover the decomposition helpers, the classifier, and the hook
entry point. They use stdlib `unittest` only:

```bash
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

- **Zero dependencies** - stdlib only (`ast`, `json`, `fnmatch`, `shlex`, `re`)
- **False positives OK, false negatives not** - unknown commands fall through
  to Claude Code's default prompt rather than being auto-allowed.
- **Configurable** - rules are data, not code.
- **Fast** - classification is purely syntactic; no subprocess fork.
