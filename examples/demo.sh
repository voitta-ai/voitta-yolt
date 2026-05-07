#!/bin/bash
# examples/demo.sh - show the shell classifier's decision on a range of
# representative invocations.
#
# This is a "visual" check, not an assertion-backed test: it prints the
# decision for each command so a human can confirm the classifier behaves
# sensibly. For programmatic checks see tests/test_shell_classifier.py.
#
# Usage:
#     ./examples/demo.sh
#
# Output format:
#     <decision>  <command>
# where <decision> is one of safe / unsafe / unknown.

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
YOLT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CLS="$YOLT_ROOT/hooks/shell_classifier.py"

if [[ ! -f "$CLS" ]]; then
  echo "error: cannot find $CLS" >&2
  exit 1
fi

# Each element is a single command. Quoted carefully - this array is the
# input to the classifier, nothing else evaluates it.
commands=(
  # Safe: plain read-only
  'ls /tmp'
  'cat /etc/hosts'
  'grep foo /tmp/log'
  'find . -name "*.py"'
  'sed "s/a/b/" file.txt'

  # Safe: AWS reads, with and without the ZoomInfo house style flags
  'aws ec2 describe-instances'
  'aws --profile prod --region us-east-1 ec2 describe-instances --no-cli-pager'
  'aws s3 ls'
  'aws logs start-query --log-group-name X --query-string "fields @timestamp"'

  # Safe: dual-use tools in read mode
  'gh api /repos/x/y/issues'
  'gh pr list'
  'curl https://api.example.com/users'
  'kubectl get pods -A'
  'kubectl describe deployment mydep'
  'git status'
  'git log --oneline -5'
  'terraform plan'
  'terraform state list'

  # Safe: interpreters with analyzable benign payloads
  'python3 -c "print(1+1)"'
  'bash -c "ls /tmp"'

  # Safe: compound forms
  'ls /tmp && pwd'
  'for svc in $(aws ecs list-services --cluster X); do aws ecs describe-services --cluster X --services "$svc"; done'
  'if aws ec2 describe-instances; then echo ok; fi'
  'case "$x" in a) ls ;; b) cat /etc/passwd ;; esac'
  '[[ -d /tmp ]] && ls /tmp'
  '{ ls /tmp; echo done; }'
  'FOO=bar BAZ=qux aws s3 ls'
  'time aws ec2 describe-instances'
  'echo foo | xargs cat'
  'aws ec2 describe-instances > /dev/null'
  'aws ec2 describe-instances 2>/dev/null | jq .'

  # Unsafe: direct mutation
  'rm -rf /tmp/foo'
  'sed -i "s/a/b/" file.txt'
  'find . -name "*.py" -delete'

  # Unsafe: AWS writes
  'aws ec2 terminate-instances --instance-ids i-abc'
  'aws s3 rm s3://bucket/key'

  # Unsafe: dual-use tools in write mode
  'gh api -X POST /repos/x/y/issues'
  'gh api /repos/x/y/issues -f title=bug'
  'curl -X POST https://api.example.com/users -d bar'
  'curl --data foo=bar https://api.example.com/users'
  'kubectl exec -it pod -- bash'
  'kubectl apply -f manifest.yaml'
  'git push origin main'
  'terraform apply'
  'terraform state rm foo.bar'

  # Unsafe: interpreters with destructive payloads
  'python3 -c "import os; os.system(\"rm -rf /\")"'
  'bash -c "rm -rf /etc"'
  'echo foo | xargs rm'

  # Unsafe: compound forms containing a destructive step
  'ls /tmp && rm -rf /etc'
  'case "$x" in a) ls ;; b) rm /tmp/foo ;; esac'
  '! rm -rf /tmp/foo'

  # Unknown: the classifier has no rule, and /
  # or the invocation writes to a file, so it falls through to Claude
  # Code's default prompt.
  'somecommand_unknown --flag'
  'aws ec2 describe-instances > out.json'
  'echo x > /etc/profile'
)

# Colorize to make scanning easier. Falls back to plain text if the
# terminal doesn't support colors.
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1; then
  GREEN="$(tput setaf 2)"
  RED="$(tput setaf 1)"
  YELLOW="$(tput setaf 3)"
  DIM="$(tput dim)"
  RESET="$(tput sgr0)"
else
  GREEN=""; RED=""; YELLOW=""; DIM=""; RESET=""
fi

for cmd in "${commands[@]}"; do
  # The CLI exits 0 for safe, non-0 otherwise; we don't care about the exit
  # code, we want the JSON decision.
  decision="$(python3 "$CLS" "$cmd" 2>/dev/null \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["decision"])' \
    2>/dev/null || echo "error")"

  case "$decision" in
    safe)    color="$GREEN" ;;
    unsafe)  color="$RED" ;;
    unknown) color="$YELLOW" ;;
    *)       color="$DIM" ;;
  esac

  printf "%s%-8s%s %s\n" "$color" "$decision" "$RESET" "$cmd"
done
