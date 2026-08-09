"""Policy layer: upgrade `unsafe` to `safe` for writes that are yours alone.

The rest of YOLT is a static checker — it answers "does this command
mutate anything?" from syntax alone. That question has no good answer for
`git commit`: committing to a shared branch someone else is building on is
a very different act from committing to a feature branch you opened five
minutes ago in your own worktree, and the argv is identical.

So this module answers a different question — "is this write confined to
work that is already mine?" — and it needs repository state to do it, which
means shelling out to `git`. That is a deliberate, scoped exception to the
no-subprocess design principle:

- It runs only when the static classifier already said `unsafe` AND the
  argv head matches a configured policy entry, so the common path never
  forks.
- It can only turn `unsafe` into `safe`. It never makes a safe command
  unsafe, and it never sees a command the classifier did not already flag.
- Every probe is read-only `git`, with a timeout, and any failure
  (no git, not a repo, timeout, weird output) resolves to "predicate not
  satisfied", i.e. the original `unsafe` stands.

Configuration lives under the `policies` key of `rules/shell.json` and is
overridable from `~/.claude/yolt/shell.json` like every other rule.
"""

import os
import subprocess

# Read-only probes, but a hung git (network filesystem, index.lock
# contention, a filter process) must not hang the permission prompt.
_GIT_TIMEOUT_SECONDS = 3

_DEFAULT_BRANCH_FALLBACKS = ("main", "master")

# Predicate names a policy entry may list in its `require` array.
PREDICATES = ("linked_worktree", "non_default_branch", "solo_author")


class GitProbe:
    """Read-only `git` queries about one directory, memoized per instance.

    One hook invocation classifies one Bash command, but that command may
    be `git add ... && git commit ... && git push`, which asks the same
    questions of the same directory three times. Memoizing keeps that at
    one round of probes.
    """

    def __init__(self, runner=None):
        # Injectable for tests; signature mirrors `_run_git`.
        self._runner = runner or _run_git
        self._cache = {}

    def state(self, directory):
        """Return a dict of facts about `directory`, or None if it is not
        usable as a git working tree."""
        if directory is None:
            return None
        key = os.path.abspath(directory)
        if key not in self._cache:
            self._cache[key] = self._probe(key)
        return self._cache[key]

    def _probe(self, directory):
        if not os.path.isdir(directory):
            return None

        out = self._runner(
            directory,
            ["rev-parse", "--git-dir", "--git-common-dir", "--abbrev-ref", "HEAD"],
        )
        if out is None:
            return None
        lines = out.splitlines()
        if len(lines) < 3:
            return None
        git_dir, git_common_dir, branch = lines[0], lines[1], lines[2]

        # In a linked worktree these differ: --git-dir points at
        # <main>/.git/worktrees/<name> while --git-common-dir points at
        # <main>/.git. In the primary checkout they are the same path.
        linked_worktree = os.path.abspath(
            os.path.join(directory, git_dir)
        ) != os.path.abspath(os.path.join(directory, git_common_dir))

        return {
            "directory": directory,
            "branch": branch,
            "detached": branch == "HEAD",
            "linked_worktree": linked_worktree,
            "default_branch": self._default_branch(directory),
            "user_email": self._config(directory, "user.email"),
        }

    def _default_branch(self, directory):
        # The remote's HEAD is the authoritative answer when the remote
        # has been fetched at least once.
        out = self._runner(
            directory, ["symbolic-ref", "--short", "refs/remotes/origin/HEAD"]
        )
        if out:
            head = out.strip()
            if head.startswith("origin/"):
                return head[len("origin/"):]

        # No remote HEAD (never fetched, or no remote). Fall back to
        # whichever candidate actually resolves in THIS repo.
        # `init.defaultBranch` is only a candidate, never an answer on its
        # own: it is a global preference for repos yet to be created, so a
        # user who sets it to `main` would otherwise make every existing
        # `master` repo look like it has no default branch.
        candidates = []
        configured = self._config(directory, "init.defaultBranch")
        if configured:
            candidates.append(configured)
        candidates.extend(
            c for c in _DEFAULT_BRANCH_FALLBACKS if c not in candidates
        )

        for candidate in candidates:
            for ref in ("refs/remotes/origin/" + candidate, "refs/heads/" + candidate):
                if self._runner(
                    directory, ["rev-parse", "--verify", "--quiet", ref]
                ) is not None:
                    return candidate
        return None

    def _config(self, directory, key):
        out = self._runner(directory, ["config", "--get", key])
        if not out:
            return None
        return out.strip() or None

    def solo_author(self, directory):
        """True when every commit on this branch that is not on the
        default branch was authored AND committed by the configured user.

        A branch with no commits of its own yet is vacuously solo — that
        is the state you are in the moment before the first `git commit`,
        which is exactly the case this policy exists to allow.
        """
        state = self.state(directory)
        if state is None:
            return (False, "not a git working tree")

        email = state.get("user_email")
        if not email:
            return (False, "git user.email is not configured")

        default_branch = state.get("default_branch")
        if not default_branch:
            return (False, "cannot determine the default branch")

        base = None
        for ref in ("origin/{}".format(default_branch), default_branch):
            if self._runner(
                directory, ["rev-parse", "--verify", "--quiet", ref]
            ) is not None:
                base = ref
                break
        if base is None:
            return (False, "no {} ref to compare against".format(default_branch))

        out = self._runner(
            directory, ["log", "--format=%ae%n%ce", "{}..HEAD".format(base)]
        )
        if out is None:
            return (False, "cannot read branch history")

        others = {
            line.strip() for line in out.splitlines()
            if line.strip() and line.strip() != email
        }
        if others:
            return (False, "branch has commits by {}".format(
                ", ".join(sorted(others))
            ))
        return (True, "every commit on this branch is {}".format(email))


class PolicySet:
    """Every configured policy, sharing one probe cache."""

    def __init__(self, policies):
        probe = GitProbe()
        self.policies = [
            GitPolicy(spec, probe=probe)
            for name, spec in sorted((policies or {}).items())
            if not name.startswith("_") and isinstance(spec, dict)
        ]

    def evaluate(self, argv, directory):
        for policy in self.policies:
            reason = policy.evaluate(argv, directory)
            if reason is not None:
                return reason
        return None


def load_policies(rules):
    """Build the policy set from loaded shell rules. Returns None when
    nothing is configured, so the classifier can skip the layer entirely."""
    policy_set = PolicySet(rules.get("policies", {}))
    if not any(p.enabled and p.entries for p in policy_set.policies):
        return None
    return policy_set


def _run_git(directory, args):
    """Run a read-only git command. Returns stdout, or None on any
    failure — a failed probe must never read as a satisfied predicate."""
    try:
        proc = subprocess.run(
            ["git", "-C", directory, "--no-pager"] + args,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=_GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.decode("utf-8", "replace")


class GitPolicy:
    """Evaluates configured policy entries against an argv + directory."""

    def __init__(self, spec, probe=None):
        spec = spec or {}
        self.enabled = bool(spec.get("enabled", False))
        if os.environ.get("YOLT_NO_POLICIES"):
            self.enabled = False
        self.entries = [e for e in spec.get("allow", []) if isinstance(e, dict)]
        self.probe = probe or GitProbe()

    def evaluate(self, argv, directory):
        """Return (reason_string) when this argv in this directory is
        allowed by policy, else None. Callers only invoke this for argv
        the static rules already classified `unsafe`."""
        if not self.enabled or not argv:
            return None

        # `git -C <path>` retargets the command; the policy must judge the
        # directory git will actually act on, not the shell's cwd. Split it
        # off first so it cannot be mistaken for a subcommand or a refspec.
        argv, c_target = _split_dash_c(argv)

        entry = self._match(argv)
        if entry is None:
            return None

        for flag in entry.get("deny_flags", []):
            if flag in argv:
                return None

        directory = _resolve_directory(c_target, directory)
        if directory is None:
            return None

        label = " ".join(entry.get("argv", []))
        requirements = entry.get("require", [])

        if not requirements:
            return "{}: allowed by policy".format(label)

        state = self.probe.state(directory)
        if state is None:
            return None
        if state.get("detached"):
            return None

        if "linked_worktree" in requirements and not state["linked_worktree"]:
            return None
        if "non_default_branch" in requirements:
            default_branch = state.get("default_branch")
            if not default_branch or state["branch"] == default_branch:
                return None
        if entry.get("deny_default_branch_refspec") and _pushes_elsewhere(
            argv, state["branch"]
        ):
            return None
        if "solo_author" in requirements:
            ok, _detail = self.probe.solo_author(directory)
            if not ok:
                return None

        return "{}: {} on {}, authored only by you".format(
            label,
            "linked worktree" if state["linked_worktree"] else "working tree",
            state["branch"],
        )

    def _match(self, argv):
        best = None
        for entry in self.entries:
            prefix = entry.get("argv", [])
            if not prefix:
                continue
            if _argv_starts_with(argv, prefix):
                if best is None or len(prefix) > len(best.get("argv", [])):
                    best = entry
        return best


def _argv_starts_with(argv, prefix):
    """Match a policy prefix against argv, skipping flags so that
    `git --no-pager commit` still matches `["git", "commit"]`. argv[0] is
    compared by basename so `/usr/bin/git` matches."""
    if not argv or not prefix:
        return False
    if os.path.basename(argv[0]) != prefix[0]:
        return False

    remaining = list(prefix[1:])
    for tok in argv[1:]:
        if not remaining:
            break
        if tok.startswith("-"):
            continue
        if tok != remaining[0]:
            return False
        remaining.pop(0)
    return not remaining


def _split_dash_c(argv):
    """Return (argv without any `-C <path>` pair, the last such path).

    Leaving `-C` in place would break both the prefix match (`/path` reads
    as the subcommand) and the refspec check (`/path` reads as the remote).
    """
    if not argv or os.path.basename(argv[0]) != "git":
        return (argv, None)
    out = [argv[0]]
    target = None
    i = 1
    while i < len(argv):
        tok = argv[i]
        if tok == "-C" and i + 1 < len(argv):
            target = argv[i + 1]
            i += 2
            continue
        if tok.startswith("-C") and len(tok) > 2:
            target = tok[2:]
            i += 1
            continue
        out.append(tok)
        i += 1
    return (out, target)


def _resolve_directory(c_target, directory):
    """Resolve a `git -C` target against the shell's directory."""
    if c_target is None:
        return directory
    if _has_expansion(c_target):
        return None
    target = os.path.expanduser(c_target)
    if os.path.isabs(target):
        return target
    if directory is None:
        return None
    return os.path.join(directory, target)


def _has_expansion(token):
    return "$" in token or "`" in token or "*" in token


def _pushes_elsewhere(argv, branch):
    """True when a `git push` names a ref other than the current branch.

    `git push` and `git push origin <current-branch>` stay inside the
    policy; `git push origin master` or any `src:dst` refspec is a push at
    something the predicates never examined, so it falls back to `ask`.
    """
    positionals = [
        tok for tok in argv[1:]
        if not tok.startswith("-") and tok != "push"
    ]
    # positionals[0] is the remote; anything after it is a refspec.
    for refspec in positionals[1:]:
        if ":" in refspec:
            return True
        if refspec != branch:
            return True
    return False
