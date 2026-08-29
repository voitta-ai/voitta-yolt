"""Policy layer: upgrade `unsafe` to `deny` for git writes we refuse outright.

The rest of YOLT is a static checker -- it answers "does this command mutate
anything?" from syntax alone. That question has no good answer for `git push`:
pushing a feature branch you opened five minutes ago and force-pushing over
someone else's commits on the default branch are different acts, and the argv
can be byte-identical. Measured on a 12-day corpus, 24 of 76 observed pushes
carried no refspec at all -- including `git push -f` -- so they push whatever
happens to be checked out, which argv cannot know.

So this module answers a different question -- "is this write one we refuse to
delegate to a probabilistic classifier?" -- and it needs repository state to do
it, which means shelling out to `git`. That is a deliberate, scoped exception
to the no-subprocess design principle:

- It runs only when the static classifier already said `unsafe` AND the argv
  head matches a configured policy entry, so the common path never forks.
- It can only turn `unsafe` into `deny`. It never makes a safe command unsafe,
  and it never sees a command the classifier did not already flag.
- Every probe is read-only `git`, with a timeout.

INVERTED FAILURE SEMANTICS -- the one thing that could not be ported

Its ancestor (#82) used these same probes to *grant* approval, where every
probe failure meant "predicate not satisfied", the grant did not happen, and
the original `ask` stood. Failure degraded toward more friction, which is
safe, so that code was free to collapse "definitely not" and "cannot tell"
into a single False.

Denying inverts that. Collapsed the same way, an unset `git config user.email`
or an unfetched `origin/master` reads as "not solo" and would **deny every
force push in the repository**. A git outage or a slow network filesystem
would brick the session. That is the failure mode #97 names, and porting the
predicate verbatim would have shipped it.

So authorship is tri-state here -- SOLO / SHARED / UNDETERMINED -- and every
probe failure resolves to UNDETERMINED, which produces no opinion. The
invariant, asserted by the tests: **no probe failure can ever produce a deny.**
"""

import os
import subprocess

# Read-only probes, but a hung git (network filesystem, index.lock
# contention, a filter process) must not hang the permission prompt.
_GIT_TIMEOUT_SECONDS = 3

_DEFAULT_BRANCH_FALLBACKS = ("main", "master")

# Authorship states. UNDETERMINED is not a failure to be retried or a
# pessimistic default -- it is a first-class answer meaning "no opinion", and
# it is what every probe failure resolves to.
SOLO = "solo"
SHARED = "shared"
UNDETERMINED = "undetermined"

# Predicate names a policy entry may list in its `refuse_when` array. Each is
# a condition under which the command is DENIED. A predicate that cannot be
# evaluated never fires.
PREDICATES = ("default_branch_target", "shared_history", "primary_checkout")


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

    def authorship(self, directory):
        """SOLO / SHARED / UNDETERMINED for the commits on this branch.

        Returns a (state, detail) pair. SOLO means every commit on this
        branch that is not on the default branch was authored AND committed
        by the configured user. SHARED means at least one was not.
        UNDETERMINED means the question could not be answered, and is
        returned for every probe failure -- no git, no user.email, no
        comparable ref, unreadable history.

        The distinction between SHARED and UNDETERMINED does not exist in
        the ancestor of this module, and adding it is the whole point of the
        port: see the failure-semantics note in the module docstring.

        A branch with no commits of its own yet is vacuously solo — that
        is the state you are in the moment before the first `git commit`,
        which is exactly the case this policy exists to allow.
        """
        state = self.state(directory)
        if state is None:
            return (UNDETERMINED, "not a git working tree")

        email = state.get("user_email")
        if not email:
            return (UNDETERMINED, "git user.email is not configured")

        default_branch = state.get("default_branch")
        if not default_branch:
            return (UNDETERMINED, "cannot determine the default branch")

        base = None
        for ref in ("origin/{}".format(default_branch), default_branch):
            if self._runner(
                directory, ["rev-parse", "--verify", "--quiet", ref]
            ) is not None:
                base = ref
                break
        if base is None:
            return (UNDETERMINED,
                    "no {} ref to compare against".format(default_branch))

        out = self._runner(
            directory, ["log", "--format=%ae%n%ce", "{}..HEAD".format(base)]
        )
        if out is None:
            return (UNDETERMINED, "cannot read branch history")

        others = {
            line.strip() for line in out.splitlines()
            if line.strip() and line.strip() != email
        }
        if others:
            return (SHARED, "branch has commits by {}".format(
                ", ".join(sorted(others))
            ))
        return (SOLO, "every commit on this branch is {}".format(email))


class DenyPolicySet:
    """Every configured deny policy, sharing one probe cache."""

    def __init__(self, policies):
        probe = GitProbe()
        self.policies = [
            GitDenyPolicy(spec, probe=probe)
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
    """Build the deny policy set from loaded shell rules. Returns None when
    nothing is configured, so the classifier can skip the layer entirely."""
    policy_set = DenyPolicySet(rules.get("policies", {}))
    if not any(p.enabled and p.entries for p in policy_set.policies):
        return None
    return policy_set


def _run_git(directory, args):
    """Run a read-only git command. Returns stdout, or None on any failure.

    A failed probe must never read as evidence. On the deny side that means
    None propagates to UNDETERMINED and the command is not denied.
    """
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


class GitDenyPolicy:
    """Evaluates configured deny entries against an argv + directory."""

    def __init__(self, spec, probe=None):
        spec = spec or {}
        self.enabled = bool(spec.get("enabled", False))
        if os.environ.get("YOLT_NO_POLICIES"):
            self.enabled = False
        self.entries = [e for e in spec.get("deny", []) if isinstance(e, dict)]
        self.probe = probe or GitProbe()

    def evaluate(self, argv, directory):
        """Return a reason string when this argv must be DENIED, else None.

        None is "no opinion", and it is the answer for every uncertainty:
        policy disabled, argv unmatched, directory unresolvable, probe
        failed, predicate undetermined. Callers only invoke this for argv
        the static rules already classified `unsafe`, so a None here leaves
        that `unsafe` standing -- the operator still gets asked.
        """
        if not self.enabled or not argv:
            return None

        # `git -C <path>` retargets the command; the policy must judge the
        # directory git will actually act on, not the shell's cwd.
        argv, c_target = _split_dash_c(argv)

        # Every matching entry is evaluated, not just the most specific
        # one. Two entries legitimately share the `git push` prefix -- one
        # refusing pushes at the default branch, one refusing force-pushes
        # over shared history -- and picking a single winner would silently
        # disable whichever lost.
        entries = self._match_all(argv)
        if not entries:
            return None

        directory = _resolve_directory(c_target, directory)
        if directory is None:
            return None

        state = self.probe.state(directory)
        if state is None:
            return None
        # Detached HEAD has no branch to reason about. Not an error, but
        # nothing here can be established, so no opinion.
        if state.get("detached"):
            return None

        for entry in entries:
            # An entry may scope itself to particular flags, so that
            # `git push --force` is refused while a plain push is not.
            only_flags = entry.get("only_flags")
            if only_flags and not any(flag in argv for flag in only_flags):
                continue
            label = " ".join(entry.get("argv", []))
            for predicate in entry.get("refuse_when", []):
                reason = self._fires(predicate, argv, state, directory)
                if reason is not None:
                    return "{}: {}".format(label, reason)
        return None

    def _fires(self, predicate, argv, state, directory):
        """Return a reason when `predicate` is affirmatively true, else None.

        Every branch that cannot establish the fact returns None rather than
        guessing. That is the fail-open invariant in one place.
        """
        if predicate == "default_branch_target":
            default_branch = state.get("default_branch")
            if not default_branch:
                return None
            target = _push_target(argv, state.get("branch"))
            if target is None:
                return None
            if target == default_branch:
                return "would push to the default branch ({})".format(
                    default_branch
                )
            return None

        if predicate == "shared_history":
            verdict, detail = self.probe.authorship(directory)
            if verdict == SHARED:
                return detail
            return None

        if predicate == "primary_checkout":
            if state.get("linked_worktree") is False:
                return "runs in the primary checkout, not a linked worktree"
            return None

        # An unknown predicate name is a configuration error, not a licence
        # to deny. Schema validation rejects these at load; this is the
        # belt-and-braces for a rules file that bypassed it.
        return None

    def _match_all(self, argv):
        """Every entry whose argv prefix matches, most specific first."""
        matched = [
            entry for entry in self.entries
            if entry.get("argv") and _argv_starts_with(argv, entry["argv"])
        ]
        matched.sort(key=lambda e: -len(e.get("argv", [])))
        retval = matched
        return retval


def _push_target(argv, current_branch):
    """The branch a `git push` would land on, or None if argv cannot say.

    With no refspec, git pushes the current branch -- so the answer comes
    from repository state, not from the command. With an explicit refspec,
    the destination is its right-hand side. Anything this cannot resolve
    (a variable, a glob, a tag ref) returns None and therefore never denies.
    """
    positionals = [
        tok for tok in argv[1:]
        if not tok.startswith("-") and tok != "push"
    ]
    refspecs = positionals[1:]
    if not refspecs:
        return current_branch
    retval = None
    for refspec in refspecs:
        if _has_expansion(refspec):
            return None
        candidate = refspec.split(":")[-1] if ":" in refspec else refspec
        candidate = candidate.replace("refs/heads/", "")
        if candidate.startswith("refs/"):
            return None
        retval = candidate
    return retval


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
