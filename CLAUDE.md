# Working in this repo

## Bump the plugin version on every merge that ships

`.claude-plugin/plugin.json#version` is the single source of truth for the
plugin version, and Claude Code caches an extracted copy of the plugin under
`~/.claude/plugins/cache/<marketplace>/<plugin>/<version>/`. That path is
keyed by the version string, so `claude plugin update` compares installed
version against available version and stops there. **If the version did not
change, it reports "up to date" and re-extracts nothing — the user keeps
running the old code no matter how many commits landed on master.**

This is not theoretical: the version sat at `0.1.0` from the initial ship
until issue #78, and every behavior change in between was invisible to
installed copies, including the maintainer's own.

So: **any merge to master that changes a file users receive must bump the
version.** The bump rides in the PR, not in a follow-up commit (see
"Tagging" below).

Changes that do *not* need their own bump, because users never execute
them: `tests/`, `.github/`, `HANDOFF.md`, and other maintainer-only files.
Fold those into whatever the next real bump is.

### Which part to bump

The plugin is pre-1.0, so the compatibility contract being versioned is
"what does YOLT decide, and how do I configure it" — not a code API.

- **PATCH** (`0.2.0` → `0.2.1`) — nothing a user could observe at a
  permission prompt. Refactors, docstrings, README edits, log-field
  additions, reason-string wording. Still required: shipped is shipped.
- **MINOR** (`0.2.0` → `0.3.0`) — user-visible behavior. A rule that flips
  a command's classification, new commands or subcommands in
  `rules/shell.json`, a new default in the Python analyzer, a change to the
  hook's decision mapping (e.g. #77's ask → deny inside subagents), a new
  config key or environment variable, a new slash command.
- **MAJOR** (`0.x` → `1.0.0`) — reserved for two things: declaring the
  rules-file format stable, and any later break of it. Renaming or removing
  a documented key in `rules/rules.json` / `rules/shell.json` /
  `~/.claude/yolt/*.json`, or dropping a documented env var, is a major
  bump once 1.0 exists. Before then, call it minor and say so in the PR.

When a single PR mixes levels, take the highest one.

### Tagging, and why `scripts/release.sh` only half-fits

`scripts/release.sh <version>` rewrites `plugin.json`, commits
`Release v<version>`, and tags. The commit-and-tag half does not fit this
repo: master takes squash merges, so a tag created on a feature branch
points at a commit that never lands on master.

Sequence that works:

1. Edit `.claude-plugin/plugin.json#version` as part of the PR's own
   changes. (`scripts/release.sh` is still handy for the rewrite+validation
   — it refuses a non-semver or non-advancing version — but drop its commit
   and tag, or just edit the field by hand.)
2. Merge the PR (squash).
3. Tag master's squash commit and push:

   ```
   git tag -a v0.3.0 -m "Release v0.3.0" <squash-sha>
   git push origin v0.3.0
   ```

Tagging creates no commit, so this respects the "no direct commits to
master" rule.

### Verifying an install actually updated

`claude plugin update` printing "up to date" is not evidence. Check the
cache copy, which is what the hook actually runs:

```
ls ~/.claude/plugins/cache/voitta-yolt/yolt/
grep -c "<a symbol from the new code>" \
  ~/.claude/plugins/cache/voitta-yolt/yolt/<version>/hooks/yolt_analyzer.py
```

The directory under `.../yolt/` should be named for the new version. The
clone under `~/.claude/plugins/marketplaces/voitta-yolt/` updating is *not*
sufficient — that is the fetched source, not the extracted install.
