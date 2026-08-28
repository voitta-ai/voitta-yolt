# Working in this repo

## Bump the plugin version on every merge that ships

The version lives in **two** manifests that must always carry the same
string: `.claude-plugin/plugin.json#version` and
`.codex-plugin/plugin.json#version`. Claude Code caches an extracted copy of
the plugin under `~/.claude/plugins/cache/<marketplace>/<plugin>/<version>/`,
Codex does the same against its own manifest, and both paths are keyed by the
version string — so `claude plugin update` compares installed version against
available version and stops there. **If the version did not change, it reports
"up to date" and re-extracts nothing — the user keeps running the old code no
matter how many commits landed on master.**

Bumping only one manifest fails the PR gate. Bumping only `.claude-plugin`
and merging past the gate would leave every Codex install frozen on the
cached old version with nothing reported anywhere, which is how
`.codex-plugin` once drifted to `0.1.0` while `.claude-plugin` was at
`1.0.3`.

This is not theoretical: the version sat at `0.1.0` from the initial ship
until issue #78, and every behavior change in between was invisible to
installed copies, including the maintainer's own.

So: **any merge to master that changes a file users receive must bump the
version.** The bump rides in the PR, not in a follow-up commit (see
"Tagging" below).

Changes that do *not* need their own bump: `tests/`, `.github/`, `docs/`,
`scripts/`, `.gitignore`, `HANDOFF.md`, and `CLAUDE.md`. Fold those into whatever the next real bump
is.

The test is **execution, not delivery.** A plugin install extracts the
whole repo, so users receive `tests/` and `.github/` too — the exemption
holds because nothing the plugin runs references them. `docs/` qualifies
on the same grounds. The corollary is the author's problem, not the
policy's: put something the plugin executes inside an exempt directory and
it ships unbumped and unnoticed.

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

### Tagging and release notes are automatic

Do not tag by hand. `.github/workflows/release.yml` owns both halves:

1. On a PR into master, the `version-bumped` job fails the PR unless
   `.claude-plugin/plugin.json#version` advances past master's *and*
   `.codex-plugin/plugin.json#version` matches it exactly. That is the
   enforcement behind "every shipping merge bumps" above. The exemption
   above is a `paths-ignore` on the workflow's `pull_request` trigger: a PR
   touching only `.github/`, `tests/`, `docs/`, `scripts/`, `.gitignore`,
   `HANDOFF.md` or `CLAUDE.md` skips the gate. Keep the two lists in sync.
2. On the resulting push to master, the `tag-and-release` job reads the
   version, and if `v<version>` is not already a tag, creates the tag and a
   GitHub release at master's squash commit with `--generate-notes`.

So the only manual step is editing the version field inside the PR.
Edit it by hand in **both** `.claude-plugin/plugin.json` and
`.codex-plugin/plugin.json`; the `version-bumped` job is what validates the
pair. The tag and release read `.claude-plugin` alone, which is why a
forgotten `.codex-plugin` is invisible after the merge and has to be caught
on the PR.

Two consequences worth knowing:

- **Release notes are the merged PR titles** since the previous tag. There
  is no CHANGELOG.md to keep in sync, which means a lazy PR title is a
  lazy release note. Write the title as the line you want users to read.
- Tagging on master's squash commit is why this is a workflow and not a
  local `git tag`: a tag made on a feature branch points at a commit that
  never lands on master.

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
