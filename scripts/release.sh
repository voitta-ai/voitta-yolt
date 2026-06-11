#!/usr/bin/env bash
#
# Cut a yolt plugin release: bump the version, commit, and tag.
#
# Usage: scripts/release.sh <new-version>      # e.g. scripts/release.sh 0.2.0
#
# Updates the "version" field in .claude-plugin/plugin.json -- the single
# source of truth the marketplace reads -- then commits "Release v<version>"
# and creates an annotated tag v<version>.
#
# The marketplace pins on this version string: pushing commits WITHOUT a
# bump leaves existing users on the cached copy. That is the whole reason
# this script exists.
#
# It does NOT push. Review the commit and tag, then run the printed
# `git push` command to publish.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
manifest="$repo_root/.claude-plugin/plugin.json"

new_version="${1:-}"
if [[ -z "$new_version" ]]; then
    echo "usage: scripts/release.sh <new-version>   (e.g. 0.2.0)" >&2
    exit 2
fi

# Validate the new version, ensure it advances past the current one, and
# rewrite only the plugin.json version field. python3 is already a project
# dependency, so use it for a robust JSON edit instead of sed-on-JSON.
python3 - "$manifest" "$new_version" <<'PY'
import json
import re
import sys

manifest_path, new_version = sys.argv[1], sys.argv[2]

if not re.fullmatch(r"\d+\.\d+\.\d+", new_version):
    sys.exit(f"error: version must be semver X.Y.Z, got {new_version!r}")

with open(manifest_path) as fh:
    data = json.load(fh)

current = data.get("version", "0.0.0")


def as_tuple(version):
    retval = tuple(int(part) for part in version.split("."))
    return retval


if as_tuple(new_version) <= as_tuple(current):
    sys.exit(
        f"error: new version {new_version} must be greater than current {current}"
    )

data["version"] = new_version
with open(manifest_path, "w") as fh:
    json.dump(data, fh, indent=2)
    fh.write("\n")

print(f"plugin.json: {current} -> {new_version}")
PY

cd "$repo_root"
# Commit only the manifest, regardless of anything else already staged.
git commit -m "Release v${new_version}" -- .claude-plugin/plugin.json
git tag -a "v${new_version}" -m "Release v${new_version}"

echo
echo "Tagged v${new_version}. Review, then publish with:"
echo "    git push origin master --follow-tags"
