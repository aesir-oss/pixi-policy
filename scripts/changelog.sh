#!/usr/bin/env bash
# Add a release's section to CHANGELOG.md, below the header and above the newest section already there. The sections
# already in the file are never regenerated: those up to 0.1.0 were written in aesir-oss/pixi-ext-contrib, with links
# to that repository's commits.
#
#   scripts/changelog.sh v0.1.1
set -euo pipefail
tag="${1:?usage: changelog.sh vX.Y.Z}"
file="${2:-CHANGELOG.md}"
section="$(git cliff --unreleased --tag "$tag" | sed '/./,$!d')"
first=$(grep -n '^## ' "$file" | head -1 | cut -d: -f1)
{
  head -n "$((first - 1))" "$file"
  printf '%s\n\n' "$section"
  tail -n "+$first" "$file"
} > "$file.new"
mv "$file.new" "$file"
