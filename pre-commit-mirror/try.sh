#!/usr/bin/env bash
# Try the hook as a user would, against the pixi-policy wheel VERSION on PyPI: render the mirror into a git repository
# under DIR, then commit to a workspace that uses it. A commit of Django 4.2 passes; swapping in Django 3.2, which the
# policy bans, is stopped. Needs git, pre-commit and the network; CI runs it (#5). Never touches this repository.
set -euo pipefail
version="${1:?usage: try.sh VERSION DIR}"
dir="${2:?usage: try.sh VERSION DIR}"
here="$(cd "$(dirname "$0")" && pwd)"
examples="$here/../examples/projects/pixi"
git=(git -c user.name=try -c user.email=try@example.invalid -c commit.gpgsign=false -c tag.gpgsign=false)

mkdir -p "$dir"
mirror="$(cd "$dir" && pwd)/mirror"
workspace="$(cd "$dir" && pwd)/workspace"
rm -rf "$mirror" "$workspace"

"$here/render.sh" "$version" "$mirror"
"${git[@]}" -C "$mirror" init -q
"${git[@]}" -C "$mirror" add -A
"${git[@]}" -C "$mirror" commit -qm "pixi-policy v${version}"
"${git[@]}" -C "$mirror" tag "v${version}"

cp -R "$examples/14-django-upgraded" "$workspace"
"${git[@]}" -C "$workspace" init -q
printf '[bans]\ndeny = [{ name = "django", version = "<4", reason = "end of life" }]\n' > "$workspace/pixi-policy.toml"
printf 'repos:\n  - repo: %s\n    rev: v%s\n    hooks:\n      - id: pixi-policy\n' "$mirror" "$version" \
  > "$workspace/.pre-commit-config.yaml"
(cd "$workspace" && pre-commit install)

"${git[@]}" -C "$workspace" add -A
"${git[@]}" -C "$workspace" commit -qm "Django 4.2"
echo "The commit of Django 4.2 passed."

cp "$examples/01-django/pixi.toml" "$examples/01-django/pixi.lock" "$workspace/"
"${git[@]}" -C "$workspace" add -A
if "${git[@]}" -C "$workspace" commit -qm "Django 3.2"; then
  echo "error: the hook let a banned Django 3.2 through" >&2
  exit 1
fi
[ "$("${git[@]}" -C "$workspace" rev-list --count HEAD)" = 1 ]
echo "The commit of Django 3.2 was stopped."
