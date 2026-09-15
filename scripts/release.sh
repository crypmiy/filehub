#!/usr/bin/env bash
# Naikkan versi, commit, dan buat tag.
#   ./scripts/release.sh 1.1.0
set -euo pipefail

[ $# -eq 1 ] || { echo "pakai: $0 <versi>  (mis. 1.1.0)"; exit 1; }
new="$1"
[[ "$new" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "versi harus X.Y.Z"; exit 1; }

cd "$(dirname "$0")/.."
git diff --quiet || { echo "ada perubahan belum di-commit; bereskan dulu"; exit 1; }

old=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' filehub.py)
echo "$old -> $new"

sed -i "s/^__version__ = \".*\"/__version__ = \"$new\"/" filehub.py
today=$(date +%F)
sed -i "s/^## \[Unreleased\]/## [Unreleased]\n\n## [$new] - $today/" CHANGELOG.md

git add filehub.py CHANGELOG.md
git commit -m "rilis v$new"
git tag -a "v$new" -m "filehub v$new"

echo "selesai. dorong dengan: git push && git push --tags"
