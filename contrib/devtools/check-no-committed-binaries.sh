#!/usr/bin/env bash
# Reject tracked release/build artifacts (archives, disk images, oversized
# blobs) so precompiled binaries never re-enter the repo. Release binaries
# belong in GitHub Releases, not git. Wire into CI and .git/hooks/pre-commit.
set -euo pipefail
MAX_BYTES=$((5 * 1024 * 1024))   # 5 MiB cap for any tracked file
bad=0
while IFS= read -r f; do
  case "$f" in
    *.tar.gz|*.tgz|*.tar|*.tar.xz|*.zip|*.dmg|*.7z|*.exe)
      echo "FORBIDDEN artifact tracked: $f"; bad=1;;
  esac
  s=$(git cat-file -s ":$f" 2>/dev/null || echo 0)
  if [ "$s" -gt "$MAX_BYTES" ]; then
    echo "OVERSIZED tracked file ($((s / 1024 / 1024)) MiB > 5 MiB): $f"; bad=1
  fi
done < <(git ls-files)
if [ "$bad" -ne 0 ]; then
  echo "FAIL: remove build artifacts and ship binaries via GitHub Releases." >&2
  exit 1
fi
echo "OK: no forbidden or oversized tracked files."
