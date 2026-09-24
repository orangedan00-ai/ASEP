#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
VERSION="$(cat VERSION)"
EXPECTED="ASEP-v${VERSION}"
[[ "$(basename "$ROOT")" == "$EXPECTED" ]] || { echo "ERROR: package root/version mismatch"; exit 1; }
[[ -f VERSION && -f release.json && -f CHANGELOG.md ]] || { echo "ERROR: release metadata missing"; exit 1; }
if find . -type d -name '__pycache__' -o -name '*.pyc' | grep -q .; then
  echo "NOTE: runtime caches exist in working tree; release archive must exclude them."
fi
printf 'Release check: PASS (%s)\n' "$VERSION"
