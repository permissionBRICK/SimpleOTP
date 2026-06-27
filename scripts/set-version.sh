#!/usr/bin/env bash
#
# Set the MAJOR.MINOR release line in version.json.
#
# The PATCH number is NOT stored here — CI computes it automatically on each push to master by
# counting existing v<major>.<minor>.* tags, so bumping major or minor here makes the next release
# restart at patch 0 (e.g. editing 1.4 -> 2.0 makes the next release v2.0.0).
#
# Usage:
#   scripts/set-version.sh 1.2          # set major=1 minor=2
#   scripts/set-version.sh 1.2 --commit # also git-commit version.json
#
set -euo pipefail

cd "$(dirname "$0")/.."

if [ $# -lt 1 ]; then
    echo "usage: $0 <major>.<minor> [--commit]" >&2
    exit 2
fi

VER="$1"
if ! [[ "$VER" =~ ^([0-9]+)\.([0-9]+)$ ]]; then
    echo "error: version must be MAJOR.MINOR (e.g. 1.2), got '$VER'" >&2
    exit 2
fi
MAJOR="${BASH_REMATCH[1]}"
MINOR="${BASH_REMATCH[2]}"

printf '{\n  "major": %s,\n  "minor": %s\n}\n' "$MAJOR" "$MINOR" > version.json
echo "version.json set to ${MAJOR}.${MINOR} (next release: v${MAJOR}.${MINOR}.0)"

if [ "${2:-}" = "--commit" ]; then
    git add version.json
    git commit -m "Set version line to ${MAJOR}.${MINOR}"
    echo "Committed. Push to master to cut v${MAJOR}.${MINOR}.0."
else
    echo "Review, commit, and push version.json to master to cut v${MAJOR}.${MINOR}.0."
fi
