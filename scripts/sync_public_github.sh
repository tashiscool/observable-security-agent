#!/usr/bin/env bash
# Sync this package (tracked files only at COMMIT) to github.com/tashiscool/observable-security-agent,
# stripping mistaken tracked paths under web/ and generated verify output.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="$(cd "$ROOT/.." && pwd)"
COMMIT="${1:-HEAD}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/osa_pub_sync.XXXXXX")"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

echo "Exporting observable-security-agent from $REPO @ $COMMIT ..."
# Exclude bulk mistaken paths during extract (web/Applications alone can be gigabytes).
git -C "$REPO" archive "$COMMIT" observable-security-agent | tar -x -C "$TMP" -f - \
  --exclude='observable-security-agent/web/Applications' \
  --exclude='observable-security-agent/web/Library' \
  --exclude='observable-security-agent/web/System' \
  --exclude='observable-security-agent/web/FedRAMP20xMCP' \
  --exclude='observable-security-agent/web/.tracker_artifacts' \
  --exclude='observable-security-agent/output/verify_features' \
  --exclude='observable-security-agent/output/verify_demo_run'

EXP="$TMP/observable-security-agent"
# Defensive cleanup if tar omitted an exclude.
rm -rf \
  "$EXP/web/Applications" \
  "$EXP/web/Library" \
  "$EXP/web/System" \
  "$EXP/web/FedRAMP20xMCP" \
  "$EXP/web/.tracker_artifacts" \
  "$EXP/output/verify_features" \
  "$EXP/output/verify_demo_run"

# Keep only Evidence Explorer assets under web/ (plus sample-data)
WEB_ALLOW='^(index\.html|app\.js|fedramp20x\.js|tracker\.js|styles\.css|sample-data|README\.md)$'
find "$EXP/web" -mindepth 1 -maxdepth 1 | while read -r p; do
  bn="$(basename "$p")"
  if [[ ! "$bn" =~ $WEB_ALLOW ]]; then
    rm -rf "$p"
  fi
done

CLONE="$TMP/gh"
git clone https://github.com/tashiscool/observable-security-agent.git "$CLONE"
rsync -a --delete \
  --exclude='.git' \
  "$EXP/" "$CLONE/"

cd "$CLONE"
git add -A
if git diff --staged --quiet; then
  echo "No changes to push."
  exit 0
fi
git commit -m "Sync from security-infra @ ${COMMIT}

Strip web/ filesystem junk and verify_* run output from public tree."
git push origin main
echo "Pushed to https://github.com/tashiscool/observable-security-agent"
