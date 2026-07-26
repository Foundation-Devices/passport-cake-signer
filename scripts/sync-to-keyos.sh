#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
keyos_root="${1:-${KEYOS_CAKE_SIGNER_ROOT:-../KeyOS-cake-signer}}"
app_root="$keyos_root/apps/gui-app-cake-signer"

if [[ ! -e "$keyos_root/.git" ]]; then
  echo "KeyOS worktree not found: $keyos_root" >&2
  echo "Pass the KeyOS worktree path as argv[1] or set KEYOS_CAKE_SIGNER_ROOT." >&2
  exit 2
fi

mkdir -p "$app_root"

rsync -a --delete \
  --exclude ".git/" \
  --exclude ".DS_Store" \
  --exclude "Cargo.lock" \
  --exclude "target/" \
  --exclude "scripts/" \
  "$repo_root/" "$app_root/"

echo "Synced passport-cake-signer -> $app_root"
