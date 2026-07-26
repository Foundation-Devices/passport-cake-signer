#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
keyos_root="${1:-${KEYOS_CAKE_SIGNER_ROOT:-../KeyOS-cake-signer}}"

"$script_dir/sync-to-keyos.sh" "$keyos_root"

cd "$keyos_root"

cargo check -p gui-app-cake-signer
cargo test -p gui-app-cake-signer
cargo clippy -p gui-app-cake-signer --bin gui-app-cake-signer --no-deps -- -D warnings
cargo xtask check gui-app-cake-signer
cargo xtask build --hosted --dont-sign --app gui-app-cake-signer

echo "KeyOS Cake signer checks passed from $repo_root"
