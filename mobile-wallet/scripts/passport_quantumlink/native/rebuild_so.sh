#!/usr/bin/env bash
set -euo pipefail

module_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
default_sdk="/opt/homebrew/share/android-commandlinetools"
android_sdk="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$default_sdk}}"
ndk_version="${PASSPORT_WDK_NDK_VERSION:-27.1.12297006}"
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$android_sdk/ndk/$ndk_version}"

if [[ ! -d "$ANDROID_NDK_HOME" ]]; then
  echo "Android NDK not found at $ANDROID_NDK_HOME" >&2
  echo "Set ANDROID_NDK_HOME or ANDROID_SDK_ROOT and retry." >&2
  exit 1
fi

cd "$module_dir"

plugin_dir="$(cd "$module_dir/.." && pwd)"
native_output="$plugin_dir/android/src/main/jniLibs"
binding_output="$module_dir/bindings/uniffi"
android_binding_output="$plugin_dir/android/src/main/java"
library="$native_output/arm64-v8a/libquantumlink_mobile.so"
binding="$binding_output/uniffi/quantumlink_mobile/quantumlink_mobile.kt"

echo "Building QuantumLink Rust core for Android arm64"
cargo ndk -t arm64-v8a -o "$native_output" build --release

echo "Generating Android-aware UniFFI Kotlin bindings"
rm -rf "$binding_output"
cargo run --bin uniffi-bindgen -- generate \
  --library "$library" \
  --language kotlin \
  --config "$module_dir/uniffi.toml" \
  --out-dir "$binding_output"

mkdir -p "$android_binding_output/uniffi/quantumlink_mobile"
cp "$binding" "$android_binding_output/uniffi/quantumlink_mobile/quantumlink_mobile.kt"

echo "Verifying WDK exports"
grep -q "buildWdkMoneroWatchCredentialsRequest" "$binding"
grep -q "buildWdkMoneroKeyImageSyncRequest" "$binding"
grep -q "buildWdkMoneroSignTransactionRequest" "$binding"
grep -q "buildWdkMoneroWalletRemovalResponse" "$binding"
grep -q "buildWdkRequestCancelled" "$binding"
grep -q "buildUnpairingRequest" "$binding"
grep -q "buildUnpairingResponse" "$binding"

echo "QuantumLink Android artifacts are ready"
