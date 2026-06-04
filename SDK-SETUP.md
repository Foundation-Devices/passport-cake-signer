# Cake Wallet Signer — SDK setup & build

This app follows the **same SDK structure proven by the Liana signer**: a
`manifest.toml`, `slint-keyos-platform` path deps, `src/main.rs` + `ui/pages/*` +
`build.rs` + `i18n/en.json`, the `app!()` macro, and the `@ui` widget library. It
is an SDK-conformant KeyOS app and builds **inside a KeyOS workspace**, not
standalone.

## Build it in the simulator (no Nix, works today)

1. **Drop it into the workspace** — copy this folder into `KeyOS/apps/`:
   ```bash
   cp -r passport-cake-signer KeyOS/apps/gui-app-cake-signer
   ```
   (The crate is already named `gui-app-cake-signer` and its path deps assume the
   `apps/<name>/` location, matching the Liana signer.)

2. **Register it** in the workspace members + the dev launcher's Secret Menu,
   exactly as `gui-app-liana-signer` is registered:
   - add to `KeyOS/Cargo.toml` workspace `members`
   - add to `os/gui-app-launcher/src/main.rs`

3. **Add the Monero crates to the workspace.** `monero-wallet` and `monero-clsag`
   are new to this workspace — pin exact versions and confirm they build for
   **both** the simulator and `armv7a-unknown-xous-elf`. Build with
   `default-features = false` (no_std) for the device target. This is the first
   thing to verify, before any feature work:
   ```bash
   cargo xtask check gui-app-cake-signer   # must pass ARM (xous) + sim
   ```

4. **Run the simulator** from `KeyOS/`:
   ```bash
   cargo xtask run --hosted        # opens the Passport window; app is in the Secret Menu
   ```

## On-device build + flash (needs Nix)

Same as the Liana signer: the full flashable image pulls the whole OS (incl.
`rfal-sys`, which needs the Nix-provided headers). Inside `nix develop` on the
KeyOS flake:
```bash
cargo xtask build && cargo xtask flash   # signed image + SAM-BA flash over USB
```
See the project memory notes for the no-Nix device build chain
(`rfal-sys` bindings restore, `AR_armv7a_unknown_xous_elf`, SAM-BA first-try
retry, 16-byte appId).

## appId

`manifest.toml` sets `appId = "0x63616b652d786d722d7369676e657221"` — ASCII
`cake-xmr-signer!`, exactly 16 bytes. Keep it exactly 16 bytes (0x + 32 hex) or
the system panics on boot.

## Status

| Piece | State |
|-------|-------|
| App shell, manifest, permissions | ✅ scaffolded |
| Cake branding / theme | ✅ wired (`ui/cake-theme.slint`) |
| Home / review / signed pages | ✅ scaffolded |
| microSD/USB file transport | ✅ ported from Liana (close-before-flush) |
| Spend/view key derivation | ⚠️ structure in place; Keccak + address TODO |
| wallet2 txset codec | ❌ stub (interop boundary — decide path first) |
| key-image export + CLSAG signing | ❌ stub (wire `monero-clsag`) |
| Monero crates build for device | ❓ unverified — do this first (step 3) |
