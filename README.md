# Cake Wallet Signer for Passport Prime

A Monero cold-signing app for Passport Prime, with Cake Wallet-compatible
watch-only credentials, transaction review/signing, key-image export, address
derivation, and wallet management.

This repository builds as a standalone Foundation SDK application. It does not
need a KeyOS source checkout and must not be copied into a KeyOS workspace.

Software validation for the SDK 1.0.0 port is complete. The earlier proof of
concept was exercised on hardware before this port; version 0.2.1 still needs
the [KeyOS 1.4 hardware matrix](docs/keyos-1.4-hardware-validation.md) run on a
Passport Prime before the port itself is described as hardware-validated.

## Requirements

- Passport Prime running KeyOS 1.4 beta or newer
- Foundation SDK 1.0.0 for KeyOS 1.4
- Nix, Git, and the SDK's `foundation` command on `PATH`

Run all commands from the repository root.

```sh
foundation doctor
foundation develop
```

`foundation doctor` should report the SDK root, KeyOS target, signing tools,
asset tool, and Slint viewer as available. The CLI creates the ignored
`.foundation-sdk/current` mapping automatically; Cargo dependencies resolve
through that mapping.

## Create a publisher identity

Each developer signs their own build. Do this once, not once per checkout:

```sh
foundation cert gen cake-signer-dev
```

Keep the generated private key private. Before using `foundation sideload`,
enable Developer Mode on Prime and allow the publisher certificate:

```sh
foundation cert fingerprint ~/.foundation/signing/cake-signer-dev/cake-signer-dev.crt
foundation cert install cake-signer-dev
```

Compare the complete fingerprint on a separate trusted channel before allowing
a publisher. Publisher names and contact details are self-asserted in KeyOS 1.4.

## Build, sign, and package

```sh
foundation build --release
foundation pack --release
```

The CLI prompts for a signing identity when more than one exists. Outputs:

- `target/keyos/gui-app-cake-signer/` — signed app bundle
- `target/keyos/gui-app-cake-signer.app` — single installable archive

Copy the `.app` archive to USB/Airlock and install it from
**Settings → Apps → Install App**, or install a development build directly:

```sh
foundation sideload --release
```

The app ID is deliberately fixed at
`0x63616b652d786d722d7369676e657221`. Never change it for an upgrade: KeyOS
uses it to derive the app seed, so changing it creates different Monero keys.

## Third-party app limitations on KeyOS 1.4

KeyOS 1.4 reserves some data/control operations for Foundation-signed
applications; calling a denied operation from an independently signed app can
terminate it, so this build does not make those calls.

The boundary is narrower than this app long assumed. It is not "which subsystem"
but "does the message carry a `permissionGroup`": a message that has one is
`thirdParty`-callable, and one that does not is Foundation-only. The QR scanner,
file picker and PIN prompt all go through `ShowModal`, which has a group — see
the note below. QuantumLink app data does not.

Available in a developer-signed build:

- app-seed-derived and imported Monero wallets
- watch-only pairing QR display
- transaction parsing, review, and signing
- signed transaction and key-image QR display
- Launcher universal-QR handoff for `xmr-txunsigned` transactions
- launching the system QR scanner from inside this app, for seed import and for
  scanning an unsigned transaction or output export straight off Cake
- manual address derivation/verification by account and subaddress index
- fixed-name Airlock file exchange and persistent app data

Unavailable until KeyOS exposes a third-party-safe API:

- Cake-over-QuantumLink requests and responses

### Note on the QR scanner

Earlier builds reported "QR scanning is not available to independently signed
apps on KeyOS 1.4". That was wrong, and it is fixed.

The scanner is **not** reached through `NavigateTo` — that is the one message in
the `os/gui-server` manifest with no `permissionGroup`, which is what makes it
Foundation-only, and it is correctly absent from this app's manifest.
`open_qr_scanner` instead brokers the scanner as a **modal**, so its entire
permission requirement is `MessageAllowed<ShowModal>`:

```toml
ShowModal = { id = 44, permissionGroup = "ui-and-input.brokered-modal", approval = "grantOnFirstUse" }
```

A `permissionGroup` is what makes a message `thirdParty`, and `ShowModal` ships
in the `gui-app` permission template this app already uses. The same is true of
`select_file` and `verify_pin`, which share the identical bound — so the system
file picker is available on the same terms, should this app ever want it.

For file exchange, disconnect USB before the app accesses Airlock:

- import unsigned transaction from `cake/unsigned_monero_tx`
- import seed text from `cake/cake-seed.txt`
- exports are written under `cake/` with Cake-compatible filenames

The UI reports these limits instead of attempting a denied call. The historical
Foundation-internal QuantumLink implementation remains source-gated behind
`cfg(foundation_internal_quantum_link)` for a future SDK/API change; it is not
part of the public third-party build.

## Companion mobile fork

`mobile-wallet/` contains the Cake Wallet proof-of-concept fork. It is excluded
from the Rust workspace and is not needed to build or package the Prime app.

## Development checks

```sh
foundation preview ui/app.slint
foundation sim
foundation build
foundation pack
```

The default debug build optimizes dependencies because Monero signing and
CryptoNight are too slow for an unoptimized Cortex-A5 build.

### Note on CryptoNight

The wallet2 txset chacha key is `cn_slow_hash` v0, taken from upstream
[`cuprate-cryptonight`](https://github.com/Cuprate/cuprate/tree/main/cryptonight)
with no patches.

Earlier versions carried a hand-patched `no_std` fork under `vendor/`, on the
belief that the crate could not otherwise build for `armv7a-unknown-xous-elf`.
That was wrong — **KeyOS is a Rust `std` target** (this app uses `std::thread`,
`std::sync::Mutex` and `std::time` throughout), so the upstream crate builds and
runs on device unmodified, `f64::sqrt()` and `std::io::Write` included. The fork
was ~2,800 lines of vendored cryptography with no reason to exist, and it is
gone.

`monero::txset::cryptonight_tests` pins the official Monero `tests-slow.txt`
vectors so the KDF stays correct across dependency bumps, whichever crate
supplies it.
