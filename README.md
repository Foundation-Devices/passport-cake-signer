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

KeyOS 1.4 ships Bluetooth, QuantumLink, QR-scanner navigation, and file-picker
APIs, but their data/control operations are reserved for Foundation-signed
applications. Calling those denied operations from an independently signed app
can terminate the app. This SDK build therefore does not make those calls.

Available in a developer-signed build:

- app-seed-derived and imported Monero wallets
- watch-only pairing QR display
- transaction parsing, review, and signing
- signed transaction and key-image QR display
- Launcher universal-QR handoff for `xmr-txunsigned` transactions
- manual address derivation/verification by account and subaddress index
- fixed-name Airlock file exchange and persistent app data

Unavailable until KeyOS exposes a third-party-safe API:

- Cake-over-QuantumLink requests and responses
- launching the system QR scanner from inside this app (Launcher can still
  scan and hand a matching `xmr-txunsigned` UR to Cake Signer)
- launching the system file picker from this app

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
