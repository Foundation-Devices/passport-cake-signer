# KeyOS 1.4 Hardware Validation

This matrix applies to the standalone Foundation SDK build, beginning with app
version 0.2.1. The June proof-of-concept hardware run predates the SDK 1.0.0,
UI2, permission, packaging, and Launcher QR-handoff migration and does not count
as validation of this port.

Current status: **pending execution on Passport Prime running KeyOS 1.4 beta**.

## Build and installation

- Run `foundation doctor` and record the CLI and SDK versions.
- Run `foundation pack --release` with the intended stable publisher identity.
- Record the `.app` SHA-256 and the app hash printed by the CLI.
- Install from **Settings → Apps → Install App** and compare the complete app
  hash under the installed app details.
- Confirm both Settings and Cake launch normally after installation.

## Upgrade and identity safety

- Upgrade an existing Cake Signer installation without removing it first.
- Confirm the existing Prime-derived wallet address is unchanged.
- Confirm imported wallets, names, archive state, and restore heights persist.
- Reboot Prime and confirm the same data remains available.

## UI2 regression

- Visit every screen in light and dark system themes.
- Confirm text uses the SDK font, no labels clip, and no glyph is missing.
- Exercise primary, secondary, danger, disabled, loading, and pressed buttons.
- Exercise wallet-name, seed, account, and subaddress inputs, including clear
  and submit behavior.
- Confirm modal, menu, scrolling, spinner, static QR, and animated QR layouts.

## Launcher QR handoff

- With Cake Signer closed, scan a Cake `xmr-txunsigned` UR from Launcher's QR
  tile; confirm Cake Signer opens directly and shows transaction review.
- Repeat while Cake Signer is already running in the background.
- Confirm an unsigned transaction for another wallet is rejected safely.
- Confirm unrelated QR and UR types are not routed to Cake Signer.
- Cancel review and repeat a scan to ensure no stale transaction is retained.

## Signing and exchange

- Review recipient, amount, change, and fee for a real unsigned transaction.
- Sign on Prime and scan the animated `xmr-txsigned` result into Cake Wallet.
- Broadcast from Cake and confirm the transaction appears in both wallets.
- Repeat import and export using the fixed Airlock paths documented in the
  README, with USB disconnected before Prime accesses Airlock.
- Export watch-only credentials and key images and confirm Cake accepts them.
- Verify primary and subaddress derivation manually by account/index.

## Permission-boundary behavior

- Open each UI action whose underlying third-party API is unavailable.
- Confirm the app displays its explanatory status instead of crashing or
  invoking Bluetooth, QuantumLink, the system scanner, or the file picker.
- Confirm the installed manifest contains no Bluetooth, QuantumLink,
  `NavigateTo`, or `FlushFs` permission.

## Result record

Record the date, Prime serial/build identifier, KeyOS version, publisher
fingerprint, app hash, `.app` SHA-256, tester, and any failed step here before
changing the status above to passed.
