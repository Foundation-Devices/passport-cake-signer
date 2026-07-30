# Passport Prime QuantumLink Monero Integration

This branch adds the Cake Wallet side of Passport Prime support as a Monero-only
Android hardware wallet.

## Current Shape

- Passport Prime is exposed as a hardware wallet manufacturer in Cake's existing
  connect-device flow.
- The connection type is Android BLE only.
- Cake can pair, disconnect, reconnect, unpair, and forget Passport Prime.
- One saved device pairing supports multiple watch-only Monero wallets from the
  same Prime. Adding another wallet does not repeat the pairing QR flow.
- Monero watch-wallet restore, key-image sync, transaction signing, and receive
  address verification all use request/response messages over QuantumLink.
- Removing a linked wallet on Prime asks Cake to confirm deletion, identifies
  the wallet by its immutable primary Monero address, and leaves the shared
  device pairing plus every other linked wallet intact.
- The Android bridge is adapted from the Passport Tether WDK QuantumLink module:
  - persistent phone QuantumLink identity
  - Passport identity UR scan
  - BLE connect, bond, notify, write, heartbeat, pair, unpair
  - auto-reconnect before Monero requests when a paired Prime is available
  - local pending-request cleanup on disconnect, cancel, timeout, or peer reject
- Monero uses Cake's existing CupCake/offline-wallet artifacts over Bluetooth:
  - watch wallet restore asks Prime for address, private view key, and restore height
  - key-image sync sends Cake's newline-delimited `xmr-output` UR frames to Prime
  - Prime returns newline-delimited `xmr-keyimage` UR frames for Cake to import
  - transaction signing sends Cake's newline-delimited `xmr-txunsigned` UR frames
  - Prime returns newline-delimited `xmr-txsigned` UR frames for Cake to import and broadcast
  - address verification sends the wallet address and selected account/subaddress
    indexes, then compares Cake's address with the address independently derived
    and approved on Prime

The important design decision is that Passport Prime mimics CupCake over
QuantumLink rather than implementing Cake's Trezor JSON signing protocol. This
lets Prime reuse the Monero wallet2 signer and key-image logic already proven in
the QR app.

## Shared Protocol Additions

The branch vendors a Foundation API copy into the QuantumLink plugin and adds
append-only Monero WDK messages:

- `WdkMoneroWatchCredentialsRequest`
  - `protocol_version: u8`
  - `request_id: Vec<u8>`
- `WdkMoneroWatchCredentialsResponse`
  - `protocol_version: u8`
  - `request_id: Vec<u8>`
  - `address: String`
  - `watch_key: String`
  - `restore_height: Option<u64>`
- `WdkMoneroKeyImageSyncRequest`
  - `protocol_version: u8`
  - `request_id: Vec<u8>`
  - `outputs_ur: String`
- `WdkMoneroKeyImageSyncResponse`
  - `protocol_version: u8`
  - `request_id: Vec<u8>`
  - `key_images_ur: String`
- `WdkMoneroSignTransactionRequest`
  - `protocol_version: u8`
  - `request_id: Vec<u8>`
  - `unsigned_tx_ur: String`
- `WdkMoneroSignTransactionResponse`
  - `protocol_version: u8`
  - `request_id: Vec<u8>`
  - `signed_tx_ur: String`
- `WdkMoneroVerifyAddressRequest`
  - `protocol_version: u8`
  - `request_id: Vec<u8>`
  - `wallet_address: String`
  - `account_index: u32`
  - `address_index: u32`
- `WdkMoneroVerifyAddressResponse`
  - `protocol_version: u8`
  - `request_id: Vec<u8>`
  - `account_index: u32`
  - `address_index: u32`
  - `address: String`
- `WdkMoneroWalletRemovalRequest`
  - `protocol_version: u8`
  - `request_id: Vec<u8>`
  - `wallet_address: String`
  - `wallet_name: String` (display only; never used as identity)
- `WdkMoneroWalletRemovalResponse`
  - `protocol_version: u8`
  - `request_id: Vec<u8>`
  - `wallet_address: String`
  - `removed: bool`

## Cake Flow

1. The user opens a Prime wallet and chooses `Add to Cake`.
2. On first use, Cake pairs to the Prime over QuantumLink BLE.
3. Cake requests the armed wallet's Monero watch credentials and restores a
   watch-only wallet.
4. For another wallet on the same Prime, Cake chooses `Add wallet from Passport`
   and reuses the saved authenticated session; there is no second pairing
   QR flow.
5. Before sending, Cake checks whether outputs/key images need sync.
6. If needed, Cake exports `Outputs (all)` as CupCake `xmr-output` UR text and
   sends it over QuantumLink.
7. Cake imports Prime's `xmr-keyimage` UR response.
8. Cake builds the pending transaction as usual.
9. For Passport, Cake asks wallet2 for the offline `xmr-txunsigned` UR text,
   sends it over QuantumLink, waits for the user to review and swipe on Prime,
   imports Prime's `xmr-txsigned` UR response, and broadcasts.
10. On the Monero receive screen, Cake can ask Prime to independently derive the
   selected account/subaddress. Cake accepts the result only when the returned
   indexes and address exactly match its own receive state.
11. When the user chooses `Remove wallet from Cake` on Prime, Cake matches the
    request by primary address, authenticates and asks the user to confirm,
    deletes only that watch-only wallet through its existing wallet service,
    and returns an acknowledgement. Prime does not mark the wallet unlinked
    unless the request ID and wallet address both match that acknowledgement.

## KeyOS Flow

The matching KeyOS branch extends `os/quantum-link` with Monero subscriptions
and response publishers. `apps/gui-app-cake-signer` subscribes to those requests
on launch:

- watch credentials come only from the wallet explicitly armed by `Add to Cake`
- key-image sync decodes the incoming `xmr-output` UR, matches it against active
  Cake-linked Prime wallets, computes key images, and returns `xmr-keyimage` UR
  text
- signing decodes the incoming `xmr-txunsigned` UR, matches it against active
  Prime wallets, stages the existing review screen, and returns `xmr-txsigned`
  UR text only after the user completes the on-device swipe
- address verification matches the request's primary address to an active Prime
  wallet already linked to Cake, independently derives the requested
  account/subaddress, and returns it only after explicit on-device confirmation
- wallet removal remains pending on Prime until Cake returns an authenticated,
  request-correlated acknowledgement for the same primary address

The native QuantumLink session is device-level. Individual Cake wallet files
retain their own Monero address and hardware-wallet type, while the singleton
Passport transport reconnects the one saved Prime as needed. Prime uses the
request payload to select the correct enrolled wallet, so users do not switch or
re-pair the transport when moving between Cake wallets.

If Prime cannot parse or match a request, it returns `WdkRequestRejected` so the
phone does not sit on a long timeout.

Cake can also send `WdkRequestCancelled` when the user leaves or replaces an
in-flight request. Prime subscribes to that cancellation and suppresses stale
worker responses instead of publishing a late key-image or signed-transaction
reply.

## Validation

Local validation run for this branch:

- `dart analyze` inside `scripts/passport_quantumlink`
- focused `flutter analyze --no-pub --no-fatal-infos` over the Passport/Cake
  integration files
- `cargo test --manifest-path scripts/passport_quantumlink/native/Cargo.toml`
- `cargo clippy --manifest-path scripts/passport_quantumlink/native/Cargo.toml --all-targets -- -D warnings`
- Android debug APK build with `/Users/admin/Documents/AI/flutter-3.41.9/bin/flutter build apk --debug`

Built APK:

- `build/app/outputs/flutter-apk/app-debug.apk`
- SHA-256: `6f7a5704c0fbfc0fa3feea14123c54363a9e0d5f74df54c72a16578dbe11f855`

## Upstreaming Notes

Keep Cake changes small and reviewable:

- no new Monero transaction format
- no direct KeyOS or signer logic inside Cake's Monero wallet code
- Passport is treated as a Monero hardware wallet transport
- Foundation-specific BLE/GSTP details stay behind `passport_quantumlink`
