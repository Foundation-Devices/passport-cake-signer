# Passport Cake Signer Technical Spec

Date: 2026-07-27

Status: original proof of concept hardware-tested; standalone Foundation SDK
1.0.0 port software-validated, with KeyOS 1.4 hardware re-validation pending

Canonical Prime app repository:
`https://github.com/Foundation-Devices/passport-cake-signer`

Companion Cake Android fork:
`https://github.com/BitcoinQnA/cake_wallet/tree/codex/passport-prime-quantumlink`

Cake upstream target:
`https://github.com/cake-tech/cake_wallet`

Build target: Foundation SDK 1.0.0 / KeyOS 1.4 beta (no KeyOS source checkout)

> Historical note: sections describing QuantumLink document the Foundation-
> internal proof of concept. The public, independently signed 1.4 package uses
> QR and fixed-name Airlock exchange because arbitrary QuantumLink app data is
> not currently exposed to third-party signing identities.

## 1. Executive Summary

The Cake Wallet Signer is a native KeyOS app that turns Passport Prime into an
offline Monero signer for the public Cake Wallet mobile app.

Cake Wallet remains the online/watch-only wallet. Passport Prime holds the
private spend key, receives Cake's Monero wallet2 payloads, performs cold-side
operations locally, and returns Cake-compatible payloads over authenticated
QuantumLink. The wallet2 payloads remain CupCake-compatible.

The current architecture intentionally mimics the CupCake/Cake offline signing
model instead of defining a new Prime-specific Monero protocol. This gives us
interop with the public Cake build today and lets us prove the hard parts first:
wallet2 parsing, key-image generation, transaction signing, and Cake broadcast.

The Prime-side KeyOS app and Cake mobile changes are intentionally tracked in
separate repositories. The Foundation `passport-cake-signer` repository is the
canonical source for the Passport app. The Cake mobile fork carries only the
Android-side changes needed to expose Passport Prime as a Cake hardware wallet
and route Monero watch restore, key-image sync, transaction signing, and receive
address verification over QuantumLink.

One real hardware transaction has been signed on Passport Prime, scanned back
into Cake Wallet, and broadcast successfully.

## 2. Goals

- Provide a working Monero cold-signing flow on Passport Prime.
- Pair Prime-created or imported Monero wallets into Cake as watch-only wallets.
- Keep the private spend key offline on Prime.
- Carry Cake's existing output, unsigned transaction, key-image, and signed
  transaction formats over QuantumLink.
- Keep Monero signing logic transport-agnostic so USB or QuantumLink can be
  added without rewriting the core signer.
- Support multiple wallet records and imported Monero seed formats.

## 3. Non-Goals

- This does not add a new Cake hardware-wallet API.
- This does not require a custom Cake Wallet build.
- This does not attempt to make QR the long-term best transport for all Monero
  payloads.
- This does not yet claim production readiness.
- This does not currently support every wallet2 edge case or transaction shape.

## 4. Current Capabilities

| Capability | Status |
| --- | --- |
| Key/address derivation from KeyOS app seed | Working |
| 16-word Polyseed recovery phrase for Prime-derived wallets | Working |
| QuantumLink pairing bootstrap | Working |
| QuantumLink watch restore | Working |
| QuantumLink key-image sync | Working |
| QuantumLink transaction request/response | Working |
| QuantumLink address verification | Working |
| wallet2 authentication/decryption | Working |
| On-device review screen | Working |
| On-device Monero signing | Working |
| Cake-compatible `signed_tx_set` packaging | Working |
| Cake broadcast after Prime signing | Working on QR-tested transaction |
| QuantumLink cancel/reconnect lifecycle handling | Working |
| Multiple Prime-derived wallet slots | Working |
| Import 16-word Polyseed wallet | Working |
| Import 24/25-word legacy Monero wallet | Working |
| Seed import by QR, typed text, or text file | Working |
| Archive/delete/restore wallet records | Working |
| QuantumLink Prime-side request/response plumbing | Working |

## 5. Glossary

### wallet2

`wallet2` is Monero's main wallet implementation in the Monero core codebase.
In this project, "wallet2 blob" means one of the binary payload formats Monero
wallets already use for offline signing and sync.

The important payloads are:

- `unsigned_tx_set`: unsigned transaction data exported by an online/watch-only
  wallet.
- `signed_tx_set`: signed transaction data returned by an offline signer.
- `output_export`: owned outputs exported by a watch-only wallet so the offline
  signer can compute key images.
- `key_image_export`: key images returned by the offline signer so the
  watch-only wallet knows which outputs are spent.

### Key Image

A key image is a deterministic Monero value derived from a spendable output and
the wallet's private spend material. It lets the network and wallet detect a
spent output without revealing which ring member was actually spent.

For Cake's watch-only wallet, key images are required bookkeeping. Without the
right key images, Cake can fail to build or complete future sends with errors
like "key image not found".

### CupCake-Compatible UR

Cake/CupCake exchange Monero payloads as animated UR QR codes. The raw wallet2
blob is wrapped as a CBOR bytestring and then emitted as UR fragments.

The relevant UR types are:

- `xmr-output`
- `xmr-keyimage`
- `xmr-txunsigned`
- `xmr-txsigned`

## 6. System Model

Passport Prime is the cold signer. Cake Wallet is the online/watch-only wallet.

Cake receives:

- Primary Monero address
- Private view key
- Restore height
- Key images generated by Prime when Cake requests spent-output sync
- Signed transaction data after user approval on Prime

Cake does not receive:

- Private spend key
- Prime device seed
- Imported wallet seed phrases

High-level flow:

```text
Passport Prime                         Cake Wallet mobile
--------------                         ------------------
Pairing QR --------------------------> Restore watch-only wallet

                                      Scan chain and track balance

                         <----------- xmr-output QR, if Cake needs spent sync
xmr-keyimage QR ---------------------> Import key images

                         <----------- xmr-txunsigned QR
Review and sign locally
xmr-txsigned QR ---------------------> Broadcast signed transaction
```

## 7. Architecture

The implementation is split into three conceptual layers:

1. UI and KeyOS integration
2. Transport
3. Monero wallet2 and signing core

The important separation is that the Monero core operates on raw wallet2 bytes.
QR is only one transport wrapper. USB or QuantumLink should be able to carry the
same payloads and reuse the same parser, signer, and key-image functions.

## 8. Implementation Map

```text
manifest.toml
  KeyOS app ID, app name, QR match rule, app-seed and filesystem permissions

src/main.rs
  KeyOS callbacks, scanner integration, wallet state, async signing flow

src/master_key.rs
  KeyOS app seed access

src/qr.rs
  Cake/CupCake UR transport and pairing JSON

src/monero/keys.rs
  Spend/view key derivation, primary addresses, subaddresses

src/monero/polyseed.rs
  Deterministic Polyseed generation for Prime-derived wallets

src/monero/wallets.rs
  Wallet records, slots, import, archive/delete/restore, sealed seed storage

src/monero/address.rs
  Monero base58 standard/subaddress encoding and validation

src/monero/txset.rs
  wallet2 decrypt/authenticate/parse and signed/key-image file framing

src/monero/keyimage.rs
  Cake output export parsing and Monero key-image generation

src/monero/signer.rs
  CLSAG/Bulletproof+ signing and wallet2 signed_tx_set construction

ui/
  Slint screens, Cake-inspired theme, wallet list/detail, review, QR output,
  seed display, import flow, address verification
```

## 9. Wallet Model

The app maintains a wallet book in local app storage.

Wallet kinds:

- `DeviceSlot`: deterministic wallet derived from the KeyOS app seed.
- `ImportedPolyseed`: imported 16-word Polyseed wallet.
- `ImportedLegacy`: imported 24/25-word Monero mnemonic wallet.

Slot behavior:

- Slot 0 preserves the original app-seed derivation.
- Additional Prime-derived wallets are domain-separated child slots.
- Device slots are deterministic and recoverable from the Prime seed plus the
  same app logic.

Imported seed storage:

- Imported phrases are sealed locally.
- Encryption uses XChaCha20-Poly1305.
- The encryption key is derived from a domain-separated hash of the KeyOS app
  seed.
- The wallet record ID is used as AAD.
- Records are stored in `wallets.json`.

Imported seed phrases are never exported automatically. The user can view or QR
display the seed only from the selected wallet's seed screen.

## 10. Pairing Flow

Prime generates Cake's expected watch-only restore JSON:

- `label`
- `version`
- `primaryAddress`
- `privateViewKey`
- `restoreHeight`

Cake scans this QR and restores the wallet as watch-only. Cake can then scan the
chain and construct unsigned transactions, but cannot spend without Prime.

Restore height notes:

- Prime-derived wallets can use the app's chosen restore height.
- Imported wallets currently default conservatively because they may predate the
  app import.
- Better restore-height UX and metadata capture is a future improvement.

## 11. QR Transport

`src/qr.rs` wraps raw wallet2 blobs in CBOR bytestrings and emits
Cake-compatible animated UR fragments.

Current UR types:

- `xmr-output`: Cake to Prime output export
- `xmr-keyimage`: Prime to Cake key-image export
- `xmr-txunsigned`: Cake to Prime unsigned transaction
- `xmr-txsigned`: Prime to Cake signed transaction

The app currently emits finite, cycling systematic fragments for signed
transaction and key-image payloads. This was chosen because large Monero payloads
cannot fit into one QR and deterministic frame cycling was more reliable with
Cake than mixed fountain fragments during testing.

## 12. Key-Image Sync

Cake watch-only wallets need key images before they can correctly reason about
spent outputs.

Flow:

1. Cake exports outputs as `xmr-output`.
2. Prime scans and reassembles the UR.
3. Prime unwraps the CBOR bytestring.
4. Prime decrypts and parses the wallet2 output export.
5. For each output, Prime derives the one-time secret.
6. Prime computes the key image.
7. Prime signs/verifies the key-image entry.
8. Prime packages a wallet2 `key_image_export`.
9. Prime returns it as `xmr-keyimage`.
10. Cake imports the key images and can then continue building/sending.

Subaddress handling:

- Output key derivation handles primary and subaddress outputs.
- The implementation tries the main tx public key and per-output additional tx
  keys, then keeps the candidate that reproduces the output public key.

Current state handling:

- Prime persists synced output entries per wallet record.
- If Cake sends an incremental suffix and Prime has the earlier prefix cached,
  Prime combines them into a full contiguous export.
- If Cake sends only a suffix and Prime lacks the prefix, Prime refuses to emit
  a malformed key-image export and asks for a full output export.

Risk:

- This remains the most fragile area. The "key image not found" class of error
  tends to appear when Cake's view of spendable outputs and Prime's cached output
  set diverge.
- More real Cake fixtures are needed across repeated coin-set changes, fresh
  watch-only restores, previously synced wallets, and subaddress activity.

## 13. Transaction Signing Flow

Flow:

1. Cake builds an unsigned transaction.
2. Cake exports it as `xmr-txunsigned`.
3. Prime scans and reassembles the UR.
4. Prime unwraps the CBOR bytestring into the raw `unsigned_tx_set`.
5. Prime authenticates/decrypts the wallet2 payload with the selected wallet's
   private view key.
6. Prime parses transaction construction data, sources, destinations,
   fee/change, and account/subaddress metadata.
7. Prime shows the review transaction screen.
8. User approves with swipe-to-sign.
9. Prime signs with the private spend key using the Rust Monero stack.
10. Prime packages the result as a wallet2 `signed_tx_set`.
11. Prime emits `xmr-txsigned` animated QR frames.
12. Cake scans the signed transaction and broadcasts.

Signer details:

- Uses `monero-wallet` / monero-oxide for CLSAG and Bulletproof+ signing.
- Reconstructs `OutputWithDecoys` from the exact ring and derived one-time key.
- Handles subaddress input offsets by testing candidate derivations against the
  real output public key.
- Reconstructs the wallet2 `signed_tx_set` envelope Cake expects.

Known signer constraints:

- Integrated-address/payment-ID destinations are currently rejected.
- Multi-`pending_tx` sets need more fixture coverage.
- Large transactions need more QuantumLink throughput and signing-latency tests
  on hardware.

## 14. Wrong-Wallet Handling

When an unsigned transaction request arrives, Prime first tries the selected wallet.
If authentication/decryption fails, the app can try other local wallet records.
If another wallet matches, Prime can switch context and load the transaction.
If none match, the app reports a wrong-wallet or incomplete-scan style error.

This is important because users can have multiple Prime-derived and imported
Monero wallets paired with Cake.

## 15. Address Verification

Cake sends the watch-only wallet's primary address and its selected account and
subaddress indexes in an authenticated QuantumLink request. Prime:

1. Matches the primary address to an active local wallet.
2. Independently derives the requested address.
3. Displays the address and indexes for explicit on-device confirmation.
4. Returns them only after confirmation.

Cake compares the returned address and both indexes byte-for-byte with its
current receive screen. A mismatch is treated as a hard verification failure.

## 16. Security Model

Primary secret boundary:

- Private spend keys remain on Prime.
- Cake receives private view keys only, matching Monero watch-only wallet
  requirements.

Seed handling:

- Device-derived wallets come from KeyOS app-seed derivation.
- Imported wallet phrases are sealed locally with XChaCha20-Poly1305.
- Sealed imported phrases are bound to wallet record IDs via AAD.
- Seed phrases are displayed only through explicit wallet seed UI.

Parsing hardening already present:

- QR payload size limits.
- Output export count limits.
- Additional transaction key count limits.
- Wallet-book normalization and maximum wallet count.
- Refusal to emit partial key-image exports when the prefix is unavailable.

Security review areas:

- wallet2 parser robustness against malformed binary archives.
- Imported seed sealing and data lifetime.
- UI paths that reveal seed phrases.
- App manifest permissions.
- QR and future USB/QuantumLink payload validation.
- Logging hygiene around private or privacy-sensitive data.

## 17. Performance Characteristics

Monero is materially heavier than typical Bitcoin signing flows on embedded
hardware.

Main performance costs:

- wallet2 CryptoNight-derived ChaCha file key.
- RingCT/CLSAG/Bulletproof+ signing.
- Large animated QR payload scan time.
- Cake scanner convergence for large payloads.

Current mitigation:

- The app memoizes the wallet2 file key.
- The app warms the key in the background when a wallet is selected.
- QR fragment sizing is bounded and deterministic.

Remaining UX issues:

- Signing can still pause for several seconds.
- QR scanning large outputs or transactions can feel glitchy.
- User feedback during heavy operations needs continued polish.

## 18. Current Limitations

- Hardware-tested but not production-ready.
- QR is the compatibility path, not the ideal long-term transport.
- Multi-`pending_tx` wallet2 sets need more coverage.
- Integrated-address/payment-ID destinations are rejected.
- Large transactions may be slow to scan and sign.
- Repeated coin-set changes and Cake output sync state need broader tests.
- More fixtures are needed for:
  - Multiple recipients
  - Many inputs
  - Subaddresses
  - Different fee conditions
  - Fresh watch-only wallets
  - Previously synced watch-only wallets
  - Imported seed wallets
  - Wrong-wallet scans
- USB/file handoff exists only as a fallback-style path; QR is the tested demo
  path.

## 19. Test And Validation

Existing validation includes:

- Unit coverage for QR payload bounds.
- Wallet import and wallet-book behavior.
- Address validation.
- Key-image parsing and export behavior.
- Signer path coverage against embedded/demo transaction data.
- Real hardware send through Cake Wallet.

Recommended next fixture suite:

- Save raw Cake `xmr-output`, `xmr-keyimage`, `xmr-txunsigned`, and
  `xmr-txsigned` payloads for each test case.
- Track whether Cake wallet state was fresh or previously synced.
- Include at least:
  - One-input one-output send.
  - External recipient send.
  - Self-send.
  - Subaddress receive then spend.
  - Multiple-input spend.
  - Multiple-recipient spend.
  - Imported Polyseed wallet.
  - Imported legacy wallet.
  - Repeated receive/send cycles from the same Cake watch-only wallet.

## 20. Build And Flash

The app source is SDK-shaped but currently builds inside a full KeyOS workspace
because it depends on workspace crates such as `slint-keyos-platform`.

Test from the KeyOS integration workspace:

```bash
cargo test -p gui-app-cake-signer
```

Build and flash from the KeyOS integration workspace:

```bash
cargo xtask build
cargo xtask build-firmware-image
cargo xtask flash --system --switch
```

Do not flash unsigned builds on production hardware.

## 21. Next Natural Steps

### 21.1 Fixture and Regression Harness

Build a fixture corpus from real Cake exports and make it cheap to replay:

- output export to key-image export
- unsigned tx to signed tx
- wrong-wallet rejection
- partial/incremental output sync behavior

This is the highest priority because the current hardest bugs have come from
wallet2/Cake state edge cases rather than UI polish.

### 21.2 USB Transport

Add USB transport for the same raw wallet2 payloads:

- Avoid large animated QR scanning for high-volume payloads.
- Reduce user frustration.
- Preserve QR as a compatibility fallback.
- Reuse the same Monero core functions.

### 21.3 QuantumLink Transport

The complete Monero companion flow now uses QuantumLink. Pairing is
device-scoped and wallet enrollment is wallet-scoped:

- Cake and Prime perform the Bluetooth/identity QR bootstrap once.
- `Add to Cake` arms one explicit Prime wallet for watch-credential export.
- Additional Prime wallets reuse the saved authenticated session without
  unpairing or scanning the device identity again.
- Prime persists an independent Cake-linked bit per wallet.
- Key-image and transaction payloads are matched cryptographically across
  enrolled wallets; address verification carries the wallet primary address.
- Removing one wallet clears only that wallet association. The explicit global
  `Forget Cake connection` operation unpairs the device and clears all wallet
  associations.
- A new Cake peer invalidates associations created for the prior peer.

Hardening work remains:

- Real-hardware large-payload throughput and repeated-send testing.
- Disconnect/reconnect, timeout, cancellation, and stale-response regression
  coverage.
- Better progress and retry semantics.
- Sender binding and request authentication review before treating it as
  production transport.

### 21.4 UI Responsiveness

Continue moving heavy work off the immediate interaction path:

- Explicit progress states for decrypt/sign/export.
- Better copy for key-image sync requirements.
- Avoid apparent freezes during signing.
- Make scan/retry states clear.

### 21.5 Security Review

Run a Foundation review focused on:

- Seed import and sealing.
- wallet2 parser bounds.
- QR payload limits.
- Permission manifest.
- Transport spoofing/confusion risks.
- UI paths that expose private material.

## 22. Open Questions

- Should production support remain compatible with public Cake first, or should
  we design a cleaner Foundation/Cake protocol in parallel?
- Is USB also required as a wired fallback after QuantumLink hardening?
- What restore-height UX do we want for imported wallets?
- How much Cake-side state can we reliably infer vs requiring explicit user
  action to force full output export?
- Should Prime expose more account/subaddress management, or keep that concept
  mostly in Cake?

## 23. Recommendation

Treat the current app as a strong proof of concept and interop prototype. The
core architecture is sound: Prime speaks existing Cake/CupCake wallet2 flows,
the spend key stays offline, and the Monero core is separated from QR transport.

Before productizing, prioritize fixture coverage and transport reliability. The
next major step is a full QuantumLink hardware regression matrix covering large
transactions, repeated coin-set changes, cancellation, disconnect/reconnect,
and address verification across account/subaddress indexes.
