# Cake Wallet Signer for Passport Prime

A Monero **cold signer** that runs natively on [Foundation Passport Prime](https://foundation.xyz), built on KeyOS. Pairs with [Cake Wallet](https://cakewallet.com) mobile.

Cake Wallet stays the wallet. Passport holds the Monero **spend key** offline (derived from the KeyOS app seed) and only ever signs a transaction that Cake Wallet's watch-only wallet built. It never goes online. This is the Monero analogue of the [Liana signer POC](../passport-liana-signer), and follows the same air-gapped model as Cake's own [Cupcake](https://blog.cakewallet.com/air-gapped-privacy-made-easy-meet-the-new-cupcake-experience/) offline app.

> **Proof-of-concept.** KeyOS application (Rust + Slint), builds inside a KeyOS workspace (see [SDK-SETUP.md](SDK-SETUP.md)).
>
> **What works, and where:**
> | Capability | Host / Simulator | Passport device (xous) |
> |---|---|---|
> | Key/address derivation (16-word **Polyseed** from the app seed) | ✅ | ✅ |
> | Pairing QR, recovery-seed display, camera QR scan | ✅ | ✅ |
> | unsigned-tx **decrypt + auth-verify + parse** | ✅ | ✅ (compiles for xous) |
> | CLSAG/Bulletproof+ **signing** + `signed_tx_set` packaging | ✅ | ✅ (compiles for xous) |
>
> The Polyseed derivation is **verified against the real Cake app** (restoring the 16 words yields the identical address). Signing is proven on host/sim and relayed on stagenet. **The full decode+sign path now compiles for the device** (`armv7a-unknown-xous-elf`): the wallet2 chacha key uses a vendored `no_std` CryptoNight (byte-for-byte parity with cuprate), and serai's signer builds `no_std` with a deterministic RNG (no `getrandom`). The ATSAMA5D27 has 128 MB DDR, so the 2 MB CryptoNight scratchpad + Bulletproof+ proving fit. **Remaining:** confirm it *runs* on real hardware (compile ≠ run) and a clean import into the Cake mobile app — see [Known limitations](#known-limitations).

## Testing model

Cake mobile is QR-only, so we develop and verify against **`monero-wallet-cli` on stagenet**, which emits the identical wallet2 file artifacts Cake uses internally. The pure, host-testable logic lives in the **[`monero-cold-core`](../monero-cold-core)** reference crate (mirrors `liana-signer-core`); the test rig that stands up the stagenet wallet pair and produces golden fixtures is in **[`test-rig/`](../test-rig)**.

**Verified so far:** `monero-wallet-cli --generate-from-keys` regenerates the exact same address from our derived spend/view keys (locked in as `keys::tests::cli_verified_stagenet_vector`). The view-only export pairing data is therefore byte-correct Monero.

## The model

Passport is the **cold** wallet; Cake mobile runs the matching **watch-only** wallet (address + private view key only). They exchange the standard Monero `wallet2` artifacts as files over **microSD/USB** (the easiest transport; animated-QR / UR is a fast-follow):

```
  Passport (cold, this app)                Cake Wallet mobile (watch-only)
  -------------------------                -------------------------------
  export view-only   --(cake-view-only)-->   create watch-only wallet      [once]
  export key images  --(cake-key-images)-->  refresh spent outputs
                      <-(unsigned tx)------   build the transaction
  review + sign       --(signed tx)------->   broadcast
```

## Why native Rust, not a port

Cake Wallet and Cupcake are Flutter/Dart with a C++ `wallet2` core. Neither runs on KeyOS (Rust microkernel + Slint, `armv7a-unknown-xous-elf`). So we rebuild the **cold-signer role** natively, using the pure-Rust, `no_std`-capable [`monero-wallet`](https://lib.rs/crates/monero-wallet) + [`monero-clsag`](https://docs.rs/monero-clsag-mirror) crates (serai / monero-oxide). These are the Monero counterpart to the `ngwallet` bitcoin+miniscript stack the Liana signer rides on.

## Branding

Cake Wallet's palette is wired in [`ui/cake-theme.slint`](ui/cake-theme.slint), taken from `cake-tech/cake_wallet` `lib/palette.dart`:

| Token | Hex | Use |
|-------|-----|-----|
| `cakeBlue` | `#00B8FA` | primary brand / CTA |
| `moneroOrange` | `#FF6600` | XMR amounts |
| `backgroundColor` | `#19233C` | app shell |
| `nightBlue` | `#232F4F` | cards |
| `brightGreen` | `#58F332` | signed / done |

> TODO: drop a Cake/XMR app glyph into `media/` and reference it from the home + done pages (currently using a placeholder icon).

## Layout

```
manifest.toml          appId, app name "Cake", fs + GetAppSeed permissions
Cargo.toml             monero-wallet + monero-clsag deps
src/
  main.rs              app entry, callbacks, microSD/USB file picker I/O
  master_key.rs        32-byte app seed from KeyOS security
  monero/
    mod.rs             types, errors, RegisteredWallet, TxSummary, format_xmr
    keys.rs            spend/view key derivation from the app seed
    txset.rs           wallet2 unsigned/signed txset codec  <-- interop boundary
    signer.rs          CLSAG signing gate                   <-- crypto core
    store.rs           persist the paired watch-only wallet
ui/
  cake-theme.slint     Cake Wallet palette
  app.slint, callbacks.slint
  pages/{home,review,sign-done}/
```

## The one decision to make first

`src/monero/txset.rs` is the integration boundary. Stock Cake Wallet emits/consumes **`wallet2`'s** binary `unsigned_tx_set` / `signed_tx_set` format. The pure-Rust crates do not speak it natively. Two paths:

1. **Interop with stock Cake mobile** — implement the `wallet2` txset codec in `txset.rs` (the real work; the "Cake-branded, just works with the Cake app" promise).
2. **Self-contained Cake-on-Prime pair** — use serai's format on both halves, which means a custom online counterpart, not stock Cake.

Confirm which with the Cake team before building out `txset.rs`.

## Roadmap

- [x] Key/address derivation — now a 16-word **Polyseed**, verified against the real Cake app
- [x] Golden fixtures from a funded stagenet wallet (`test-rig/`)
- [x] wallet2 `unsigned_tx_set` decrypt + auth-verify + structural parse (`txset.rs`, host/sim)
- [x] CLSAG/Bulletproof+ signing + from-scratch `signed_tx_set` packaging (`signer.rs`, host/sim)
- [x] End-to-end on **stagenet** (cold sign -> `submit_transfer` -> relayed)
- [x] Animated QR / UR transport (CupCake-style `xmr-txunsigned`/`xmr-txsigned`), Cake-native
- [x] Cake Wallet app glyph (`ui/ui/icons/cake.svg`)
- [ ] **On-device** decode + signing (`no_std` CryptoNight + serai on xous) — see Known limitations
- [ ] Preserve `extra`/unlock_time/exact fee; multi-`pending_tx`; key-image export
- [ ] Clean import into the **Cake mobile** app (acceptance test)

## Known limitations

Tracked candidly (several surfaced in an external review). The signing core is a strong host prototype, **not yet a complete offline KeyOS signer**:

- **On-device decode/sign — compiles, runtime unverified (P0).** Previously gated off xous; now ALL-TARGET via a vendored `no_std` CryptoNight (`cryptonight-noxous`) + `no_std` serai. The full stack builds for `armv7a-unknown-xous-elf`. Still needs an on-hardware run (does CryptoNight + Bulletproof+ proving complete within memory/time on the device).
- **Signer rebuilds rather than re-signs wallet2's construction (P1).** It reconstructs the tx via serai with a hardcoded `RctType`, empty `extra`, and serai's own fee/change, instead of preserving `sources`/`splitted_dsts`/`extra`/`unlock_time`/`use_rct` from `tx_construction_data`. Recipients + amounts are now parsed structurally from `dests` (external sends work, subaddresses honored), but **`extra` (payment IDs), unlock_time, and the exact fee are not yet preserved**, and the bookkeeping fee may differ from wallet2's.
- **Single pending_tx only (P1).** `build_signed_tx_set` emits one `pending_tx`; wallet2 can split a transfer into several. Multi-tx sets aren't handled yet.
- **No output/key-image export (P2).** `encode_key_images` is a stub; the watch-only side needs key-image import for ongoing spent-output correctness across sessions.
- **Acceptance still pending a real Cake import (P1).** The `signed_tx_set` field order is now verified byte-positionally against a real wallet2 fixture (`monero-cold-core/tests/dump_reference.rs`) and relayed on stagenet via `submit_transfer`, but a clean import into the **Cake mobile** app has not been run.

**Fixed from the review:** external-recipient parsing (was self-only), `signed_tx_set` field order (`construction_data` before `multisig_sigs`), decrypt now bounds-checks (no panic on a magic-only file) and **verifies the wallet2 authentication signature** before decrypting.
