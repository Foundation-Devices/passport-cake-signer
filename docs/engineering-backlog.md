# Cake Signer Engineering Backlog

This document tracks the reliability work that sits around the core QR signing
demo. The app source lives here; KeyOS validation runs after syncing into the
`KeyOS-cake-signer` integration worktree.

## State-Machine Invariants

- Pending unsigned transactions are tagged with the wallet id that decoded them.
- Signed transaction QR/file exports are tagged with the wallet id that produced
  them.
- Key-image QR exports are tagged with the wallet id that produced them.
- Wallet selection, add/import/archive/restore/delete invalidates any pending
  transaction work and any cached outgoing artifact.
- Background unsigned-transaction parsing is guarded by a monotonic request id.
  Stale workers are ignored.
- Background signing rechecks that the same wallet and pending transaction are
  still active before publishing the signed transaction.

## Validation

Automated checks:

```bash
./scripts/check-in-keyos.sh /Users/admin/Documents/AI/KeyOS-cake-signer
```

That script syncs this source repo into KeyOS, then runs:

- `cargo check -p gui-app-cake-signer`
- `cargo test -p gui-app-cake-signer`
- `cargo clippy -p gui-app-cake-signer --bin gui-app-cake-signer --no-deps -- -D warnings`
- `cargo xtask check gui-app-cake-signer`
- `cargo xtask build --hosted --dont-sign --app gui-app-cake-signer`

Manual hardware checks still required:

- Pair a fresh Cake watch-only wallet from Prime.
- Receive funds, let Cake rescan, then trigger spent-output sync.
- Scan Prime `xmr-keyimage` output back into Cake.
- Build an unsigned transaction in Cake.
- Scan/sign on Prime.
- Confirm Prime shows animated `xmr-txsigned` QR frames, not a static fallback.
- Scan the signed transaction into Cake and broadcast.
- Repeat after changing the active coin set, adding another wallet, and switching
  wallets.

## Known External Boundary

Cake mobile is not part of this source repo.

- Canonical Prime app source:
  <https://github.com/Foundation-Devices/passport-cake-signer>
- Companion Cake Android fork:
  <https://github.com/BitcoinQnA/cake_wallet/tree/codex/passport-prime-quantumlink>
- Cake upstream target:
  <https://github.com/cake-tech/cake_wallet>

QuantumLink work requires the Cake mobile fork plus the KeyOS QuantumLink server
path. For upstreamability, Cake-side changes should remain limited to:

- A Passport Prime hardware-wallet entry beside existing hardware integrations.
- A QuantumLink transport adapter.
- Monero request/response plumbing for watch credentials, key-image sync, and
  signed transactions.
- Error handling that maps Prime rejections into Cake's existing send/restore UI.

QR remains the compatibility baseline until that path is stable.
