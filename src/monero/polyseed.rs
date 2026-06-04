// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Deterministic Polyseed (16-word Monero seed) from the KeyOS app seed.
//!
//! Mirrors the host-proven `monero-cold-core::polyseed` (3 tests incl. the
//! official Polyseed vector). KeyOS gives each app a per-`appId` 32-byte
//! `app_seed`; we turn it into a standard Polyseed so the wallet restores in
//! Cake/Feather from 16 words while staying reproducible from the Passport.
//!
//!   entropy  = Keccak256( DOMAIN ‖ app_seed )[..19], Polyseed-masked  (one-way:
//!              the phrase encodes a HASH of app_seed, never app_seed itself)
//!   spend    = sc_reduce32( Polyseed::key() )       // Polyseed PBKDF2 keygen
//!   view     = sc_reduce32( Keccak256(spend) )      // standard Monero
//!
//! Polyseed's `key()` salt mixes in the birthday, so it MUST be a fixed constant
//! (`BIRTHDAY_SECS`) for a stable seed. Chosen before any Prime ships, so Cake's
//! restore-height scan never starts after a deposit.

use polyseed::{Language, Polyseed};
use zeroize::Zeroizing;

use super::keccak256;

/// Domain separator: the exported phrase is a one-way function of `app_seed`,
/// not the raw platform secret (defense in depth atop KeyOS's per-app seed).
const DOMAIN: &[u8] = b"foundation.cake-signer.polyseed.v1";

/// Fixed wallet birthday (seconds since UNIX epoch). 2026-01-01 00:00:00 UTC.
/// Baked in so the seed is stable; before any Prime ships, so never later than a
/// wallet's first funding.
pub const BIRTHDAY_SECS: u64 = 1_767_225_600;

const SECRET_SIZE: usize = 19; // Polyseed secret = 150 bits
const LAST_BYTE_MASK: u8 = 0x3F; // final byte keeps 6 bits

/// Build the deterministic Polyseed for this device's Cake wallet.
pub fn derive(app_seed: &[u8; 32]) -> Polyseed {
    // Stack buffer (alloc-free) — same on device and sim.
    let mut buf = [0u8; DOMAIN.len() + 32];
    buf[..DOMAIN.len()].copy_from_slice(DOMAIN);
    buf[DOMAIN.len()..].copy_from_slice(app_seed);
    let h = keccak256(&buf);

    let mut entropy = Zeroizing::new([0u8; 32]);
    entropy[..SECRET_SIZE].copy_from_slice(&h[..SECRET_SIZE]);
    entropy[SECRET_SIZE - 1] &= LAST_BYTE_MASK;

    Polyseed::from(Language::English, 0, BIRTHDAY_SECS, entropy)
        .expect("masked 19-byte entropy is always valid")
}

/// The 16-word English seed phrase, for the (gated) Show-seed screen.
pub fn seed_words(app_seed: &[u8; 32]) -> Zeroizing<String> {
    derive(app_seed).to_string()
}

/// The 32-byte Polyseed secret (pre-reduction); the caller reduces to the spend
/// scalar. Zeroized on drop.
pub fn spend_key_bytes(app_seed: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    derive(app_seed).key()
}
