// SPDX-License-Identifier: MIT
// Vendored from Cuprate's `cryptonight` crate (dimalinux, Boog900, The Monero
// Project), patched to no_std. Only the v0 hash (the wallet2 txset chacha-key
// KDF) is exported. Output is byte-identical to cuprate-cryptonight.
#![no_std]

extern crate alloc;

mod blake256;
mod cnaes;
mod hash_v2;
mod hash_v4;
mod slow_hash;
mod util;

use slow_hash::cn_slow_hash;

/// Calculates the `CryptoNight` v0 hash of `buf`.
pub fn cryptonight_hash_v0(buf: &[u8]) -> [u8; 32] {
    cn_slow_hash(buf, slow_hash::Variant::V0, 0)
}
