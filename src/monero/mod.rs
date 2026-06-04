// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Monero cold-signer logic for the Cake Wallet Prime app.
//!
//! Passport is the COLD wallet: it holds the Monero spend key (derived from the
//! KeyOS app seed) and never goes online. Cake Wallet mobile runs the matching
//! WATCH-ONLY wallet (it has only the address + private view key), scans the
//! chain, and builds the transaction. The two halves exchange the standard
//! Monero wallet2 artifacts as files over microSD/USB:
//!
//! ```text
//!   Passport (cold)                         Cake mobile (watch-only)
//!   ---------------                         ------------------------
//!   export view-only    --(monero_view_only)-->  create watch-only wallet
//!   export key images   --(monero_key_images)--> mark spent outputs
//!                        <-(unsigned_monero_tx)-- build unsigned tx
//!   sign + export        --(signed_monero_tx)-->  broadcast
//! ```
//!
//! The crypto engine is the pure-Rust serai / monero-oxide stack
//! (`monero-wallet` + `monero-clsag`), the Monero analogue of the
//! bitcoin+miniscript `ngwallet` stack the Liana signer uses. Both compile
//! no_std for `armv7a-unknown-xous-elf`, which is what makes a native KeyOS
//! Monero signer feasible (the C++ wallet2 core does not).

#![allow(dead_code)]

pub mod address;
pub mod keyimage;
pub mod keys;
pub mod polyseed;
pub mod signer;
pub mod store;
pub mod txset;

use serde::{Deserialize, Serialize};

/// Original Keccak-256 (NOT NIST SHA3-256) — the hash Monero uses everywhere.
pub fn keccak256(input: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    let mut h = Keccak256::new();
    h.update(input);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The app seed could not be read from KeyOS security.
    Seed(String),
    /// A wallet2 artifact (unsigned_txset / key_images / outputs) failed to parse.
    Parse(String),
    /// Parsed, but uses a form this POC does not handle yet (e.g. multisig).
    Unsupported(String),
    /// Network mismatch between the loaded tx and the paired wallet.
    WrongNetwork,
    /// CLSAG signing failed.
    Sign(String),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Seed(s) => write!(f, "seed error: {s}"),
            Error::Parse(s) => write!(f, "parse error: {s}"),
            Error::Unsupported(s) => write!(f, "unsupported: {s}"),
            Error::WrongNetwork => write!(f, "transaction is for a different network than the paired wallet"),
            Error::Sign(s) => write!(f, "signing error: {s}"),
        }
    }
}
impl std::error::Error for Error {}

/// Monero network selector. Start the POC on stagenet (free coins, mirrors
/// mainnet rules) exactly as the Liana signer starts on signet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Network {
    Mainnet,
    Stagenet,
    Testnet,
}

impl Default for Network {
    fn default() -> Self {
        Network::Stagenet
    }
}

impl Network {
    /// Address-prefix byte for a STANDARD (primary) public address
    /// (Monero `cryptonote_config.h`): mainnet 18, stagenet 24, testnet 53.
    pub fn standard_prefix(self) -> u8 {
        match self {
            Network::Mainnet => 18,
            Network::Stagenet => 24,
            Network::Testnet => 53,
        }
    }
}

/// The watch-only wallet this Passport is paired with. Persisted as JSON so the
/// signer can sanity-check that an imported unsigned tx belongs to this device
/// (same primary address) before it ever touches the spend key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegisteredWallet {
    pub network: Network,
    /// Primary (standard) address, base58. What Cake mobile restores from.
    pub primary_address: String,
    /// Private view key, hex. Exported to Cake mobile; safe to share (view-only).
    pub private_view_key: String,
    /// Optional human label so multiple paired wallets stay distinguishable.
    #[serde(default)]
    pub label: String,
}

/// A human-readable summary of an unsigned transaction, parsed on-device from
/// the wallet2 `unsigned_txset` so the user can verify it on the review screen
/// BEFORE the spend key signs anything.
#[derive(Debug, Clone, PartialEq)]
pub struct TxSummary {
    pub network: Network,
    /// Amount actually leaving the wallet = total outputs − change (atomic units).
    pub amount_atomic: u64,
    /// Change returned to this wallet (atomic units).
    pub change_atomic: u64,
    /// Network fee (atomic units). Implicit (= inputs − outputs) and not stored
    /// in the unsigned set; 0 until the source walk lands (the signer re-derives
    /// it authoritatively).
    pub fee_atomic: u64,
    /// Destination addresses (base58); includes the change address for now.
    pub destinations: Vec<String>,
    /// Number of transaction outputs (sends + change).
    pub output_count: usize,
}

/// Format atomic units (1 XMR = 1e12 atomic) as a trimmed decimal string.
pub fn format_xmr(atomic: u64) -> String {
    let whole = atomic / 1_000_000_000_000;
    let frac = atomic % 1_000_000_000_000;
    if frac == 0 {
        format!("{whole}")
    } else {
        // 12 dp, trailing zeros trimmed.
        let s = format!("{whole}.{frac:012}");
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_xmr_trims() {
        assert_eq!(format_xmr(0), "0");
        assert_eq!(format_xmr(1_000_000_000_000), "1");
        assert_eq!(format_xmr(1_500_000_000_000), "1.5");
        assert_eq!(format_xmr(123_456_789), "0.000123456789");
    }
}
