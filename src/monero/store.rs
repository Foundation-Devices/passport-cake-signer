// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Persist the paired watch-only wallet as JSON.
//!
//! On device this maps to writing `wallet.json` via the KeyOS FileSystem (the
//! app wires the I/O); the functions here are pure so they are fully testable.
//! Only PUBLIC pairing data is stored (address + view key + label) — never the
//! spend secret, which is always re-derived from the app seed.

use super::{Error, RegisteredWallet, Result};

pub fn to_json(wallet: &RegisteredWallet) -> Result<String> {
    serde_json::to_string_pretty(wallet).map_err(|e| Error::Parse(format!("serialize: {e}")))
}

pub fn from_json(s: &str) -> Result<RegisteredWallet> {
    serde_json::from_str(s).map_err(|e| Error::Parse(format!("deserialize: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monero::Network;

    #[test]
    fn round_trips() {
        let w = RegisteredWallet {
            network: Network::Stagenet,
            primary_address: "5...".into(),
            private_view_key: "00".repeat(32),
            label: "Phone".into(),
        };
        let json = to_json(&w).unwrap();
        assert_eq!(from_json(&json).unwrap(), w);
    }
}
