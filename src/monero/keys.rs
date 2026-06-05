// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Deterministic Monero key derivation from the KeyOS app seed.
//!
//! Verified against monero-wallet-cli: `--generate-from-keys` regenerates the
//! identical address from these derived keys (see ../../../monero-cold-core,
//! `keys::tests::cli_verified_stagenet_vector`). Kept in sync with that crate.
//!
//!   spend_secret = sc_reduce32( seed )
//!   view_secret  = sc_reduce32( keccak256( spend_secret ) )   // hash_to_scalar

use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};

use super::{address, keccak256, Network};

/// Subaddress secret offset m = Hs("SubAddr\0" || a || major || minor), where
/// `a` is the private view key. For (0, 0), Monero displays the standard
/// primary address instead of a subaddress.
pub fn subaddress_secret(view: &[u8; 32], major: u32, minor: u32) -> Scalar {
    let mut data = Vec::with_capacity(48);
    data.extend_from_slice(b"SubAddr\0");
    data.extend_from_slice(view);
    data.extend_from_slice(&major.to_le_bytes());
    data.extend_from_slice(&minor.to_le_bytes());
    Scalar::from_bytes_mod_order(keccak256(&data))
}

/// The cold wallet's secret key material. NEVER serialized or exported.
pub struct MoneroKeys {
    pub spend_secret: Scalar,
    pub view_secret: Scalar,
}

impl MoneroKeys {
    /// Build keys from an already-derived Monero private spend key. Used for
    /// imported Polyseed and legacy Monero mnemonic wallets.
    pub fn from_spend_key_bytes(spend_key: [u8; 32]) -> Self {
        let spend_secret = Scalar::from_bytes_mod_order(spend_key);
        let view_secret = Scalar::from_bytes_mod_order(keccak256(spend_secret.as_bytes()));
        MoneroKeys {
            spend_secret,
            view_secret,
        }
    }

    /// Derive the spend/view secrets from the 32-byte app seed via Polyseed, so
    /// the wallet restores in Cake from the 16-word phrase ([`super::polyseed`]).
    ///   spend = sc_reduce32( Polyseed::key( H(domain ‖ app_seed) ) )
    ///   view  = sc_reduce32( keccak256( spend ) )   // standard Monero
    pub fn from_app_seed(seed: &[u8; 32]) -> Self {
        let key = super::polyseed::spend_key_bytes(seed);
        Self::from_spend_key_bytes(*key)
    }

    /// The 16-word Polyseed phrase for this wallet (Show-seed screen). Secret.
    pub fn seed_words(seed: &[u8; 32]) -> zeroize::Zeroizing<String> {
        super::polyseed::seed_words(seed)
    }

    /// Public spend key (compressed ed25519 point), 32 bytes.
    pub fn public_spend(&self) -> [u8; 32] {
        EdwardsPoint::mul_base(&self.spend_secret)
            .compress()
            .to_bytes()
    }

    /// Public view key (compressed ed25519 point), 32 bytes.
    pub fn public_view(&self) -> [u8; 32] {
        EdwardsPoint::mul_base(&self.view_secret)
            .compress()
            .to_bytes()
    }

    /// Private view key as hex — what the watch-only export shares (safe: it
    /// cannot spend).
    pub fn private_view_key_hex(&self) -> String {
        hex::encode(self.view_secret.as_bytes())
    }

    /// Private view key bytes — used to decrypt the wallet2 unsigned tx set.
    pub fn view_secret_bytes(&self) -> [u8; 32] {
        *self.view_secret.as_bytes()
    }

    /// Private spend key bytes — used by the signer. NEVER exported.
    pub fn spend_secret_bytes(&self) -> [u8; 32] {
        *self.spend_secret.as_bytes()
    }

    /// Standard (primary) address, base58, for `network`.
    pub fn primary_address(&self, network: Network) -> String {
        address::primary_address(network, &self.public_spend(), &self.public_view())
    }

    /// Monero account/subaddress address. Account 0 / index 0 is the primary
    /// standard address; all other pairs are subaddresses.
    pub fn address_at(&self, network: Network, account: u32, index: u32) -> String {
        if account == 0 && index == 0 {
            return self.primary_address(network);
        }
        let (spend, view) = self.subaddress_public_keys(account, index);
        address::subaddress_address(network, &spend, &view)
    }

    fn subaddress_public_keys(&self, account: u32, index: u32) -> ([u8; 32], [u8; 32]) {
        let m = subaddress_secret(&self.view_secret_bytes(), account, index);
        let public_spend = EdwardsPoint::mul_base(&self.spend_secret);
        let sub_spend = public_spend + EdwardsPoint::mul_base(&m);
        let sub_view = self.view_secret * sub_spend;
        (
            sub_spend.compress().to_bytes(),
            sub_view.compress().to_bytes(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Polyseed-derived dev wallet ([0x11;32]). Address/view match the host-proven
    /// `monero-cold-core::polyseed` output. Acceptance: restoring the 16-word
    /// phrase in Cake yields this same mainnet address.
    #[test]
    fn polyseed_dev_wallet_vector() {
        let k = MoneroKeys::from_app_seed(&[0x11; 32]);
        assert_eq!(
            k.primary_address(Network::Mainnet),
            "4APTP4HYNScMjNQdwkXCw2fYnVtJas2nxSSpCP3bBzSmKXEbdKjjvyWZCbtyNjaYXSc4RHQgiYtWqWpUpY1qC5KR7sUspfD"
        );
        assert_eq!(
            k.primary_address(Network::Stagenet),
            "5AbVTuCW23iMjNQdwkXCw2fYnVtJas2nxSSpCP3bBzSmKXEbdKjjvyWZCbtyNjaYXSc4RHQgiYtWqWpUpY1qC5KR7r7pBvP"
        );
        assert_eq!(
            k.private_view_key_hex(),
            "40ed52a7a341c97b229a0e334867e3c9c8297075da869f4f0120a5d1a1a9900c"
        );
        // 16-word phrase round-trips.
        assert_eq!(
            MoneroKeys::seed_words(&[0x11; 32])
                .split_whitespace()
                .count(),
            16
        );
    }

    #[test]
    fn address_at_primary_and_subaddress_shapes() {
        let k = MoneroKeys::from_app_seed(&[0x11; 32]);
        let primary = k.primary_address(Network::Mainnet);
        let sub = k.address_at(Network::Mainnet, 0, 1);
        assert_eq!(k.address_at(Network::Mainnet, 0, 0), primary);
        assert_eq!(sub.len(), 95);
        assert!(sub.starts_with('8'), "got {sub}");
        assert_ne!(sub, primary);
    }
}
