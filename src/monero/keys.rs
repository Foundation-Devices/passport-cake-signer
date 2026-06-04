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

/// The cold wallet's secret key material. NEVER serialized or exported.
pub struct MoneroKeys {
    pub spend_secret: Scalar,
    pub view_secret: Scalar,
}

impl MoneroKeys {
    /// Derive the spend/view secrets from the 32-byte app seed via Polyseed, so
    /// the wallet restores in Cake from the 16-word phrase ([`super::polyseed`]).
    ///   spend = sc_reduce32( Polyseed::key( H(domain ‖ app_seed) ) )
    ///   view  = sc_reduce32( keccak256( spend ) )   // standard Monero
    pub fn from_app_seed(seed: &[u8; 32]) -> Self {
        let key = super::polyseed::spend_key_bytes(seed);
        let spend_secret = Scalar::from_bytes_mod_order(*key);
        let view_secret = Scalar::from_bytes_mod_order(keccak256(spend_secret.as_bytes()));
        MoneroKeys { spend_secret, view_secret }
    }

    /// The 16-word Polyseed phrase for this wallet (Show-seed screen). Secret.
    pub fn seed_words(seed: &[u8; 32]) -> zeroize::Zeroizing<String> {
        super::polyseed::seed_words(seed)
    }

    /// Public spend key (compressed ed25519 point), 32 bytes.
    pub fn public_spend(&self) -> [u8; 32] {
        EdwardsPoint::mul_base(&self.spend_secret).compress().to_bytes()
    }

    /// Public view key (compressed ed25519 point), 32 bytes.
    pub fn public_view(&self) -> [u8; 32] {
        EdwardsPoint::mul_base(&self.view_secret).compress().to_bytes()
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
        assert_eq!(MoneroKeys::seed_words(&[0x11; 32]).split_whitespace().count(), 16);
    }
}
