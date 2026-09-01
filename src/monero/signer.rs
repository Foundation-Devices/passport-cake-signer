// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! RingCT/CLSAG signing of a wallet2 `unsigned_tx_set`.
//!
//! Host/sim path (non-device): parse the unsigned set, reconstruct serai's input
//! (`OutputWithDecoys`) from the exact ring + the derived one-time key, and sign
//! with the cold spend key via serai/monero-oxide (CLSAG + Bulletproof+). The
//! result is the raw consensus transaction — network-validated: a signed tx from
//! a real wallet2 unsigned set was accepted + relayed by stagenet daemons.
//!
//! Mirrors the host-tested `monero-cold-core::signer`. serai builds no_std, so
//! this runs ALL-TARGET — including on the Passport device.

use super::keys::MoneroKeys;
use super::Network;

#[derive(Debug)]
pub enum SignError {
    Decrypt,
    Parse(&'static str),
    Serai(String),
    #[allow(dead_code)]
    Unsupported,
}

impl core::fmt::Display for SignError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SignError::Decrypt => write!(f, "decrypt failed"),
            SignError::Parse(s) => write!(f, "parse: {s}"),
            SignError::Serai(s) => write!(f, "{s}"),
            SignError::Unsupported => write!(f, "on-device signing not wired (host/sim only)"),
        }
    }
}

// ---------------------------------------------------------------------------
// Signing — ALL-TARGET. serai and upstream cuprate-cryptonight run on the
// device unmodified; the signer seeds a deterministic ChaCha20Rng so no getrandom.
// ---------------------------------------------------------------------------
mod imp {
    use monero_wallet::{
        address::{MoneroAddress, Network as SeraiNetwork},
        ed25519::{Point as SeraiPoint, Scalar as SeraiScalar},
        ringct::RctType,
        send::{Change, SignableTransaction},
        OutputWithDecoys, ViewPair,
    };
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    use zeroize::Zeroizing;

    use super::{MoneroKeys, Network, SignError};
    use crate::monero::keccak256;
    use crate::monero::keys::subaddress_secret;
    use crate::monero::txset::{decrypt, parse_sources, ParsedSource};

    fn write_varint(mut v: u64, out: &mut Vec<u8>) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                out.push(b | 0x80);
            } else {
                out.push(b);
                break;
            }
        }
    }

    fn hash_to_scalar(d: &[u8]) -> curve25519_dalek::scalar::Scalar {
        curve25519_dalek::scalar::Scalar::from_bytes_mod_order(keccak256(d))
    }

    fn output_key_offset(
        view_secret: &[u8; 32],
        real_out_tx_key: &[u8; 32],
        idx: u64,
    ) -> Option<curve25519_dalek::scalar::Scalar> {
        use curve25519_dalek::{edwards::CompressedEdwardsY, scalar::Scalar};
        let a = Scalar::from_bytes_mod_order(*view_secret);
        let r = CompressedEdwardsY(*real_out_tx_key).decompress()?;
        let deriv = (a * r).mul_by_cofactor();
        let mut data = deriv.compress().to_bytes().to_vec();
        write_varint(idx, &mut data);
        Some(hash_to_scalar(&data))
    }

    /// Derive the per-input offset serai adds to the wallet spend key. Primary
    /// inputs use Hs(8*a*R || idx). Subaddress inputs must add
    /// Hs("SubAddr\0" || a || account || minor). Try the wallet2 source tx keys
    /// and selected subaddress indices, then keep only the candidate which
    /// reproduces the real one-time output public key.
    fn input_key_offset(
        src: &ParsedSource,
        keys: &MoneroKeys,
        account: u32,
        subaddr_indices: &[u32],
    ) -> Option<[u8; 32]> {
        use curve25519_dalek::edwards::EdwardsPoint;
        let view_secret = keys.view_secret_bytes();
        let spend_secret =
            curve25519_dalek::scalar::Scalar::from_bytes_mod_order(keys.spend_secret_bytes());
        let real = src.ring.get(src.real_output as usize)?;

        let mut tx_keys = vec![src.real_out_tx_key];
        if let Some(additional) = src
            .real_out_additional_tx_keys
            .get(src.real_output_in_tx_index as usize)
        {
            tx_keys.push(*additional);
        }

        let mut indices = vec![0u32];
        for index in subaddr_indices {
            if !indices.contains(index) {
                indices.push(*index);
            }
        }

        for tx_key in tx_keys {
            let Some(base_offset) =
                output_key_offset(&view_secret, &tx_key, src.real_output_in_tx_index)
            else {
                continue;
            };
            for minor in &indices {
                let sub_offset = if account == 0 && *minor == 0 {
                    curve25519_dalek::scalar::Scalar::ZERO
                } else {
                    subaddress_secret(&view_secret, account, *minor)
                };
                let key_offset = base_offset + sub_offset;
                let one_time = EdwardsPoint::mul_base(&(spend_secret + key_offset))
                    .compress()
                    .to_bytes();
                if one_time == real.dest {
                    return Some(*key_offset.as_bytes());
                }
            }
        }
        None
    }

    /// Serialize an OutputWithDecoys in serai's wire format (its fields are
    /// private, so we build it via `read`).
    fn input_bytes(
        src: &ParsedSource,
        keys: &MoneroKeys,
        account: u32,
        subaddr_indices: &[u32],
    ) -> Result<Vec<u8>, SignError> {
        let mut b = Vec::with_capacity(128 + src.ring.len() * 64);
        let real = src
            .ring
            .get(src.real_output as usize)
            .ok_or(SignError::Parse("real output index"))?;
        b.extend_from_slice(&real.dest);
        b.extend_from_slice(
            &input_key_offset(src, keys, account, subaddr_indices)
                .ok_or(SignError::Parse("input key offset"))?,
        );
        b.extend_from_slice(&src.mask);
        b.extend_from_slice(&src.amount.to_le_bytes());
        write_varint(src.ring.len() as u64, &mut b);
        let mut prev = 0u64;
        for m in &src.ring {
            write_varint(m.global_index - prev, &mut b);
            prev = m.global_index;
        }
        b.push(src.real_output as u8);
        for m in &src.ring {
            b.extend_from_slice(&m.dest);
            b.extend_from_slice(&m.commitment);
        }
        Ok(b)
    }

    fn serai_network(n: Network) -> SeraiNetwork {
        match n {
            Network::Mainnet => SeraiNetwork::Mainnet,
            Network::Stagenet => SeraiNetwork::Stagenet,
            Network::Testnet => SeraiNetwork::Testnet,
        }
    }

    pub fn sign_unsigned_tx(
        unsigned_file: &[u8],
        keys: &MoneroKeys,
        network: Network,
        fee_per_weight: u64,
    ) -> Result<Vec<u8>, SignError> {
        let view_secret = keys.view_secret_bytes();
        let spend_pub = keys.public_spend();
        let pt = decrypt(unsigned_file, &view_secret).map_err(|_| SignError::Decrypt)?;
        let sources = parse_sources(&pt).ok_or(SignError::Parse("sources"))?;
        if sources.is_empty() {
            return Err(SignError::Parse("no sources"));
        }

        use crate::monero::txset::{parse_construction_data, parse_dest_entries};
        let spans = parse_construction_data(&pt).ok_or(SignError::Parse("construction_data"))?;

        let net = serai_network(network);

        let mut inputs = Vec::with_capacity(sources.len());
        for s in &sources {
            let bytes = input_bytes(s, keys, spans.subaddr_account, &spans.subaddr_indices)?;
            let owd = OutputWithDecoys::read(&mut &bytes[..])
                .map_err(|e| SignError::Serai(format!("input: {e:?}")))?;
            inputs.push(owd);
        }

        // Payments = the user's recipients, parsed STRUCTURALLY from `dests`
        // (excludes change). Finds external recipients (the old self-pubkey scan
        // only worked for self-sends); honors subaddress recipients.
        use monero_wallet::address::AddressType;

        let dests = parse_dest_entries(&pt, spans.dests).ok_or(SignError::Parse("dests"))?;
        let mut payments: Vec<(MoneroAddress, u64)> = Vec::new();
        for d in &dests {
            if d.is_integrated {
                return Err(SignError::Parse("integrated address destination"));
            }
            let spend_pt = curve25519_dalek::edwards::CompressedEdwardsY(d.spend_pub)
                .decompress()
                .ok_or(SignError::Parse("dest spend point"))?;
            let view_pt = curve25519_dalek::edwards::CompressedEdwardsY(d.view_pub)
                .decompress()
                .ok_or(SignError::Parse("dest view point"))?;
            let kind = if d.is_subaddress {
                AddressType::Subaddress
            } else {
                AddressType::Legacy
            };
            let addr = MoneroAddress::new(
                net,
                kind,
                SeraiPoint::from(spend_pt),
                SeraiPoint::from(view_pt),
            );
            payments.push((addr, d.amount));
        }
        if payments.is_empty() {
            return Err(SignError::Parse("no destination"));
        }

        let spend_point = curve25519_dalek::edwards::CompressedEdwardsY(spend_pub)
            .decompress()
            .ok_or(SignError::Parse("spend point"))?;
        let view_scalar = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(view_secret);
        let view_pair = ViewPair::new(
            SeraiPoint::from(spend_point),
            Zeroizing::new(SeraiScalar::from(view_scalar)),
        )
        .map_err(|e| SignError::Serai(format!("view pair: {e:?}")))?;
        let change_out = Change::new(view_pair, None);

        let fee_rate = monero_wallet::interface::FeeRate::new(fee_per_weight, 10_000)
            .ok_or(SignError::Serai("fee rate".into()))?;
        let ovk = keccak256(&pt);

        let signable = SignableTransaction::new(
            RctType::ClsagBulletproofPlus,
            Zeroizing::new(ovk),
            inputs,
            payments,
            change_out,
            vec![],
            fee_rate,
        )
        .map_err(|e| SignError::Serai(format!("build: {e:?}")))?;

        let spend_scalar =
            curve25519_dalek::scalar::Scalar::from_bytes_mod_order(keys.spend_secret_bytes());
        let mut rng = ChaCha20Rng::from_seed(ovk);
        let tx = signable
            .sign(&mut rng, &Zeroizing::new(SeraiScalar::from(spend_scalar)))
            .map_err(|e| SignError::Serai(format!("sign: {e:?}")))?;
        Ok(tx.serialize())
    }

    /// Build a wallet2 `signed_tx_set` from scratch (no reference set) — the real
    /// product path. Signs `unsigned`, then assembles the `pending_tx` +
    /// `signed_tx_set`, copying the construction-data fields verbatim from the
    /// unsigned set and taking the key image from our signed transaction. Returns
    /// the encrypted signed file, ready for Cake `submit_transfer`.
    ///
    /// VERIFIED in monero-cold-core (tests/from_scratch.rs + stagenet relay).
    pub fn build_signed_tx_set(
        unsigned: &[u8],
        keys: &MoneroKeys,
        network: Network,
        fee_per_weight: u64,
    ) -> Result<Vec<u8>, SignError> {
        use monero_wallet::transaction::{Input, NotPruned, Transaction};

        use crate::monero::txset::{
            change_amount, decrypt, encrypt_tx_set, parse_construction_data, parse_dest_entries,
            parse_sources, MAGIC_SIGNED,
        };

        let view_secret = keys.view_secret_bytes();
        let view_pub = keys.public_view();
        let spend_pub = keys.public_spend();

        let pt = decrypt(unsigned, &view_secret).map_err(|_| SignError::Decrypt)?;
        let sp = parse_construction_data(&pt).ok_or(SignError::Parse("construction_data"))?;

        let tx_bytes = sign_unsigned_tx(unsigned, keys, network, fee_per_weight)?;
        let tx = Transaction::<NotPruned>::read(&mut &tx_bytes[..])
            .map_err(|e| SignError::Serai(format!("reparse tx: {e:?}")))?;
        // Sanity: the signed tx must carry a key-image input.
        match tx.prefix().inputs.first() {
            Some(Input::ToKey { .. }) => {}
            _ => return Err(SignError::Parse("input not ToKey")),
        }

        // Bookkeeping fee = inputs − (recipients + change), recipients from the
        // structural `dests` parse so external sends compute correctly.
        let total_in: u64 = parse_sources(&pt)
            .map(|s| s.iter().map(|x| x.amount).sum())
            .unwrap_or(0);
        let recipients_out: u64 = parse_dest_entries(&pt, sp.dests)
            .map(|v| v.iter().map(|d| d.amount).sum())
            .unwrap_or(0);
        let change_out = change_amount(&pt, &spend_pub);
        let fee = total_in.saturating_sub(recipients_out.saturating_add(change_out));

        let cut = |s: (usize, usize)| &pt[s.0..s.1];
        let mut plain = Vec::with_capacity(tx_bytes.len() + (sp.cdata.1 - sp.cdata.0) + 256);
        plain.extend_from_slice(&[0x00, 0x01, 0x01]); // set ver, ptx count, pending_tx ver
        plain.extend_from_slice(&tx_bytes); // tx
        plain.extend_from_slice(&0u64.to_le_bytes()); // dust
        plain.extend_from_slice(&fee.to_le_bytes()); // fee
        plain.push(0x00); // dust_added_to_fee
        plain.extend_from_slice(cut(sp.change_dts)); // change_dts (copy)
        plain.extend_from_slice(cut(sp.selected_transfers)); // selected_transfers (copy)
        plain.push(0x00); // key_images string (empty)
        plain.extend_from_slice(&[0u8; 32]); // tx_key (null)
        plain.push(0x00); // additional_tx_keys (empty)
        plain.extend_from_slice(cut(sp.dests)); // dests (copy: count + entries)
                                                // wallet2 pending_tx order (VERIFIED vs reference fixture in
                                                // monero-cold-core/tests/dump_reference): construction_data comes BEFORE
                                                // multisig_sigs + multisig_tx_key_entropy, not after.
        plain.extend_from_slice(cut(sp.cdata)); // construction_data (copy)
        plain.push(0x00); // multisig_sigs (empty)
        plain.extend_from_slice(&[0u8; 32]); // multisig_tx_key_entropy (null)
                                             // signed_tx_set wrapper: key_images vec MUST be empty (wallet2's holds the
                                             // cold wallet's full export; a partial entry fails import — the tx's key
                                             // image is already inline) + tx_key_images map (empty).
        plain.push(0x00); // key_images count = 0
        plain.push(0x00); // tx_key_images map count = 0

        let iv8 = keccak256(&plain);
        let mut iv = [0u8; 8];
        iv.copy_from_slice(&iv8[..8]);
        Ok(encrypt_tx_set(
            &plain,
            &view_secret,
            &view_pub,
            MAGIC_SIGNED,
            0x05,
            iv,
        ))
    }
}

pub use imp::build_signed_tx_set;
// `sign_unsigned_tx` is used internally by `build_signed_tx_set`; re-exported for
// tests / raw-tx callers.
#[allow(unused_imports)]
pub use imp::sign_unsigned_tx;

// ---------------------------------------------------------------------------
// Port verification: run the app's OWN build_signed_tx_set on the embedded
// stagenet fixture (same one the simulator seeds) with the pinned dev wallet
// (seed 0x11*32), and confirm the output is a valid, re-decryptable wallet2
// signed_tx_set. The cold-core reference proves byte-identity vs real wallet2 +
// stagenet relay; this proves the in-app copy reproduces it.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod port_tests {
    use super::*;
    use crate::monero::keys::MoneroKeys;
    use crate::monero::txset::MAGIC_SIGNED;
    use crate::monero::Network;

    const DEMO_UNSIGNED: &[u8] = include_bytes!("../../resources/demo_unsigned_monero_tx");

    /// Decrypt a signed_tx_set the same way wallet2 does (mirror of txset::decrypt
    /// but for the signed magic), so the test can read back what we produced.
    fn decrypt_signed(file: &[u8], view_secret: &[u8; 32]) -> Vec<u8> {
        use chacha20::cipher::generic_array::GenericArray;
        use chacha20::cipher::{KeyIvInit, StreamCipher};
        use chacha20::ChaCha20Legacy;
        assert!(
            file.starts_with(MAGIC_SIGNED),
            "output is not a signed_tx_set"
        );
        let body = &file[MAGIC_SIGNED.len() + 1..];
        let iv = &body[..8];
        let key = crate::monero::txset::chacha_key(view_secret);
        let mut buf = body[8..].to_vec();
        ChaCha20Legacy::new(GenericArray::from_slice(&key), GenericArray::from_slice(iv))
            .apply_keystream(&mut buf);
        buf.truncate(buf.len() - 64); // drop auth sig
        buf
    }

    /// The demo fixture was built for the ORIGINAL derivation (spend =
    /// sc_reduce32(seed)); production `from_app_seed` now derives via Polyseed, so
    /// build the fixture-matching keys explicitly here. Tests the signer, not the
    /// key derivation (which has its own vector in keys.rs).
    fn fixture_keys() -> MoneroKeys {
        use curve25519_dalek::scalar::Scalar;
        let spend_secret = Scalar::from_bytes_mod_order([0x11u8; 32]);
        let view_secret =
            Scalar::from_bytes_mod_order(crate::monero::keccak256(spend_secret.as_bytes()));
        MoneroKeys {
            spend_secret,
            view_secret,
        }
    }

    #[test]
    fn build_signed_tx_set_on_fixture() {
        let keys = fixture_keys();
        let out = build_signed_tx_set(DEMO_UNSIGNED, &keys, Network::Stagenet, 20_000)
            .expect("build_signed_tx_set");

        // Framed as a wallet2 signed_tx_set.
        assert!(out.starts_with(MAGIC_SIGNED));
        assert!(
            out.len() > 1500,
            "signed set implausibly small: {}",
            out.len()
        );

        // Re-decrypts and the pending_tx header is [set_ver=0, ptx_count=1,
        // pending_tx_ver=1] exactly as wallet2 emits.
        let pt = decrypt_signed(&out, &keys.view_secret_bytes());
        assert_eq!(&pt[..3], &[0x00, 0x01, 0x01], "pending_tx header mismatch");

        // The signed set must end with the two empty key-image collections — the
        // critical fix: a non-empty key_images vec fails Cake's import.
        assert_eq!(
            &pt[pt.len() - 2..],
            &[0x00, 0x00],
            "trailing key-image vecs not empty"
        );
    }
}
