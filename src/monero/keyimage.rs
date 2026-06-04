// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! wallet2 output-import → key-image-export (the Cake "key image sync" step).
//!
//! Cake's watch-only wallet exports its outputs (`xmr-output`); the cold wallet
//! must compute the key image of each and return them (`xmr-keyimage`) before
//! Cake will build an unsigned tx. For each output:
//!   x  = Hs( 8·a·R ‖ varint(i) ) + b        (one-time secret; standard address)
//!   ki = x · Hp(P)                            (Hp = Monero hash_to_point)
//!   sig = 1-member ring signature over ki     (verifiable; deterministic nonce)
//! Key images are deterministic (matched byte-for-byte vs monero-wallet-cli);
//! signatures only need to verify.

use curve25519_dalek::{edwards::CompressedEdwardsY, edwards::EdwardsPoint, scalar::Scalar};
use monero_wallet::ed25519::Point as SeraiPoint;

use super::keys::MoneroKeys;
use super::keccak256;
use super::txset::{decrypt_with_magic, encrypt_tx_set, read_varint};

pub const MAGIC_OUTPUTS: &[u8] = b"Monero output export";
pub const MAGIC_KEY_IMAGES: &[u8] = b"Monero key image export";

#[derive(Debug)]
pub struct OutEntry {
    pub pubkey: [u8; 32],            // one-time output pubkey P
    pub tx_pubkey: [u8; 32],         // main tx pubkey R
    pub additional: Vec<[u8; 32]>,   // per-output tx pubkeys (subaddress sends)
    pub internal_idx: u64,           // output index within its tx
    pub major: u32,                  // subaddress account
    pub minor: u32,                  // subaddress index (0,0 = primary address)
}

/// Subaddress secret offset m = Hs("SubAddr\0" ‖ a ‖ major(LE) ‖ minor(LE)).
/// The subaddress spend key is (b + m)·G.
fn subaddress_secret(view: &[u8; 32], major: u32, minor: u32) -> Scalar {
    let mut data = Vec::with_capacity(48);
    data.extend_from_slice(b"SubAddr\0"); // 8 bytes incl. null terminator
    data.extend_from_slice(view);
    data.extend_from_slice(&major.to_le_bytes());
    data.extend_from_slice(&minor.to_le_bytes());
    hs(&data)
}

fn read_32(buf: &[u8], p: &mut usize) -> Option<[u8; 32]> {
    let end = p.checked_add(32)?;
    let mut a = [0u8; 32];
    a.copy_from_slice(buf.get(*p..end)?);
    *p = end;
    Some(a)
}
fn read_u32_le(buf: &[u8], p: &mut usize) -> Option<u32> {
    let end = p.checked_add(4)?;
    let mut a = [0u8; 4];
    a.copy_from_slice(buf.get(*p..end)?);
    *p = end;
    Some(u32::from_le_bytes(a))
}
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
fn hs(d: &[u8]) -> Scalar {
    Scalar::from_bytes_mod_order(keccak256(d))
}

/// Parse a decrypted wallet2 output-export plaintext: spend_pub(32) view_pub(32)
/// then a serialized tuple (size, offset, total, vec<exported_transfer_details>).
pub fn parse_output_export(pt: &[u8]) -> Option<Vec<OutEntry>> {
    if pt.len() < 64 {
        return None;
    }
    let mut p = 64usize; // skip spend_pub + view_pub
    let _tuple_size = read_varint(pt, &mut p)?; // monero tuple element count (3)
    let _offset = read_varint(pt, &mut p)?;
    let _total = read_varint(pt, &mut p)?;
    let count = read_varint(pt, &mut p)? as usize;
    if count > 4096 {
        return None;
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let _ver = read_varint(pt, &mut p)?; // VERSION_FIELD(1)
        let pubkey = read_32(pt, &mut p)?;
        let internal_idx = read_varint(pt, &mut p)?;
        let _global_idx = read_varint(pt, &mut p)?;
        let tx_pubkey = read_32(pt, &mut p)?;
        let _flags = read_u32_le(pt, &mut p)?; // FIELD(m_flags.flags) fixed u32 LE
        let _amount = read_varint(pt, &mut p)?;
        let nadd = read_varint(pt, &mut p)? as usize; // additional_tx_keys vector
        let mut additional = Vec::with_capacity(nadd);
        for _ in 0..nadd {
            additional.push(read_32(pt, &mut p)?);
        }
        let major = read_varint(pt, &mut p)? as u32;
        let minor = read_varint(pt, &mut p)? as u32;
        out.push(OutEntry { pubkey, tx_pubkey, additional, internal_idx, major, minor });
    }
    Some(out)
}

/// The output's one-time secret key x, such that x·G == P. Handles BOTH primary
/// (subaddr 0,0) and subaddress outputs:
///   x = Hs(8·a·R ‖ varint(i)) + b + m
/// where m is the subaddress offset (0 for primary) and R is the tx pubkey that
/// produced this output — the main one for primary sends, or the per-output
/// `additional_tx_keys[i]` for subaddress sends. We try both and keep the one
/// that reproduces P (so the key image is provably correct).
fn output_secret(e: &OutEntry, keys: &MoneroKeys) -> Option<Scalar> {
    let view = keys.view_secret_bytes();
    let a = Scalar::from_bytes_mod_order(view);
    let b = Scalar::from_bytes_mod_order(keys.spend_secret_bytes());
    let m = if e.major == 0 && e.minor == 0 {
        Scalar::ZERO
    } else {
        subaddress_secret(&view, e.major, e.minor)
    };

    // Candidate tx pubkeys: the main key, then this output's additional key.
    let mut candidates: Vec<[u8; 32]> = vec![e.tx_pubkey];
    if let Some(add) = e.additional.get(e.internal_idx as usize) {
        candidates.push(*add);
    }
    for rb in candidates {
        let Some(r) = CompressedEdwardsY(rb).decompress() else { continue };
        let deriv = (a * r).mul_by_cofactor(); // 8·a·R
        let mut data = deriv.compress().to_bytes().to_vec();
        write_varint(e.internal_idx, &mut data);
        let x = hs(&data) + b + m;
        if EdwardsPoint::mul_base(&x).compress().to_bytes() == e.pubkey {
            return Some(x); // x·G == P  ⇒  ki = x·Hp(P) is correct
        }
    }
    None
}

/// Key image of an output: ki = x · Hp(P), Hp = Monero hash_to_point.
pub fn key_image(e: &OutEntry, keys: &MoneroKeys) -> Option<[u8; 32]> {
    let x = output_secret(e, keys)?;
    let hp: EdwardsPoint = SeraiPoint::biased_hash(e.pubkey).into();
    Some((x * hp).compress().to_bytes())
}

/// 1-member ring signature over `ki` by the output secret `x` (deterministic
/// nonce; verifies regardless). Returns c‖r (64 bytes).
fn sign_key_image(ki: &[u8; 32], pubkey: &[u8; 32], x: &Scalar) -> [u8; 64] {
    let hp: EdwardsPoint = SeraiPoint::biased_hash(*pubkey).into();
    // deterministic nonce from (x ‖ ki)
    let mut nb = x.as_bytes().to_vec();
    nb.extend_from_slice(ki);
    let k = hs(&nb);
    let l = EdwardsPoint::mul_base(&k).compress().to_bytes();
    let r_pt = (k * hp).compress().to_bytes();
    let mut cb = Vec::with_capacity(96);
    cb.extend_from_slice(ki); // prefix = key image
    cb.extend_from_slice(&l);
    cb.extend_from_slice(&r_pt);
    let c = hs(&cb);
    let r = k - c * x;
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(c.as_bytes());
    sig[32..].copy_from_slice(r.as_bytes());
    sig
}

/// Build the encrypted wallet2 `key_image_export` from an `output_export` file.
pub fn export_key_images(output_file: &[u8], keys: &MoneroKeys) -> Option<Vec<u8>> {
    let view_secret = keys.view_secret_bytes();
    let view_pub = keys.public_view();
    let spend_pub = keys.public_spend();
    let pt = decrypt_with_magic(output_file, &view_secret, MAGIC_OUTPUTS).ok()?;
    let entries = parse_output_export(&pt)?;

    // plaintext: offset(u32 LE) spend_pub(32) view_pub(32) [ki(32) sig(64)]…
    let mut plain = Vec::with_capacity(4 + 64 + entries.len() * 96);
    plain.extend_from_slice(&0u32.to_le_bytes()); // offset 0 (export all)
    plain.extend_from_slice(&spend_pub);
    plain.extend_from_slice(&view_pub);
    for e in &entries {
        let x = output_secret(e, keys)?;
        let ki = key_image(e, keys)?;
        let sig = sign_key_image(&ki, &e.pubkey, &x);
        plain.extend_from_slice(&ki);
        plain.extend_from_slice(&sig);
    }
    let iv8 = keccak256(&plain);
    let mut iv = [0u8; 8];
    iv.copy_from_slice(&iv8[..8]);
    Some(encrypt_tx_set(&plain, &view_secret, &view_pub, MAGIC_KEY_IMAGES, 0x03, iv))
}

