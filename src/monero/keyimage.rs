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
use monero_wallet::{
    ed25519::{CompressedPoint, Point as SeraiPoint},
    ring_signatures::RingSignature,
};

use super::keccak256;
use super::keys::{subaddress_secret, MoneroKeys};
use super::txset::{decrypt_with_magic, encrypt_tx_set, read_varint};

pub const MAGIC_OUTPUTS: &[u8] = b"Monero output export";
pub const MAGIC_KEY_IMAGES: &[u8] = b"Monero key image export";
const MAX_OUTPUT_EXPORT_ENTRIES: usize = 4_096;
const MAX_ADDITIONAL_TX_KEYS: usize = 256;

#[derive(Debug, Clone)]
pub struct OutEntry {
    pub pubkey: [u8; 32],          // one-time output pubkey P
    pub tx_pubkey: [u8; 32],       // main tx pubkey R
    pub additional: Vec<[u8; 32]>, // per-output tx pubkeys (subaddress sends)
    pub internal_idx: u64,         // output index within its tx
    pub major: u32,                // subaddress account
    pub minor: u32,                // subaddress index (0,0 = primary address)
}

#[derive(Debug, Clone)]
pub struct OutputExport {
    pub offset: u32,
    pub total: u32,
    pub entries: Vec<OutEntry>,
}

fn read_32(buf: &[u8], p: &mut usize) -> Option<[u8; 32]> {
    let end = p.checked_add(32)?;
    let mut a = [0u8; 32];
    a.copy_from_slice(buf.get(*p..end)?);
    *p = end;
    Some(a)
}
fn read_u8(buf: &[u8], p: &mut usize) -> Option<u8> {
    let b = *buf.get(*p)?;
    *p = p.checked_add(1)?;
    Some(b)
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
fn hs(d: &[u8]) -> Scalar { Scalar::from_bytes_mod_order(keccak256(d)) }

/// Parse a decrypted wallet2 output-export plaintext: spend_pub(32) view_pub(32)
/// then a serialized tuple (size, offset, total, vec<exported_transfer_details>).
pub fn parse_output_export(pt: &[u8]) -> Option<OutputExport> {
    if pt.len() < 64 {
        return None;
    }
    let mut p = 64usize; // skip spend_pub + view_pub
    let _tuple_size = read_varint(pt, &mut p)?; // monero tuple element count (3)
    let offset = read_varint(pt, &mut p)?;
    if offset > u32::MAX as u64 {
        return None;
    }
    let total = read_varint(pt, &mut p)?;
    if total > u32::MAX as u64 {
        return None;
    }
    let count = read_varint(pt, &mut p)? as usize;
    if count > MAX_OUTPUT_EXPORT_ENTRIES {
        return None;
    }
    if count > 0 && offset.saturating_add(count as u64) > total {
        return None;
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let _ver = read_varint(pt, &mut p)?; // VERSION_FIELD(1)
        let pubkey = read_32(pt, &mut p)?;
        let internal_idx = read_varint(pt, &mut p)?;
        let _global_idx = read_varint(pt, &mut p)?;
        let tx_pubkey = read_32(pt, &mut p)?;
        let _flags = read_u8(pt, &mut p)?; // FIELD(m_flags.flags), uint8_t
        let _amount = read_varint(pt, &mut p)?;
        let nadd = read_varint(pt, &mut p)? as usize; // additional_tx_keys vector
        if nadd > MAX_ADDITIONAL_TX_KEYS {
            return None;
        }
        let mut additional = Vec::with_capacity(nadd);
        for _ in 0..nadd {
            additional.push(read_32(pt, &mut p)?);
        }
        let major = read_varint(pt, &mut p)? as u32;
        let minor = read_varint(pt, &mut p)? as u32;
        out.push(OutEntry { pubkey, tx_pubkey, additional, internal_idx, major, minor });
    }
    if p != pt.len() {
        log::warn!(
            "output export parse left {} trailing bytes after {} entries",
            pt.len().saturating_sub(p),
            count
        );
        return None;
    }
    Some(OutputExport { offset: offset as u32, total: total as u32, entries: out })
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
    let m =
        if e.major == 0 && e.minor == 0 { Scalar::ZERO } else { subaddress_secret(&view, e.major, e.minor) };

    // Candidate tx pubkeys: the main key, then this output's additional key.
    let mut candidates: Vec<[u8; 32]> = vec![e.tx_pubkey];
    if let Some(add) = e.additional.get(e.internal_idx as usize) {
        candidates.push(*add);
    }
    for rb in candidates {
        let Some(r) = CompressedEdwardsY(rb).decompress() else {
            continue;
        };
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

fn verify_key_image_signature(ki: &[u8; 32], pubkey: &[u8; 32], sig: &[u8; 64]) -> bool {
    let mut sig_reader = &sig[..];
    let Ok(signature) = RingSignature::read(1, &mut sig_reader) else {
        return false;
    };
    sig_reader.is_empty()
        && signature.verify(ki, &[CompressedPoint::from(*pubkey)], &CompressedPoint::from(*ki))
}

pub fn parse_output_export_file(output_file: &[u8], keys: &MoneroKeys) -> Option<OutputExport> {
    let view_secret = keys.view_secret_bytes();
    let pt = decrypt_with_magic(output_file, &view_secret, MAGIC_OUTPUTS).ok()?;
    parse_output_export(&pt)
}

/// Build the encrypted wallet2 `key_image_export` from parsed output-export data.
pub fn build_key_image_export(export: &OutputExport, keys: &MoneroKeys) -> Option<Vec<u8>> {
    let view_secret = keys.view_secret_bytes();
    let view_pub = keys.public_view();
    let spend_pub = keys.public_spend();
    // plaintext: offset(u32 LE) spend_pub(32) view_pub(32) [ki(32) sig(64)]…
    let mut plain = Vec::with_capacity(4 + 64 + export.entries.len() * 96);
    plain.extend_from_slice(&export.offset.to_le_bytes());
    plain.extend_from_slice(&spend_pub);
    plain.extend_from_slice(&view_pub);
    for e in &export.entries {
        let x = output_secret(e, keys)?;
        let ki = key_image(e, keys)?;
        let sig = sign_key_image(&ki, &e.pubkey, &x);
        if !verify_key_image_signature(&ki, &e.pubkey, &sig) {
            log::warn!(
                "generated key-image signature failed self-check: output={}, key_image={}",
                hex::encode(e.pubkey),
                hex::encode(ki)
            );
            return None;
        }
        plain.extend_from_slice(&ki);
        plain.extend_from_slice(&sig);
    }
    let iv8 = keccak256(&plain);
    let mut iv = [0u8; 8];
    iv.copy_from_slice(&iv8[..8]);
    Some(encrypt_tx_set(&plain, &view_secret, &view_pub, MAGIC_KEY_IMAGES, 0x03, iv))
}

/// Build the encrypted wallet2 `key_image_export` from an `output_export` file.
pub fn export_key_images(output_file: &[u8], keys: &MoneroKeys) -> Option<Vec<u8>> {
    let export = parse_output_export_file(output_file, keys)?;
    build_key_image_export(&export, keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn decode_hex<const N: usize>(s: &str) -> [u8; N] {
        fn nibble(b: u8) -> u8 {
            match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => panic!("invalid hex"),
            }
        }
        assert_eq!(s.len(), N * 2);
        let mut out = [0u8; N];
        for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
            out[i] = (nibble(chunk[0]) << 4) | nibble(chunk[1]);
        }
        out
    }

    fn verify_local_ring_signature(ki: &[u8; 32], pubkey: &[u8; 32], sig: &[u8; 64]) -> bool {
        let Some(p) = CompressedEdwardsY(*pubkey).decompress() else {
            return false;
        };
        let Some(ki_pt) = CompressedEdwardsY(*ki).decompress() else {
            return false;
        };
        let hp: EdwardsPoint = SeraiPoint::biased_hash(*pubkey).into();
        let mut cb = [0u8; 32];
        let mut rb = [0u8; 32];
        cb.copy_from_slice(&sig[..32]);
        rb.copy_from_slice(&sig[32..]);
        let c = Scalar::from_bytes_mod_order(cb);
        let r = Scalar::from_bytes_mod_order(rb);
        let l = EdwardsPoint::vartime_double_scalar_mul_basepoint(&c, &p, &r).compress().to_bytes();
        let rr = (r * hp + c * ki_pt).compress().to_bytes();
        let mut h = Vec::new();
        h.extend_from_slice(ki);
        h.extend_from_slice(&l);
        h.extend_from_slice(&rr);
        hs(&h) == c
    }

    #[test]
    fn cake_reported_key_image_signature_was_for_a_different_pubkey() {
        let ki = decode_hex::<32>("3f9671913bc534f3fbb7e4bdf8d2f20624e5cd6d789ec337cdedd5ad2b8a142b");
        let sig = decode_hex::<64>(
            "2f2f17ce3bd4628777ac64ba8b410b76f041dc68789b81e7399c991c06605a09\
             d511c781e6df0cd04d6bea54c50246accb031868b16d6fb7b89ec77485d3de02",
        );
        let pubkey = decode_hex::<32>("b989789e6004b41dce5f1c89cff4d53ab4e590cddcadb441d34f0a11ecb53f6c");
        assert!(!verify_local_ring_signature(&ki, &pubkey, &sig));
        assert!(!verify_key_image_signature(&ki, &pubkey, &sig));
    }

    fn synthetic_output_export(keys: &MoneroKeys, offset: u64, internal_idx: u64) -> (Vec<u8>, [u8; 32]) {
        let view_secret = keys.view_secret_bytes();
        let view_pub = keys.public_view();
        let spend_pub = keys.public_spend();
        let view_scalar = Scalar::from_bytes_mod_order(view_secret);
        let spend_scalar = Scalar::from_bytes_mod_order(keys.spend_secret_bytes());

        let mut r_bytes = [0u8; 32];
        r_bytes[0] = 7;
        let tx_secret = Scalar::from_bytes_mod_order(r_bytes);
        let tx_pubkey = EdwardsPoint::mul_base(&tx_secret).compress().to_bytes();

        let derivation = (view_scalar * EdwardsPoint::mul_base(&tx_secret)).mul_by_cofactor();
        let mut data = derivation.compress().to_bytes().to_vec();
        write_varint(internal_idx, &mut data);
        let output_secret = hs(&data) + spend_scalar;
        let output_pubkey = EdwardsPoint::mul_base(&output_secret).compress().to_bytes();

        let mut output_plain = Vec::new();
        output_plain.extend_from_slice(&spend_pub);
        output_plain.extend_from_slice(&view_pub);
        write_varint(3, &mut output_plain); // tuple fields: offset, total, entries
        write_varint(offset, &mut output_plain);
        write_varint(offset + 1, &mut output_plain);
        write_varint(1, &mut output_plain); // one exported_transfer_details entry
        write_varint(1, &mut output_plain); // VERSION_FIELD(1)
        output_plain.extend_from_slice(&output_pubkey);
        write_varint(internal_idx, &mut output_plain);
        write_varint(12345, &mut output_plain); // global output index
        output_plain.extend_from_slice(&tx_pubkey);
        output_plain.push(0); // FIELD(m_flags.flags), uint8_t
        write_varint(0, &mut output_plain); // amount
        write_varint(0, &mut output_plain); // additional_tx_keys count
        write_varint(0, &mut output_plain); // subaddress account
        write_varint(0, &mut output_plain); // subaddress index

        let mut iv = [0u8; 8];
        iv.copy_from_slice(&keccak256(&output_plain)[..8]);
        (encrypt_tx_set(&output_plain, &view_secret, &view_pub, MAGIC_OUTPUTS, 0x04, iv), output_pubkey)
    }

    #[test]
    fn key_image_export_preserves_output_offset() {
        let keys = MoneroKeys::from_app_seed(&[0x22; 32]);
        let view_secret = keys.view_secret_bytes();
        let view_pub = keys.public_view();
        let spend_pub = keys.public_spend();
        let mut output_plain = Vec::new();
        output_plain.extend_from_slice(&spend_pub);
        output_plain.extend_from_slice(&view_pub);
        write_varint(3, &mut output_plain); // tuple fields: offset, total, entries
        write_varint(17, &mut output_plain);
        write_varint(17, &mut output_plain);
        write_varint(0, &mut output_plain);
        let mut iv = [0u8; 8];
        iv.copy_from_slice(&keccak256(&output_plain)[..8]);
        let output_file = encrypt_tx_set(&output_plain, &view_secret, &view_pub, MAGIC_OUTPUTS, 0x04, iv);

        let key_image_file = export_key_images(&output_file, &keys).expect("key images");
        let key_image_plain =
            decrypt_with_magic(&key_image_file, &view_secret, MAGIC_KEY_IMAGES).expect("decrypt key images");

        assert_eq!(u32::from_le_bytes(key_image_plain[0..4].try_into().unwrap()), 17);
        assert_eq!(&key_image_plain[4..36], &spend_pub);
        assert_eq!(&key_image_plain[36..68], &view_pub);
        assert_eq!(key_image_plain.len(), 68);
    }

    #[test]
    fn key_image_export_parses_one_byte_transfer_flags_and_valid_signature() {
        let keys = MoneroKeys::from_app_seed(&[0x33; 32]);
        let view_secret = keys.view_secret_bytes();
        let (output_file, output_pubkey) = synthetic_output_export(&keys, 29, 0);

        let key_image_file = export_key_images(&output_file, &keys).expect("key images");
        let key_image_plain =
            decrypt_with_magic(&key_image_file, &view_secret, MAGIC_KEY_IMAGES).expect("decrypt key images");

        assert_eq!(u32::from_le_bytes(key_image_plain[0..4].try_into().unwrap()), 29);
        assert_eq!(key_image_plain.len(), 68 + 96);

        let mut key_image = [0u8; 32];
        key_image.copy_from_slice(&key_image_plain[68..100]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&key_image_plain[100..164]);
        assert!(verify_local_ring_signature(&key_image, &output_pubkey, &signature));
        assert!(verify_key_image_signature(&key_image, &output_pubkey, &signature));
    }
}
