// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! wallet2 `unsigned_tx_set` decode + signed/key-image encode.
//!
//! Decode (decryption) is VERIFIED against a real stagenet fixture in the host
//! crate `monero-cold-core` (`txset::tests`). The same logic is inlined here:
//!
//!   "Monero unsigned tx set" || ver || iv(8) || chacha20_ct || authsig(64)
//!   chacha key = cryptonight_hash_v0(view_secret) (cn_slow_hash v0, kdf_rounds 1)
//!   amounts are LEB128 varints; addresses are spend_pub(32)||view_pub(32).
//!
//! cn_slow_hash needs CryptoNight; we use the vendored no_std `cryptonight-noxous`
//! (byte-for-byte parity with cuprate-cryptonight), so decryption runs on the
//! device too, not just host/sim.

use std::sync::Mutex;

use super::{Error, Network, Result, TxSummary};

pub const MAGIC_UNSIGNED: &[u8] = b"Monero unsigned tx set";
pub const MAGIC_SIGNED: &[u8] = b"Monero signed tx set";
pub const MAGIC_OUTPUTS: &[u8] = b"Monero output export";
pub const MAGIC_KEY_IMAGES: &[u8] = b"Monero key image export";

/// wallet2 derives the chacha file key as `cn_slow_hash_v0(view_secret)` with
/// kdf_rounds = 1. CryptoNight is memory-hard and there is no AES hardware on the
/// Cortex-A5, so this costs several seconds in software — and the input (the wallet
/// view secret) never changes. Memoize it so only the FIRST decrypt/encrypt in a
/// session pays the cost; the key-image sync, unsigned-tx review, and signing after
/// it are instant. Call `warm_chacha_key` once at startup to absorb even that first
/// hit while the user is still navigating.
static CHACHA_KEY_CACHE: Mutex<Option<([u8; 32], [u8; 32])>> = Mutex::new(None);

/// Memoized `cn_slow_hash_v0(view_secret)` → 32-byte chacha key.
pub fn chacha_key(view_secret: &[u8; 32]) -> [u8; 32] {
    {
        let guard = CHACHA_KEY_CACHE.lock().unwrap();
        if let Some((vs, k)) = guard.as_ref() {
            if vs == view_secret {
                return *k;
            }
        }
    }
    let k = cryptonight_noxous::cryptonight_hash_v0(view_secret);
    *CHACHA_KEY_CACHE.lock().unwrap() = Some((*view_secret, k));
    k
}

/// Precompute and cache the chacha key (call from a background thread at launch).
pub fn warm_chacha_key(view_secret: &[u8; 32]) { let _ = chacha_key(view_secret); }

/// A parsed unsigned tx set, holding the review summary.
pub struct UnsignedTxSet {
    pub network: Network,
    summary: TxSummary,
}

impl UnsignedTxSet {
    /// Decrypt + summarize a wallet2 `unsigned_tx_set` (simulator/host path).
    pub fn parse(
        file: &[u8],
        view_secret: &[u8; 32],
        spend_pub: &[u8; 32],
        network: Network,
    ) -> Result<Self> {
        let pt = decrypt(file, view_secret)?;
        // STRUCTURAL recipients from `dests` (excludes change). This is what the
        // user must see + verify before signing — the old self-pubkey scan showed
        // the wrong recipient (and amount 0) for any external send.
        let spans = parse_construction_data(&pt).ok_or_else(|| Error::Parse("construction_data".into()))?;
        let recipients =
            parse_dest_entries(&pt, spans.dests).ok_or_else(|| Error::Parse("destinations".into()))?;
        if recipients.is_empty() {
            return Err(Error::Parse("no destinations found in unsigned tx set".into()));
        }
        let sent: u64 = recipients.iter().map(|d| d.amount).sum();
        let change = change_amount(&pt, spend_pub);
        let total_in: u64 = parse_sources(&pt).map(|s| s.iter().map(|x| x.amount).sum()).unwrap_or(0);
        let fee = total_in.saturating_sub(sent.saturating_add(change));
        // Display the address Cake/wallet2 carried in `original` when present
        // (covers integrated addresses too). If a fixture omits it, synthesize
        // from the structural keys and the destination type bit.
        let addrs: Vec<String> = recipients
            .iter()
            .map(|d| {
                if !d.original.is_empty() {
                    d.original.clone()
                } else if d.is_subaddress {
                    super::address::subaddress_address(network, &d.spend_pub, &d.view_pub)
                } else {
                    super::address::primary_address(network, &d.spend_pub, &d.view_pub)
                }
            })
            .collect();
        let destination_amounts_atomic = recipients.iter().map(|d| d.amount).collect();
        let summary = TxSummary {
            network,
            amount_atomic: sent,
            change_atomic: change,
            fee_atomic: fee,
            destinations: addrs,
            destination_amounts_atomic,
            subaddr_account: spans.subaddr_account,
            subaddr_indices: spans.subaddr_indices,
            // On-chain outputs = recipients + the change output (when there is change).
            // wallet2 always emits a change output unless change is exactly 0, so a
            // normal send shows 2 here (one to the recipient, one back to us).
            output_count: recipients.len() + if change > 0 { 1 } else { 0 },
        };
        Ok(Self { network, summary })
    }

    pub fn summary(&self) -> &TxSummary { &self.summary }
}

// ---------------------------------------------------------------------------
// Host/sim decode internals
// ---------------------------------------------------------------------------

pub struct Destination {
    pub amount: u64,
    pub spend_pub: [u8; 32],
    pub view_pub: [u8; 32],
}

/// Decrypt a wallet2 `unsigned_tx_set` (default magic).
pub fn decrypt(file: &[u8], view_secret: &[u8; 32]) -> Result<Vec<u8>> {
    decrypt_with_magic(file, view_secret, MAGIC_UNSIGNED)
}

/// Decrypt any wallet2 chacha-framed export (unsigned tx, outputs, key images)
/// for the given magic. Bounds-checked + auth-signature-verified.
pub fn decrypt_with_magic(file: &[u8], view_secret: &[u8; 32], magic: &[u8]) -> Result<Vec<u8>> {
    use chacha20::cipher::generic_array::GenericArray;
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    use chacha20::ChaCha20Legacy;
    use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};

    const AUTH_SIG_LEN: usize = 64;
    if !file.starts_with(magic) {
        return Err(Error::Parse("not a Monero unsigned tx set (bad magic)".into()));
    }
    // Bounds: need magic + version byte + iv(8) + sig(64). Guards a magic-only file.
    if file.len() <= magic.len() {
        return Err(Error::Parse("unsigned tx set too short".into()));
    }
    let body = &file[magic.len() + 1..]; // skip magic + version byte
    if body.len() < 8 + AUTH_SIG_LEN {
        return Err(Error::Parse("unsigned tx set too short".into()));
    }

    // The 64-byte signature is appended in the clear after `iv ‖ ciphertext`.
    // Verify it (the file must come from the paired view key) before decrypting.
    let sig_start = body.len() - AUTH_SIG_LEN;
    let blob = &body[..sig_start]; // iv ‖ ciphertext
    let mut sig = [0u8; AUTH_SIG_LEN];
    sig.copy_from_slice(&body[sig_start..]);
    let view_pub = EdwardsPoint::mul_base(&Scalar::from_bytes_mod_order(*view_secret)).compress().to_bytes();
    let hash = super::keccak256(blob);
    if !verify_signature(&hash, &view_pub, &sig) {
        return Err(Error::Parse("tx set authentication signature invalid".into()));
    }

    let iv = &blob[..8];
    let key = chacha_key(view_secret);
    let mut buf = blob[8..].to_vec(); // ciphertext only (sig already separated)
    ChaCha20Legacy::new(GenericArray::from_slice(&key), GenericArray::from_slice(iv))
        .apply_keystream(&mut buf);
    Ok(buf)
}

/// Verify Monero `generate_signature`: comm = r·G + c·pubk; accept iff
/// Hs(prefix ‖ pubk ‖ comm) == c.
fn verify_signature(prefix_hash: &[u8; 32], pubk: &[u8; 32], sig: &[u8; 64]) -> bool {
    use curve25519_dalek::{edwards::CompressedEdwardsY, edwards::EdwardsPoint, scalar::Scalar};
    let Some(pub_point) = CompressedEdwardsY(*pubk).decompress() else { return false };
    let mut cb = [0u8; 32];
    let mut rb = [0u8; 32];
    cb.copy_from_slice(&sig[..32]);
    rb.copy_from_slice(&sig[32..]);
    let c = Scalar::from_bytes_mod_order(cb);
    let r = Scalar::from_bytes_mod_order(rb);
    let comm = (EdwardsPoint::mul_base(&r) + c * pub_point).compress().to_bytes();
    let mut buf = Vec::with_capacity(96);
    buf.extend_from_slice(prefix_hash);
    buf.extend_from_slice(pubk);
    buf.extend_from_slice(&comm);
    let c_prime = Scalar::from_bytes_mod_order(super::keccak256(&buf));
    c_prime == c
}

/// Scan for `varint(amount) || spend_pub(32) || view_pub(32)` destination
/// entries belonging to this wallet. First pass (enough for the review screen);
/// a full tx_construction_data walk to split change + compute fee is next.
/// Amount of `change_dts` (change returned to this wallet). It is serialized
/// before `splitted_dsts`/`dests`, and `sources` never carry the bare wallet
/// spend pubkey, so the FIRST occurrence of `wallet_spend_pub` is the change
/// output. Returns 0 when there is no change.
pub fn change_amount(pt: &[u8], wallet_spend_pub: &[u8; 32]) -> u64 {
    let mut i = 0usize;
    while i + 32 <= pt.len() {
        if &pt[i..i + 32] == wallet_spend_pub.as_slice() {
            if let Some(amount) = read_varint_backwards(pt, i) {
                return amount;
            }
        }
        i += 1;
    }
    0
}

pub fn scan_destinations(pt: &[u8], wallet_spend_pub: &[u8; 32]) -> Vec<Destination> {
    let mut out: Vec<Destination> = Vec::new();
    let mut i = 0usize;
    while i + 64 <= pt.len() {
        if &pt[i..i + 32] == wallet_spend_pub.as_slice() {
            if let Some(amount) = read_varint_backwards(pt, i) {
                let mut spend = [0u8; 32];
                let mut view = [0u8; 32];
                spend.copy_from_slice(&pt[i..i + 32]);
                view.copy_from_slice(&pt[i + 32..i + 64]);
                // The same output appears in several arrays (dests, splitted_dsts,
                // change_dts), so collapse identical (amount,address) entries.
                let dup =
                    out.iter().any(|d| d.amount == amount && d.spend_pub == spend && d.view_pub == view);
                if !dup {
                    out.push(Destination { amount, spend_pub: spend, view_pub: view });
                }
                i += 64;
                continue;
            }
        }
        i += 1;
    }
    out
}

pub fn read_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let b = *buf.get(*pos)?;
        *pos += 1;
        value |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
}

fn read_varint_backwards(buf: &[u8], addr_pos: usize) -> Option<u64> {
    if addr_pos == 0 {
        return None;
    }
    let mut start = addr_pos - 1;
    while start > 0 && buf[start - 1] & 0x80 != 0 {
        start -= 1;
    }
    let mut pos = start;
    let value = read_varint(buf, &mut pos)?;
    if pos == addr_pos {
        Some(value)
    } else {
        None
    }
}

// --- tx_source_entry parsing (inputs) — mirrors monero-cold-core::txset ------
// One spent input, carrying the ring + the data the signer needs. Kept in sync
// with the host-tested ../../../monero-cold-core/src/txset.rs.

/// One ring member: absolute global output index + ctkey (output key + commitment).
#[derive(Clone)]
pub struct RingMember {
    pub global_index: u64,
    pub dest: [u8; 32],
    pub commitment: [u8; 32],
}

/// A parsed input (`tx_source_entry`): ring, real-output position, and the data
/// to derive the one-time key + recover the amount/mask for signing.
#[derive(Clone)]
pub struct ParsedSource {
    pub ring: Vec<RingMember>,
    pub real_output: u64,
    pub real_out_tx_key: [u8; 32],
    pub real_out_additional_tx_keys: Vec<[u8; 32]>,
    pub real_output_in_tx_index: u64,
    pub amount: u64,
    pub mask: [u8; 32],
}

// Bytes consumed by a `rct::multisig_kLRki` in a non-multisig source (4 keys).
// VERIFIED in monero-cold-core: the 129th byte belongs to the following
// `change_dts.original` string, so the source ends after exactly 128.
const MULTISIG_KLRKI_LEN: usize = 128;

fn read_u64_le(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let end = pos.checked_add(8)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(buf.get(*pos..end)?);
    *pos = end;
    Some(u64::from_le_bytes(a))
}

fn read_32(buf: &[u8], pos: &mut usize) -> Option<[u8; 32]> {
    let end = pos.checked_add(32)?;
    let mut a = [0u8; 32];
    a.copy_from_slice(buf.get(*pos..end)?);
    *pos = end;
    Some(a)
}

fn parse_source(buf: &[u8], pos: &mut usize) -> Option<ParsedSource> {
    let count = read_varint(buf, pos)? as usize;
    if count == 0 || count > 256 {
        return None;
    }
    let mut ring = Vec::with_capacity(count);
    for _ in 0..count {
        let _lead = *buf.get(*pos)?; // constant 0x02 element tag
        *pos += 1;
        let global_index = read_varint(buf, pos)?;
        let dest = read_32(buf, pos)?;
        let commitment = read_32(buf, pos)?;
        ring.push(RingMember { global_index, dest, commitment });
    }
    let real_output = read_u64_le(buf, pos)?;
    let real_out_tx_key = read_32(buf, pos)?;
    let add = read_varint(buf, pos)? as usize;
    let mut real_out_additional_tx_keys = Vec::with_capacity(add);
    for _ in 0..add {
        real_out_additional_tx_keys.push(read_32(buf, pos)?);
    }
    let real_output_in_tx_index = read_u64_le(buf, pos)?;
    let amount = read_u64_le(buf, pos)?;
    *pos += 1; // rct bool
    let mask = read_32(buf, pos)?;
    *pos = pos.checked_add(MULTISIG_KLRKI_LEN)?;
    Some(ParsedSource {
        ring,
        real_output,
        real_out_tx_key,
        real_out_additional_tx_keys,
        real_output_in_tx_index,
        amount,
        mask,
    })
}

/// Parse the `sources` vector of the first `tx_construction_data`.
pub fn parse_sources(plaintext: &[u8]) -> Option<Vec<ParsedSource>> {
    let mut p = 0usize;
    read_varint(plaintext, &mut p)?; // version
    if read_varint(plaintext, &mut p)? == 0 {
        return None; // txes count
    }
    let n = read_varint(plaintext, &mut p)? as usize;
    if n == 0 || n > 256 {
        return None;
    }
    let mut sources = Vec::with_capacity(n);
    for _ in 0..n {
        sources.push(parse_source(plaintext, &mut p)?);
    }
    Some(sources)
}

// ---------------------------------------------------------------------------
// Encode side — wallet2 signed_tx_set packaging.
// VERIFIED in monero-cold-core (tests/from_scratch.rs): the assembled
// signed_tx_set loads into a real wallet2 watch-only wallet and the tx relays on
// stagenet. Inlined here for the simulator/host path; xous-gated like decode.
// ---------------------------------------------------------------------------

/// Monero `generate_signature(prefix_hash, pub, sec)` — the Schnorr signature
/// wallet2 appends to authenticated chacha blobs (and verifies on load).
///   k (nonce), comm = k·G, c = Hs(prefix_hash ‖ pub ‖ comm), r = k − c·sec
/// Returns c‖r (64 bytes). Nonce is derived deterministically (no random source
/// needed); the signature is valid regardless of nonce choice.
fn generate_signature(
    prefix_hash: &[u8; 32],
    pubk: &[u8; 32],
    sec: &curve25519_dalek::scalar::Scalar,
) -> [u8; 64] {
    use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};
    let hs = |d: &[u8]| Scalar::from_bytes_mod_order(super::keccak256(d));
    let mut nbuf = sec.as_bytes().to_vec();
    nbuf.extend_from_slice(prefix_hash);
    let k = hs(&nbuf);
    let comm = EdwardsPoint::mul_base(&k).compress().to_bytes();
    let mut cbuf = Vec::with_capacity(96);
    cbuf.extend_from_slice(prefix_hash);
    cbuf.extend_from_slice(pubk);
    cbuf.extend_from_slice(&comm);
    let c = hs(&cbuf);
    let r = k - c * sec;
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(c.as_bytes());
    sig[32..].copy_from_slice(r.as_bytes());
    sig
}

/// Encrypt + frame a tx set the way wallet2 does (inverse of [`decrypt`]):
///   `magic ‖ version ‖ iv(8) ‖ chacha20(pt) ‖ sig(64)`.
/// `view_secret` is the wallet view key; `view_pub` its public point.
pub fn encrypt_tx_set(
    plaintext: &[u8],
    view_secret: &[u8; 32],
    view_pub: &[u8; 32],
    magic: &[u8],
    version: u8,
    iv: [u8; 8],
) -> Vec<u8> {
    use chacha20::cipher::generic_array::GenericArray;
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    use chacha20::ChaCha20Legacy;
    use curve25519_dalek::scalar::Scalar;

    let key = chacha_key(view_secret);
    let mut body = plaintext.to_vec();
    ChaCha20Legacy::new(GenericArray::from_slice(&key), GenericArray::from_slice(&iv))
        .apply_keystream(&mut body);

    // blob (for the auth hash) = iv ‖ ciphertext-body
    let mut blob = Vec::with_capacity(8 + body.len() + 64);
    blob.extend_from_slice(&iv);
    blob.extend_from_slice(&body);
    let hash = super::keccak256(&blob); // cn_fast_hash = keccak256
    let sec = Scalar::from_bytes_mod_order(*view_secret);
    let sig = generate_signature(&hash, view_pub, &sec);

    let mut out = Vec::with_capacity(magic.len() + 1 + blob.len() + 64);
    out.extend_from_slice(magic);
    out.push(version);
    out.extend_from_slice(&blob);
    out.extend_from_slice(&sig);
    out
}

/// Byte spans (start,end) of the fields a signed `pending_tx` copies verbatim from
/// the first `tx_construction_data`, plus the full construction-data span.
#[derive(Debug, Clone)]
pub struct CdataSpans {
    pub cdata: (usize, usize),
    pub change_dts: (usize, usize),
    pub selected_transfers: (usize, usize),
    pub dests: (usize, usize),
    pub subaddr_account: u32,
    pub subaddr_indices: Vec<u32>,
}

fn skip_dest(b: &[u8], p: &mut usize) -> Option<()> {
    // tx_destination_entry: original(varint len+str) amount(varint) addr(64)
    //                        is_subaddress(1) is_integrated(1)
    let ol = read_varint(b, p)? as usize;
    *p = p.checked_add(ol)?;
    read_varint(b, p)?; // amount
    *p = p.checked_add(64 + 2)?;
    if *p > b.len() {
        return None;
    }
    Some(())
}

/// Parse the first `tx_construction_data` and return the spans of the fields the
/// `signed_tx_set` reuses. Layout (wallet2.h): sources, change_dts, splitted_dsts,
/// selected_transfers, extra, unlock_time(u64-LE), construction_flags(1),
/// rct_config(version+2 varints), dests, subaddr_account, subaddr_indices.
pub fn parse_construction_data(pt: &[u8]) -> Option<CdataSpans> {
    let mut p = 0usize;
    read_varint(pt, &mut p)?; // set version
    read_varint(pt, &mut p)?; // txes count
    let cdata_start = p;
    // sources
    let nsrc = read_varint(pt, &mut p)? as usize;
    for _ in 0..nsrc {
        parse_source(pt, &mut p)?;
    }
    // change_dts
    let cd_s = p;
    skip_dest(pt, &mut p)?;
    let change_dts = (cd_s, p);
    // splitted_dsts
    let nsd = read_varint(pt, &mut p)? as usize;
    for _ in 0..nsd {
        skip_dest(pt, &mut p)?;
    }
    // selected_transfers (vec<size_t> as varints)
    let st_s = p;
    let nst = read_varint(pt, &mut p)? as usize;
    for _ in 0..nst {
        read_varint(pt, &mut p)?;
    }
    let selected_transfers = (st_s, p);
    // extra
    let ex = read_varint(pt, &mut p)? as usize;
    p = p.checked_add(ex)?;
    // unlock_time (8-byte LE)
    p = p.checked_add(8)?;
    // construction_flags (1)
    p = p.checked_add(1)?;
    // rct_config: version + range_proof_type + bp_version
    read_varint(pt, &mut p)?;
    read_varint(pt, &mut p)?;
    read_varint(pt, &mut p)?;
    // dests
    let de_s = p;
    let nd = read_varint(pt, &mut p)? as usize;
    for _ in 0..nd {
        skip_dest(pt, &mut p)?;
    }
    let dests = (de_s, p);
    // subaddr_account: wallet2 declares FIELD(subaddr_account) on a uint32_t, which in
    // binary_archive is a FIXED 4-byte little-endian int (NOT a varint). Reading it as a
    // varint drops 3 bytes whenever the account byte is < 0x80, truncating the cdata span
    // and making wallet2 reject the whole signed_tx_set ("Failed to deserialize").
    let account_end = p.checked_add(4)?;
    let mut account = [0u8; 4];
    account.copy_from_slice(pt.get(p..account_end)?);
    let subaddr_account = u32::from_le_bytes(account);
    p = account_end;
    // subaddr_indices (set<uint32_t>: count varint + each element varint)
    let nsi = read_varint(pt, &mut p)? as usize;
    if nsi > 4096 {
        return None;
    }
    let mut subaddr_indices = Vec::with_capacity(nsi);
    for _ in 0..nsi {
        subaddr_indices.push(read_varint(pt, &mut p)? as u32);
    }
    if p > pt.len() {
        return None;
    }
    Some(CdataSpans {
        cdata: (cdata_start, p),
        change_dts,
        selected_transfers,
        dests,
        subaddr_account,
        subaddr_indices,
    })
}

/// A structurally-parsed `tx_destination_entry` (a real recipient).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestEntry {
    pub amount: u64,
    pub spend_pub: [u8; 32],
    pub view_pub: [u8; 32],
    pub is_subaddress: bool,
    pub is_integrated: bool,
    pub original: String,
}

/// Structurally parse a `dests` span (count varint + entries). Unlike
/// [`scan_destinations`], this returns EXTERNAL recipients (addresses that differ
/// from this wallet), required for any non-self-send. `dests` holds the user's
/// recipients only (change is separate), so every entry is a real payment.
pub fn parse_dest_entries(pt: &[u8], span: (usize, usize)) -> Option<Vec<DestEntry>> {
    let mut p = span.0;
    let n = read_varint(pt, &mut p)? as usize;
    if n > 256 {
        return None;
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        // original(varint len+str) amount(varint) addr(spend32+view32)
        //   is_subaddress(1) is_integrated(1)
        let ol = read_varint(pt, &mut p)? as usize;
        let original_end = p.checked_add(ol)?;
        let original = String::from_utf8_lossy(pt.get(p..original_end)?).into_owned();
        p = original_end;
        let amount = read_varint(pt, &mut p)?;
        let spend_pub = read_32(pt, &mut p)?;
        let view_pub = read_32(pt, &mut p)?;
        let is_subaddress = *pt.get(p)? != 0;
        p += 1;
        let is_integrated = *pt.get(p)? != 0;
        p += 1;
        if p > span.1 {
            return None;
        }
        out.push(DestEntry { amount, spend_pub, view_pub, is_subaddress, is_integrated, original });
    }
    Some(out)
}

/// Encode a wallet2 key-image export blob for the watch-only wallet. Not yet
/// wired (the signed_tx_set already marks inputs spent via `selected_transfers`,
/// so key-image export is only needed for incremental refresh). TODO.
pub fn encode_key_images(_images: &[([u8; 32], [u8; 64])], _view_key_hex: &str) -> Result<Vec<u8>> {
    Err(Error::Unsupported("key image export encode not implemented yet".into()))
}
