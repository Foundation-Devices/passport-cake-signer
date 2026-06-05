// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! CupCake-compatible QR transport.
//!
//! Cake Wallet mobile and CupCake exchange Monero tx data as **UR (Uniform
//! Resources) animated QR codes**. The UR payload is a single CBOR bytestring
//! wrapping the raw wallet2 blob — byte-identical to what this app already
//! parses (`unsigned_tx_set`) and produces (`signed_tx_set`). So the crypto is
//! transport-agnostic; this module is only the wrapper:
//!
//!   * encode: raw signed_tx_set -> CBOR(bytes) -> `encode_qr_parts(ur_type,…)` -> infinite frame model the
//!     Slint `DynamicQrCode` cycles.
//!   * decode: scanned UR message (the scanner server already reassembled the fountain frames) -> CBOR decode
//!     -> raw unsigned_tx_set.
//!
//! UR types (match cake-tech/cupcake `lib/coins/monero/wallet.dart`):
//!   xmr-txunsigned (Cake -> Prime), xmr-txsigned (Prime -> Cake), xmr-keyimage.
//!
//! Pairing is separate: a single STATIC QR of the view-only JSON
//! (`{label, version, primaryAddress, privateViewKey, restoreHeight}`), rendered
//! straight from the string by the Slint `QrCodeCard`. See [`pair_json`].

use slint_keyos_platform::{
    qrcode,
    slint::{ModelRc, SharedString},
};

/// UR type for the signed tx we hand back to Cake.
pub const UR_TX_SIGNED: &str = "xmr-txsigned";
/// UR type for the unsigned tx Cake hands us.
pub const UR_TX_UNSIGNED: &str = "xmr-txunsigned";
/// UR type for the outputs Cake exports for the key-image sync.
pub const UR_OUTPUT: &str = "xmr-output";
/// UR type for the key images we return to Cake.
pub const UR_KEY_IMAGE: &str = "xmr-keyimage";

/// Wrap `blob` as a CBOR bytestring (the UR payload CupCake/Cake expect) and
/// return the animated UR frame model for `ur_type`. `max_size` is the per-frame
/// budget the `DynamicQrCode` density selector passes (250 / 500 / 1000).
pub fn ur_parts(ur_type: &str, blob: &[u8], max_size: i32) -> ModelRc<SharedString> {
    let bytes = minicbor::bytes::ByteVec::from(blob.to_vec());
    let ur_bytes = minicbor::to_vec(bytes).expect("cbor encode of bytestring is infallible");
    // Emit ONLY the pure (systematic) fragments as a finite, cycling list. The signed
    // tx set is ~2.5-4 KB, which cannot fit in a single QR (renderer panics with
    // DataTooLong), so it MUST be multi-part. Pure parts decode deterministically in
    // Cake's bc-ur — unlike fountain-mixed parts, which the two stacks reassemble
    // differently and which made scans drag on for minutes (or never converge).
    qrcode::encode_qr_parts_static(ur_type, ur_bytes, max_size)
}

/// Unwrap the CBOR bytestring carried by an incoming UR back to the raw blob.
/// The scanner server returns the reassembled UR *message* (CBOR) in
/// `ScanQrResult::Ur2.data`; tolerate an already-unwrapped payload too.
pub fn ur_payload(data: &[u8]) -> Vec<u8> {
    match minicbor::decode::<minicbor::bytes::ByteVec>(data) {
        Ok(bv) => bv.into(),
        Err(_) => data.to_vec(), // not CBOR-wrapped; use as-is
    }
}

/// Build the CupCake pairing JSON (`pairQrString`): the watch-only credentials
/// Cake restores from. `restore_height` of 0 means Cake rescans from genesis —
/// safe but slow; a real birthday height can be threaded in later.
pub fn pair_json(label: &str, primary_address: &str, private_view_key: &str, restore_height: u64) -> String {
    // Hand-built to guarantee field order + no em dashes; serde_json would also
    // work but this keeps the dependency surface tiny and the output stable.
    format!(
        "{{\n   \"label\": \"{label}\",\n   \"version\": 0,\n   \"primaryAddress\": \"{primary_address}\",\n   \"privateViewKey\": \"{private_view_key}\",\n   \"restoreHeight\": {restore_height}\n}}"
    )
}
