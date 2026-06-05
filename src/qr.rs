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

use serde::Serialize;
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

const MIN_UR_FRAGMENT_BYTES: i32 = 120;
const MAX_UR_FRAGMENT_BYTES: i32 = 1_200;
const DEFAULT_UR_FRAGMENT_BYTES: i32 = 500;

/// Wrap `blob` as a CBOR bytestring (the UR payload CupCake/Cake expect) and
/// return the animated UR frame model for `ur_type`. `max_size` is the per-frame
/// budget the `DynamicQrCode` density selector passes (250 / 500 / 1000).
pub fn ur_parts(ur_type: &str, blob: &[u8], max_size: i32) -> ModelRc<SharedString> {
    let bytes = minicbor::bytes::ByteVec::from(blob.to_vec());
    let ur_bytes = minicbor::to_vec(bytes).expect("cbor encode of bytestring is infallible");
    let max_size = if (MIN_UR_FRAGMENT_BYTES..=MAX_UR_FRAGMENT_BYTES).contains(&max_size) {
        max_size
    } else {
        DEFAULT_UR_FRAGMENT_BYTES
    };
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

pub fn ur_payload_limited(data: &[u8], max_len: usize) -> Result<Vec<u8>, &'static str> {
    if data.len() > max_len.saturating_add(16) {
        return Err("QR payload is too large.");
    }
    let payload = ur_payload(data);
    if payload.len() > max_len {
        return Err("QR payload is too large.");
    }
    Ok(payload)
}

/// Build the CupCake pairing JSON (`pairQrString`): the watch-only credentials
/// Cake restores from. `restore_height` of 0 means Cake rescans from genesis —
/// safe but slow; a real birthday height can be threaded in later.
pub fn pair_json(label: &str, primary_address: &str, private_view_key: &str, restore_height: u64) -> String {
    #[derive(Serialize)]
    struct PairPayload<'a> {
        label: &'a str,
        version: u8,
        #[serde(rename = "primaryAddress")]
        primary_address: &'a str,
        #[serde(rename = "privateViewKey")]
        private_view_key: &'a str,
        #[serde(rename = "restoreHeight")]
        restore_height: u64,
    }

    serde_json::to_string_pretty(&PairPayload {
        label,
        version: 0,
        primary_address,
        private_view_key,
        restore_height,
    })
    .expect("pairing payload serialization is infallible")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pair_json_escapes_labels() {
        let json = pair_json("Prime \"main\"\nwallet", "4abc", "00", 123);
        assert!(json.contains(r#"Prime \"main\"\nwallet"#));
        assert!(serde_json::from_str::<serde_json::Value>(&json).is_ok());
    }

    #[test]
    fn ur_payload_limited_rejects_oversized_payloads() {
        let oversized = vec![0u8; 33];
        assert!(ur_payload_limited(&oversized, 16).is_err());
    }
}
