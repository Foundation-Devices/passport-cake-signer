// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Monero standard/subaddress address encoding.
//!
//! Layout:  base58_monero( prefix_varint || pub_spend(32) || pub_view(32) || checksum(4) )
//! where    checksum = keccak256(prefix || pub_spend || pub_view)[..4].
//!
//! Monero's base58 is block-wise (not the bitcoin streaming variant): the byte
//! string is split into 8-byte blocks, each encoded big-endian to a fixed
//! number of base58 chars (a full 8-byte block -> 11 chars). A 69-byte address
//! therefore encodes to 95 chars, the familiar Monero address length.

use super::{keccak256, Network};

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const FULL_BLOCK_SIZE: usize = 8;
const FULL_ENCODED_BLOCK_SIZE: usize = 11;
// Encoded length for a final partial block of N bytes (index = N).
const ENCODED_BLOCK_SIZES: [usize; 9] = [0, 2, 3, 5, 6, 7, 9, 10, 11];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressKind {
    Standard,
    Subaddress,
}

/// Build a Monero address for the given network, type, and public keys.
pub fn address(network: Network, kind: AddressKind, pub_spend: &[u8; 32], pub_view: &[u8; 32]) -> String {
    let mut data = Vec::with_capacity(1 + 32 + 32 + 4);
    // All Monero standard/subaddress prefixes are < 128, so the varint is a
    // single byte.
    data.push(match kind {
        AddressKind::Standard => network.standard_prefix(),
        AddressKind::Subaddress => network.subaddress_prefix(),
    });
    data.extend_from_slice(pub_spend);
    data.extend_from_slice(pub_view);
    let checksum = keccak256(&data);
    data.extend_from_slice(&checksum[..4]);
    base58_encode(&data)
}

/// Build the standard address for the given network + public keys.
pub fn primary_address(network: Network, pub_spend: &[u8; 32], pub_view: &[u8; 32]) -> String {
    address(network, AddressKind::Standard, pub_spend, pub_view)
}

/// Build the subaddress for the given network + public keys.
pub fn subaddress_address(network: Network, pub_spend: &[u8; 32], pub_view: &[u8; 32]) -> String {
    address(network, AddressKind::Subaddress, pub_spend, pub_view)
}

pub fn is_valid_standard_or_subaddress(address: &str, network: Network) -> bool {
    let Some(decoded) = base58_decode(address) else {
        return false;
    };
    if decoded.len() != 1 + 32 + 32 + 4 || !has_valid_checksum(&decoded) {
        return false;
    }
    matches!(decoded[0], prefix if prefix == network.standard_prefix() || prefix == network.subaddress_prefix())
}

/// Encode one block (1..=8 bytes) into exactly `ENCODED_BLOCK_SIZES[len]` chars,
/// big-endian, left-padded with the '1' (zero) digit.
fn encode_block(block: &[u8], out: &mut Vec<u8>) {
    let mut num: u64 = 0;
    for &b in block {
        num = num << 8 | b as u64;
    }
    let size = ENCODED_BLOCK_SIZES[block.len()];
    let start = out.len();
    out.resize(start + size, ALPHABET[0]); // pad with '1'
    let mut i = size;
    while num != 0 && i > 0 {
        i -= 1;
        out[start + i] = ALPHABET[(num % 58) as usize];
        num /= 58;
    }
}

fn base58_encode(data: &[u8]) -> String {
    let mut out = Vec::new();
    let full_blocks = data.len() / FULL_BLOCK_SIZE;
    for i in 0..full_blocks {
        encode_block(&data[i * FULL_BLOCK_SIZE..(i + 1) * FULL_BLOCK_SIZE], &mut out);
    }
    let rem = data.len() % FULL_BLOCK_SIZE;
    if rem > 0 {
        encode_block(&data[full_blocks * FULL_BLOCK_SIZE..], &mut out);
    }
    // Sanity: full blocks -> 11 chars each; checked by tests.
    let _ = FULL_ENCODED_BLOCK_SIZE;
    String::from_utf8(out).expect("base58 alphabet is ASCII")
}

fn base58_value(byte: u8) -> Option<u64> {
    ALPHABET.iter().position(|candidate| *candidate == byte).map(|i| i as u64)
}

fn decoded_block_size(encoded_len: usize) -> Option<usize> {
    match encoded_len {
        0 => Some(0),
        2 => Some(1),
        3 => Some(2),
        5 => Some(3),
        6 => Some(4),
        7 => Some(5),
        9 => Some(6),
        10 => Some(7),
        11 => Some(8),
        _ => None,
    }
}

fn decode_block(block: &[u8], decoded_len: usize, out: &mut Vec<u8>) -> Option<()> {
    let mut num = 0u64;
    for byte in block {
        num = num.checked_mul(58)?.checked_add(base58_value(*byte)?)?;
    }
    let start = out.len();
    out.resize(start + decoded_len, 0);
    for i in (0..decoded_len).rev() {
        out[start + i] = (num & 0xff) as u8;
        num >>= 8;
    }
    if num == 0 {
        Some(())
    } else {
        None
    }
}

fn base58_decode(encoded: &str) -> Option<Vec<u8>> {
    if encoded.is_empty() {
        return None;
    }
    let bytes = encoded.as_bytes();
    let full_blocks = bytes.len() / FULL_ENCODED_BLOCK_SIZE;
    let rem = bytes.len() % FULL_ENCODED_BLOCK_SIZE;
    let mut out = Vec::with_capacity(full_blocks * FULL_BLOCK_SIZE + decoded_block_size(rem)?);
    for i in 0..full_blocks {
        decode_block(
            &bytes[i * FULL_ENCODED_BLOCK_SIZE..(i + 1) * FULL_ENCODED_BLOCK_SIZE],
            FULL_BLOCK_SIZE,
            &mut out,
        )?;
    }
    if rem > 0 {
        decode_block(&bytes[full_blocks * FULL_ENCODED_BLOCK_SIZE..], decoded_block_size(rem)?, &mut out)?;
    }
    Some(out)
}

fn has_valid_checksum(decoded: &[u8]) -> bool {
    if decoded.len() < 5 {
        return false;
    }
    let split = decoded.len() - 4;
    let checksum = keccak256(&decoded[..split]);
    decoded[split..] == checksum[..4]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_address_is_95_chars() {
        let addr = primary_address(Network::Stagenet, &[1u8; 32], &[2u8; 32]);
        assert_eq!(addr.len(), 95, "got {addr}");
    }

    #[test]
    fn stagenet_addresses_start_with_5() {
        // Stagenet standard addresses begin with '5' (prefix byte 24).
        let addr = primary_address(Network::Stagenet, &[1u8; 32], &[2u8; 32]);
        assert!(addr.starts_with('5'), "got {addr}");
    }

    #[test]
    fn mainnet_addresses_start_with_4() {
        // Mainnet standard addresses begin with '4' (prefix byte 18).
        let addr = primary_address(Network::Mainnet, &[1u8; 32], &[2u8; 32]);
        assert!(addr.starts_with('4'), "got {addr}");
    }

    #[test]
    fn validates_monero_checksum_and_network_prefix() {
        let mainnet = primary_address(Network::Mainnet, &[1u8; 32], &[2u8; 32]);
        let stagenet = primary_address(Network::Stagenet, &[1u8; 32], &[2u8; 32]);
        assert!(is_valid_standard_or_subaddress(&mainnet, Network::Mainnet));
        assert!(!is_valid_standard_or_subaddress(&stagenet, Network::Mainnet));

        let mut corrupted = mainnet.clone();
        let replacement = if corrupted.as_bytes()[10] == b'1' { "2" } else { "1" };
        corrupted.replace_range(10..11, replacement);
        assert!(!is_valid_standard_or_subaddress(&corrupted, Network::Mainnet));
    }

    #[test]
    fn subaddresses_use_subaddress_prefixes() {
        let main = subaddress_address(Network::Mainnet, &[1u8; 32], &[2u8; 32]);
        let stage = subaddress_address(Network::Stagenet, &[1u8; 32], &[2u8; 32]);
        let test = subaddress_address(Network::Testnet, &[1u8; 32], &[2u8; 32]);
        assert_eq!(main.len(), 95);
        assert!(main.starts_with('8'), "got {main}");
        assert!(stage.starts_with('7'), "got {stage}");
        assert!(test.starts_with('B'), "got {test}");
    }

    // Known Monero mainnet base58 vector: the all-purpose block encoder must
    // turn the 69-byte donation-style payload length into 95 chars and be
    // internally consistent. Full end-to-end key->address correctness is
    // verified against monero-wallet-cli in the test rig (test-rig/README.md).
    #[test]
    fn block_encoder_lengths() {
        // 8 bytes -> 11 chars
        let mut o = Vec::new();
        encode_block(&[0xff; 8], &mut o);
        assert_eq!(o.len(), 11);
        // 5 bytes -> 7 chars
        let mut o = Vec::new();
        encode_block(&[0xff; 5], &mut o);
        assert_eq!(o.len(), 7);
    }
}
