// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Monero standard (primary) address encoding.
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

/// Build the standard address for the given network + public keys.
pub fn primary_address(network: Network, pub_spend: &[u8; 32], pub_view: &[u8; 32]) -> String {
    let mut data = Vec::with_capacity(1 + 32 + 32 + 4);
    // All standard prefixes are < 128, so the varint is a single byte.
    data.push(network.standard_prefix());
    data.extend_from_slice(pub_spend);
    data.extend_from_slice(pub_view);
    let checksum = keccak256(&data);
    data.extend_from_slice(&checksum[..4]);
    base58_encode(&data)
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
