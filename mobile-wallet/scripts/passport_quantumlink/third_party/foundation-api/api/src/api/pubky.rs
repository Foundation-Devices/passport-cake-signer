// SPDX-License-Identifier: GPL-3.0-or-later
//! Pubky Ring ⇄ Passport Prime QuantumLink messages.
//!
//! Added for the Pubky Ring POC: Prime is the key custodian/signer, the phone is
//! the online companion. The phone asks Prime for its pubkys and forwards
//! `pubkyauth://` sign-in requests; Prime signs and returns the bridge payload
//! the phone relays to the homeserver/relay.

use quantum_link_macros::quantum_link;

/// Phone → Prime: request the list of pubkys Prime holds (to display).
#[quantum_link]
pub struct PubkyListRequest {}

/// One pubky in a [`PubkyListResponse`].
#[quantum_link]
pub struct PubkyEntry {
    #[n(0)]
    pub pubky: String, // z-base-32 public key
    #[n(1)]
    pub label: String,
    #[n(2)]
    pub homeserver: String,
    #[n(3)]
    pub is_setup: bool,
}

/// Prime → phone: the pubkys Prime holds.
#[quantum_link]
pub struct PubkyListResponse {
    #[n(0)]
    pub pubkys: Vec<PubkyEntry>,
}

/// Phone → Prime: a `pubkyauth://` sign-in request to approve + sign.
#[quantum_link]
pub struct PubkyAuthRequest {
    #[n(0)]
    pub pubky: String, // which pubky to sign with (z32)
    #[n(1)]
    pub pubkyauth_url: String, // the scanned pubkyauth:// URL
}

/// Phone → Prime: rename a pubky (label edited on the phone).
#[quantum_link]
pub struct PubkyEditRequest {
    #[n(0)]
    pub pubky: String,
    #[n(1)]
    pub label: String,
}

/// Phone → Prime: delete a pubky (removed on the phone).
#[quantum_link]
pub struct PubkyDeleteRequest {
    #[n(0)]
    pub pubky: String,
}

/// Prime → phone: ask the (online) phone to resolve a pubky's human profile name
/// from its homeserver. Prime is offline at import time and only knows the pubky.
#[quantum_link]
pub struct ResolveNameRequest {
    #[n(0)]
    pub pubky: String, // z32 public key to look up
}

/// Phone → Prime: the resolved profile name (empty if none found).
#[quantum_link]
pub struct ResolveNameResponse {
    #[n(0)]
    pub pubky: String,
    #[n(1)]
    pub name: String,
}

/// Prime → phone: the signed/encrypted AuthToken bridge payload to relay, or a
/// rejection (`approved = false`).
#[quantum_link]
pub struct PubkyAuthResponse {
    #[n(0)]
    pub approved: bool,
    #[n(1)]
    pub relay: String,
    #[n(2)]
    pub channel: String, // base64url(blake3(secret))
    #[n(3)]
    pub token_b64: String, // base64(crypto::encrypt(token, secret))
}
