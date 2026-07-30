// SPDX-License-Identifier: GPL-3.0-or-later
//! Phone-side QuantumLink protocol core for Cake Wallet's Passport Prime bridge.
//!
//! BLE transport lives in Kotlin. This crate owns the post-quantum identity,
//! GSTP sealing/unsealing, replay checks, BTP framing, and typed WDK messages.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use btp::{chunk, Chunk, MasterDechunker};
use foundation_api::bc_envelope::prelude::CBOREncodable;
use foundation_api::bc_envelope::Envelope;
use foundation_api::bc_xid::XIDDocument;
use foundation_api::dcbor::CBOR;
use foundation_api::message::{
    EnvoyMessage, PassportMessage, QuantumLinkMessage, PROTOCOL_VERSION,
};
use foundation_api::pairing::{PairingRequest, UnpairingRequest, UnpairingResponse};
use foundation_api::quantum_link::{ARIDCache, QuantumLink, QuantumLinkIdentity};
use foundation_api::status::Heartbeat;
use foundation_api::wdk::{
    WdkBtcAccountRequest, WdkBtcSignPsbtRequest, WdkEvmAccountRequest,
    WdkEvmSignTransactionRequest, WdkMoneroKeyImageSyncRequest, WdkMoneroSignTransactionRequest,
    WdkMoneroVerifyAddressRequest, WdkMoneroWalletRemovalResponse,
    WdkMoneroWatchCredentialsRequest, WdkRequestCancelled, WDK_BITCOIN_TESTNET,
    WDK_PROTOCOL_VERSION, WDK_SEPOLIA_CHAIN_ID,
};

uniffi::setup_scaffolding!();

const REQUEST_ID_LEN: usize = 16;
const EVM_ADDRESS_LEN: usize = 42;
const MAX_CALLDATA_LEN: usize = 4_096;
const MAX_SIGNED_TRANSACTION_LEN: usize = 8_192;
const MAX_DECIMAL_LEN: usize = 78;
const EVM_ACCOUNT_PATH: &str = "m/44'/60'/0'/0/0";
const BTC_ACCOUNT_PATH: &str = "m/84'/1'/0'/0/0";
const MAX_PSBT_LEN: usize = 65_536;
const MAX_SIGNED_BTC_TRANSACTION_LEN: usize = 100_000;
const MAX_MONERO_UR_LEN: usize = 1_048_576;
const MAX_MONERO_ADDRESS_LEN: usize = 128;
const MONERO_VIEW_KEY_HEX_LEN: usize = 64;
const MAX_MONERO_WALLET_NAME_LEN: usize = 33;

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum QlError {
    #[error("{0}")]
    Failed(String),
}

impl QlError {
    fn msg(error: impl std::fmt::Display) -> Self {
        Self::Failed(error.to_string())
    }
}

/// A reassembled, authenticated message from Passport Prime.
#[derive(uniffi::Record)]
pub struct DecodedMessage {
    pub kind: String,
    pub device_name: String,
    pub request_id: Vec<u8>,
    pub derivation_path: String,
    pub address: String,
    pub watch_key: String,
    pub wallet_name: String,
    pub restore_height: Option<u64>,
    pub public_key: Vec<u8>,
    pub signed_transaction: Vec<u8>,
    pub key_images_ur: String,
    pub signed_transaction_ur: String,
    pub account_index: u32,
    pub address_index: u32,
    pub reason_code: u8,
    pub message: String,
}

impl DecodedMessage {
    fn kind(kind: &str) -> Self {
        Self {
            kind: kind.into(),
            device_name: String::new(),
            request_id: Vec::new(),
            derivation_path: String::new(),
            address: String::new(),
            watch_key: String::new(),
            wallet_name: String::new(),
            restore_height: None,
            public_key: Vec::new(),
            signed_transaction: Vec::new(),
            key_images_ur: String::new(),
            signed_transaction_ur: String::new(),
            account_index: 0,
            address_index: 0,
            reason_code: 0,
            message: String::new(),
        }
    }
}

/// Generate a fresh post-quantum QuantumLink identity for secure persistence.
#[uniffi::export]
pub fn generate_identity() -> Vec<u8> {
    QuantumLinkIdentity::generate().to_bytes()
}

/// Return the public XID document for the persisted phone identity.
#[uniffi::export]
pub fn identity_xid(identity: Vec<u8>) -> Result<Vec<u8>, QlError> {
    let identity = QuantumLinkIdentity::from_bytes(&identity).map_err(QlError::msg)?;
    Ok(identity.xid_document.to_cbor_data())
}

/// Build the two-step pairing request after the phone has connected over BLE.
#[uniffi::export]
pub fn build_pairing_request(
    identity: Vec<u8>,
    prime_xid: Vec<u8>,
    device_name: String,
) -> Result<Vec<Vec<u8>>, QlError> {
    let identity = QuantumLinkIdentity::from_bytes(&identity).map_err(QlError::msg)?;
    let recipient = parse_xid(&prime_xid)?;
    let private_keys = identity
        .private_keys
        .as_ref()
        .ok_or_else(|| QlError::Failed("identity contains no private keys".into()))?;

    let message = EnvoyMessage {
        message: QuantumLinkMessage::PairingRequest(PairingRequest {
            xid_document: identity.xid_document.to_cbor_data(),
            device_name,
        }),
        timestamp: now_secs(),
        protocol_version: Some(PROTOCOL_VERSION),
    };
    let envelope = message.seal((private_keys, &identity.xid_document), &recipient);
    Ok(frames(&envelope.to_cbor_data()))
}

/// Answer Passport Prime's liveness probe. Prime treats a connected BLE link
/// as dead unless the authenticated peer returns these heartbeats.
#[uniffi::export]
pub fn build_heartbeat_response(
    identity: Vec<u8>,
    prime_xid: Vec<u8>,
) -> Result<Vec<Vec<u8>>, QlError> {
    seal_envoy(
        &identity,
        &prime_xid,
        QuantumLinkMessage::Heartbeat(Heartbeat {}),
    )
}

/// Ask Passport Prime to remove the authenticated pairing at both ends.
#[uniffi::export]
pub fn build_unpairing_request(
    identity: Vec<u8>,
    prime_xid: Vec<u8>,
) -> Result<Vec<Vec<u8>>, QlError> {
    seal_envoy(
        &identity,
        &prime_xid,
        QuantumLinkMessage::UnpairingRequest(UnpairingRequest {}),
    )
}

/// Acknowledge a Passport-initiated unpair before removing local state.
#[uniffi::export]
pub fn build_unpairing_response(
    identity: Vec<u8>,
    prime_xid: Vec<u8>,
    success: bool,
) -> Result<Vec<Vec<u8>>, QlError> {
    seal_envoy(
        &identity,
        &prime_xid,
        QuantumLinkMessage::UnpairingResponse(UnpairingResponse { success }),
    )
}

/// Ask Passport for the public EVM account derived from its per-app seed.
#[uniffi::export]
pub fn build_wdk_evm_account_request(
    identity: Vec<u8>,
    prime_xid: Vec<u8>,
    request_id: Vec<u8>,
    derivation_path: String,
    chain_id: u32,
) -> Result<Vec<Vec<u8>>, QlError> {
    validate_request(&request_id, &derivation_path, chain_id)?;
    seal_envoy(
        &identity,
        &prime_xid,
        QuantumLinkMessage::WdkEvmAccountRequest(WdkEvmAccountRequest {
            protocol_version: WDK_PROTOCOL_VERSION,
            request_id,
            derivation_path,
            chain_id,
        }),
    )
}

/// Send a fully populated canonical EIP-1559 transaction for Passport review.
#[allow(clippy::too_many_arguments)]
#[uniffi::export]
pub fn build_wdk_evm_sign_transaction_request(
    identity: Vec<u8>,
    prime_xid: Vec<u8>,
    request_id: Vec<u8>,
    derivation_path: String,
    chain_id: u32,
    nonce: u64,
    from: String,
    to: String,
    data: Vec<u8>,
    value: String,
    gas_limit: String,
    max_fee_per_gas: String,
    max_priority_fee_per_gas: String,
) -> Result<Vec<Vec<u8>>, QlError> {
    validate_request(&request_id, &derivation_path, chain_id)?;
    validate_address(&from)?;
    validate_address(&to)?;
    if data.len() > MAX_CALLDATA_LEN {
        return Err(QlError::Failed("transaction calldata is too large".into()));
    }
    validate_decimal("value", &value)?;
    validate_decimal("gas_limit", &gas_limit)?;
    validate_decimal("max_fee_per_gas", &max_fee_per_gas)?;
    validate_decimal("max_priority_fee_per_gas", &max_priority_fee_per_gas)?;

    seal_envoy(
        &identity,
        &prime_xid,
        QuantumLinkMessage::WdkEvmSignTransactionRequest(WdkEvmSignTransactionRequest {
            protocol_version: WDK_PROTOCOL_VERSION,
            request_id,
            derivation_path,
            chain_id,
            nonce,
            from,
            to,
            data,
            value,
            gas_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas,
        }),
    )
}

/// Ask Passport for the public BIP-84 Bitcoin testnet account.
#[uniffi::export]
pub fn build_wdk_btc_account_request(
    identity: Vec<u8>,
    prime_xid: Vec<u8>,
    request_id: Vec<u8>,
    derivation_path: String,
    network: u8,
) -> Result<Vec<Vec<u8>>, QlError> {
    validate_btc_request(&request_id, &derivation_path, network)?;
    seal_envoy(
        &identity,
        &prime_xid,
        QuantumLinkMessage::WdkBtcAccountRequest(WdkBtcAccountRequest {
            protocol_version: WDK_PROTOCOL_VERSION,
            request_id,
            derivation_path,
            network,
        }),
    )
}

/// Send a complete PSBT for Passport Prime to validate, render and sign.
#[uniffi::export]
pub fn build_wdk_btc_sign_psbt_request(
    identity: Vec<u8>,
    prime_xid: Vec<u8>,
    request_id: Vec<u8>,
    derivation_path: String,
    network: u8,
    psbt: Vec<u8>,
) -> Result<Vec<Vec<u8>>, QlError> {
    validate_btc_request(&request_id, &derivation_path, network)?;
    if psbt.is_empty() || psbt.len() > MAX_PSBT_LEN {
        return Err(QlError::Failed(
            "Bitcoin PSBT is invalid or too large".into(),
        ));
    }
    seal_envoy(
        &identity,
        &prime_xid,
        QuantumLinkMessage::WdkBtcSignPsbtRequest(WdkBtcSignPsbtRequest {
            protocol_version: WDK_PROTOCOL_VERSION,
            request_id,
            derivation_path,
            network,
            psbt,
        }),
    )
}

/// Ask Passport for Monero watch-only credentials for Cake Wallet.
#[uniffi::export]
pub fn build_wdk_monero_watch_credentials_request(
    identity: Vec<u8>,
    prime_xid: Vec<u8>,
    request_id: Vec<u8>,
) -> Result<Vec<Vec<u8>>, QlError> {
    validate_request_id(&request_id)?;
    seal_envoy(
        &identity,
        &prime_xid,
        QuantumLinkMessage::WdkMoneroWatchCredentialsRequest(WdkMoneroWatchCredentialsRequest {
            protocol_version: WDK_PROTOCOL_VERSION,
            request_id,
        }),
    )
}

/// Send Cake's CupCake-compatible output export UR to Passport for key-image sync.
#[uniffi::export]
pub fn build_wdk_monero_key_image_sync_request(
    identity: Vec<u8>,
    prime_xid: Vec<u8>,
    request_id: Vec<u8>,
    outputs_ur: String,
) -> Result<Vec<Vec<u8>>, QlError> {
    validate_request_id(&request_id)?;
    validate_monero_ur("outputs_ur", &outputs_ur, "ur:xmr-output")?;
    seal_envoy(
        &identity,
        &prime_xid,
        QuantumLinkMessage::WdkMoneroKeyImageSyncRequest(WdkMoneroKeyImageSyncRequest {
            protocol_version: WDK_PROTOCOL_VERSION,
            request_id,
            outputs_ur,
        }),
    )
}

/// Send Cake's CupCake-compatible unsigned transaction UR to Passport.
#[uniffi::export]
pub fn build_wdk_monero_sign_transaction_request(
    identity: Vec<u8>,
    prime_xid: Vec<u8>,
    request_id: Vec<u8>,
    unsigned_tx_ur: String,
) -> Result<Vec<Vec<u8>>, QlError> {
    validate_request_id(&request_id)?;
    validate_monero_ur("unsigned_tx_ur", &unsigned_tx_ur, "ur:xmr-txunsigned")?;
    seal_envoy(
        &identity,
        &prime_xid,
        QuantumLinkMessage::WdkMoneroSignTransactionRequest(WdkMoneroSignTransactionRequest {
            protocol_version: WDK_PROTOCOL_VERSION,
            request_id,
            unsigned_tx_ur,
        }),
    )
}

/// Ask Passport to independently derive and confirm a Monero receive address.
#[uniffi::export]
pub fn build_wdk_monero_verify_address_request(
    identity: Vec<u8>,
    prime_xid: Vec<u8>,
    request_id: Vec<u8>,
    wallet_address: String,
    account_index: u32,
    address_index: u32,
    address: String,
) -> Result<Vec<Vec<u8>>, QlError> {
    validate_request_id(&request_id)?;
    validate_monero_address(&wallet_address)?;
    validate_monero_address(&address)?;
    seal_envoy(
        &identity,
        &prime_xid,
        QuantumLinkMessage::WdkMoneroVerifyAddressRequest(WdkMoneroVerifyAddressRequest {
            protocol_version: WDK_PROTOCOL_VERSION,
            request_id,
            wallet_address,
            account_index,
            address_index,
            address,
        }),
    )
}

/// Acknowledge a Passport-initiated, wallet-scoped removal request.
#[uniffi::export]
pub fn build_wdk_monero_wallet_removal_response(
    identity: Vec<u8>,
    prime_xid: Vec<u8>,
    request_id: Vec<u8>,
    wallet_address: String,
    removed: bool,
) -> Result<Vec<Vec<u8>>, QlError> {
    validate_request_id(&request_id)?;
    validate_monero_address(&wallet_address)?;
    seal_envoy(
        &identity,
        &prime_xid,
        QuantumLinkMessage::WdkMoneroWalletRemovalResponse(WdkMoneroWalletRemovalResponse {
            protocol_version: WDK_PROTOCOL_VERSION,
            request_id,
            wallet_address,
            removed,
        }),
    )
}

/// Cancel a pending review request.
#[uniffi::export]
pub fn build_wdk_request_cancelled(
    identity: Vec<u8>,
    prime_xid: Vec<u8>,
    request_id: Vec<u8>,
) -> Result<Vec<Vec<u8>>, QlError> {
    validate_request_id(&request_id)?;
    seal_envoy(
        &identity,
        &prime_xid,
        QuantumLinkMessage::WdkRequestCancelled(WdkRequestCancelled {
            protocol_version: WDK_PROTOCOL_VERSION,
            request_id,
        }),
    )
}

/// Stateful BTP decoder and GSTP replay-protected unsealer.
#[derive(uniffi::Object)]
pub struct QlSession {
    identity: QuantumLinkIdentity,
    state: Mutex<DecoderState>,
}

struct DecoderState {
    dechunker: MasterDechunker<10>,
    arid_cache: ARIDCache,
    expected_peer: Option<XIDDocument>,
}

#[uniffi::export]
impl QlSession {
    #[uniffi::constructor]
    pub fn new(identity: Vec<u8>) -> Result<Arc<Self>, QlError> {
        let identity = QuantumLinkIdentity::from_bytes(&identity).map_err(QlError::msg)?;
        Ok(Arc::new(Self {
            identity,
            state: Mutex::new(DecoderState {
                dechunker: MasterDechunker::default(),
                arid_cache: ARIDCache::new(),
                expected_peer: None,
            }),
        }))
    }

    /// Pin the peer identity scanned from Passport before accepting messages.
    ///
    /// Authentication by itself only proves that a message has a valid XID
    /// signature. Pinning binds it to the specific Passport selected by the
    /// user and prevents another valid QuantumLink identity from responding.
    pub fn set_expected_peer(&self, prime_xid: Vec<u8>) -> Result<(), QlError> {
        let expected_peer = parse_xid(&prime_xid)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| QlError::Failed("decoder lock poisoned".into()))?;
        state.expected_peer = Some(expected_peer);
        Ok(())
    }

    /// Feed one BLE notification. Returns a message only after complete,
    /// authenticated reassembly.
    pub fn feed(&self, frame: Vec<u8>) -> Result<Option<DecodedMessage>, QlError> {
        let chunk = Chunk::decode(&frame)
            .map_err(|error| QlError::Failed(format!("invalid BTP chunk: {error:?}")))?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| QlError::Failed("decoder lock poisoned".into()))?;
        let Some(data) = state.dechunker.insert_chunk(chunk) else {
            return Ok(None);
        };
        let envelope = Envelope::try_from_cbor_data(data).map_err(QlError::msg)?;
        let private_keys = self
            .identity
            .private_keys
            .as_ref()
            .ok_or_else(|| QlError::Failed("identity contains no private keys".into()))?;
        let (message, sender) = PassportMessage::unseal_passport_message_with_replay_check(
            &envelope,
            private_keys,
            &mut state.arid_cache,
        )
        .map_err(QlError::msg)?;
        if state.expected_peer.as_ref() != Some(&sender) {
            return Err(QlError::Failed(
                "QuantumLink response came from an unexpected identity".into(),
            ));
        }

        let decoded = match message.message {
            QuantumLinkMessage::PairingResponse(response) => {
                let mut decoded = DecodedMessage::kind("PairingResponse");
                decoded.device_name = response
                    .device_name
                    .unwrap_or_else(|| "Passport Prime".into());
                decoded
            }
            QuantumLinkMessage::Heartbeat(_) => DecodedMessage::kind("Heartbeat"),
            QuantumLinkMessage::UnpairingRequest(_) => DecodedMessage::kind("UnpairingRequest"),
            QuantumLinkMessage::UnpairingResponse(response) => {
                let mut decoded = DecodedMessage::kind("UnpairingResponse");
                decoded.reason_code = u8::from(response.success);
                decoded
            }
            QuantumLinkMessage::WdkEvmAccountResponse(response) => {
                validate_response_version(response.protocol_version)?;
                validate_request_id(&response.request_id)?;
                if response.derivation_path != EVM_ACCOUNT_PATH {
                    return Err(QlError::Failed(
                        "Passport returned an unexpected derivation path".into(),
                    ));
                }
                validate_address(&response.address)?;
                if response.public_key.len() != 33 && response.public_key.len() != 65 {
                    return Err(QlError::Failed(
                        "Passport returned an invalid EVM public key".into(),
                    ));
                }
                let mut decoded = DecodedMessage::kind("WdkEvmAccountResponse");
                decoded.request_id = response.request_id;
                decoded.derivation_path = response.derivation_path;
                decoded.address = response.address;
                decoded.public_key = response.public_key;
                decoded
            }
            QuantumLinkMessage::WdkEvmSignTransactionResponse(response) => {
                validate_response_version(response.protocol_version)?;
                validate_request_id(&response.request_id)?;
                validate_address(&response.address)?;
                if response.signed_transaction.is_empty()
                    || response.signed_transaction.len() > MAX_SIGNED_TRANSACTION_LEN
                {
                    return Err(QlError::Failed(
                        "Passport returned an invalid signed transaction".into(),
                    ));
                }
                let mut decoded = DecodedMessage::kind("WdkEvmSignTransactionResponse");
                decoded.request_id = response.request_id;
                decoded.address = response.address;
                decoded.signed_transaction = response.signed_transaction;
                decoded
            }
            QuantumLinkMessage::WdkBtcAccountResponse(response) => {
                validate_response_version(response.protocol_version)?;
                validate_request_id(&response.request_id)?;
                if response.derivation_path != BTC_ACCOUNT_PATH {
                    return Err(QlError::Failed(
                        "Passport returned an unexpected Bitcoin derivation path".into(),
                    ));
                }
                validate_btc_address(&response.address)?;
                if response.public_key.len() != 33 {
                    return Err(QlError::Failed(
                        "Passport returned an invalid Bitcoin public key".into(),
                    ));
                }
                let mut decoded = DecodedMessage::kind("WdkBtcAccountResponse");
                decoded.request_id = response.request_id;
                decoded.derivation_path = response.derivation_path;
                decoded.address = response.address;
                decoded.public_key = response.public_key;
                decoded
            }
            QuantumLinkMessage::WdkBtcSignPsbtResponse(response) => {
                validate_response_version(response.protocol_version)?;
                validate_request_id(&response.request_id)?;
                validate_btc_address(&response.address)?;
                if response.signed_transaction.is_empty()
                    || response.signed_transaction.len() > MAX_SIGNED_BTC_TRANSACTION_LEN
                {
                    return Err(QlError::Failed(
                        "Passport returned an invalid Bitcoin transaction".into(),
                    ));
                }
                let mut decoded = DecodedMessage::kind("WdkBtcSignPsbtResponse");
                decoded.request_id = response.request_id;
                decoded.address = response.address;
                decoded.signed_transaction = response.signed_transaction;
                decoded
            }
            QuantumLinkMessage::WdkMoneroWatchCredentialsResponse(response) => {
                validate_response_version(response.protocol_version)?;
                validate_request_id(&response.request_id)?;
                validate_monero_address(&response.address)?;
                validate_monero_view_key(&response.watch_key)?;
                let mut decoded = DecodedMessage::kind("WdkMoneroWatchCredentialsResponse");
                decoded.request_id = response.request_id;
                decoded.address = response.address;
                decoded.watch_key = response.watch_key;
                decoded.wallet_name = response.wallet_name;
                decoded.restore_height = response.restore_height;
                decoded
            }
            QuantumLinkMessage::WdkMoneroWalletMetadata(metadata) => {
                validate_response_version(metadata.protocol_version)?;
                validate_monero_address(&metadata.wallet_address)?;
                validate_monero_wallet_name(&metadata.wallet_name)?;
                let mut decoded = DecodedMessage::kind("WdkMoneroWalletMetadata");
                decoded.address = metadata.wallet_address;
                decoded.wallet_name = metadata.wallet_name;
                decoded
            }
            QuantumLinkMessage::WdkMoneroWalletRemovalRequest(request) => {
                validate_response_version(request.protocol_version)?;
                validate_request_id(&request.request_id)?;
                validate_monero_address(&request.wallet_address)?;
                validate_monero_wallet_name(&request.wallet_name)?;
                let mut decoded = DecodedMessage::kind("WdkMoneroWalletRemovalRequest");
                decoded.request_id = request.request_id;
                decoded.address = request.wallet_address;
                decoded.wallet_name = request.wallet_name;
                decoded
            }
            QuantumLinkMessage::WdkMoneroKeyImageSyncResponse(response) => {
                validate_response_version(response.protocol_version)?;
                validate_request_id(&response.request_id)?;
                validate_monero_ur("key_images_ur", &response.key_images_ur, "ur:xmr-keyimage")?;
                let mut decoded = DecodedMessage::kind("WdkMoneroKeyImageSyncResponse");
                decoded.request_id = response.request_id;
                decoded.key_images_ur = response.key_images_ur;
                decoded
            }
            QuantumLinkMessage::WdkMoneroSignTransactionResponse(response) => {
                validate_response_version(response.protocol_version)?;
                validate_request_id(&response.request_id)?;
                validate_monero_ur(
                    "signed_transaction_ur",
                    &response.signed_tx_ur,
                    "ur:xmr-txsigned",
                )?;
                let mut decoded = DecodedMessage::kind("WdkMoneroSignTransactionResponse");
                decoded.request_id = response.request_id;
                decoded.signed_transaction_ur = response.signed_tx_ur;
                decoded
            }
            QuantumLinkMessage::WdkMoneroVerifyAddressResponse(response) => {
                validate_response_version(response.protocol_version)?;
                validate_request_id(&response.request_id)?;
                validate_monero_address(&response.address)?;
                let mut decoded = DecodedMessage::kind("WdkMoneroVerifyAddressResponse");
                decoded.request_id = response.request_id;
                decoded.address = response.address;
                decoded.account_index = response.account_index;
                decoded.address_index = response.address_index;
                decoded
            }
            QuantumLinkMessage::WdkRequestRejected(response) => {
                validate_response_version(response.protocol_version)?;
                validate_request_id(&response.request_id)?;
                let mut decoded = DecodedMessage::kind("WdkRequestRejected");
                decoded.request_id = response.request_id;
                decoded.reason_code = response.reason_code;
                decoded.message = response.message;
                decoded
            }
            QuantumLinkMessage::WdkRequestCancelled(response) => {
                validate_response_version(response.protocol_version)?;
                validate_request_id(&response.request_id)?;
                let mut decoded = DecodedMessage::kind("WdkRequestCancelled");
                decoded.request_id = response.request_id;
                decoded
            }
            _ => DecodedMessage::kind("Other"),
        };

        Ok(Some(decoded))
    }
}

fn validate_response_version(version: u8) -> Result<(), QlError> {
    if version != WDK_PROTOCOL_VERSION {
        return Err(QlError::Failed(
            "unsupported Passport WDK protocol version".into(),
        ));
    }
    Ok(())
}

fn validate_request(
    request_id: &[u8],
    derivation_path: &str,
    chain_id: u32,
) -> Result<(), QlError> {
    validate_request_id(request_id)?;
    if derivation_path != EVM_ACCOUNT_PATH {
        return Err(QlError::Failed("unsupported derivation path".into()));
    }
    if chain_id != WDK_SEPOLIA_CHAIN_ID {
        return Err(QlError::Failed("unsupported EVM chain".into()));
    }
    Ok(())
}

fn validate_request_id(request_id: &[u8]) -> Result<(), QlError> {
    if request_id.len() != REQUEST_ID_LEN {
        return Err(QlError::Failed("request ID must be 128 bits".into()));
    }
    Ok(())
}

fn validate_btc_request(
    request_id: &[u8],
    derivation_path: &str,
    network: u8,
) -> Result<(), QlError> {
    validate_request_id(request_id)?;
    if derivation_path != BTC_ACCOUNT_PATH {
        return Err(QlError::Failed(
            "unsupported Bitcoin derivation path".into(),
        ));
    }
    if network != WDK_BITCOIN_TESTNET {
        return Err(QlError::Failed("unsupported Bitcoin network".into()));
    }
    Ok(())
}

fn validate_btc_address(address: &str) -> Result<(), QlError> {
    if !address.starts_with("tb1q")
        || !(42..=62).contains(&address.len())
        || !address
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return Err(QlError::Failed("invalid Bitcoin testnet address".into()));
    }
    Ok(())
}

fn validate_monero_address(address: &str) -> Result<(), QlError> {
    if !matches!(address.len(), 95 | 106)
        || address.len() > MAX_MONERO_ADDRESS_LEN
        || !address.bytes().all(|byte| {
            matches!(
                byte,
                b'1'..=b'9'
                    | b'A'..=b'H'
                    | b'J'..=b'N'
                    | b'P'..=b'Z'
                    | b'a'..=b'k'
                    | b'm'..=b'z'
            )
        })
    {
        return Err(QlError::Failed("invalid Monero address".into()));
    }
    Ok(())
}

fn validate_monero_view_key(view_key: &str) -> Result<(), QlError> {
    if view_key.len() != MONERO_VIEW_KEY_HEX_LEN
        || !view_key.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(QlError::Failed("invalid Monero view key".into()));
    }
    Ok(())
}

fn validate_monero_wallet_name(name: &str) -> Result<(), QlError> {
    if name.is_empty()
        || name.len() > MAX_MONERO_WALLET_NAME_LEN
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'-' | b'_'))
    {
        return Err(QlError::Failed("invalid Monero wallet name".into()));
    }
    Ok(())
}

fn validate_monero_ur(field: &str, value: &str, expected_prefix: &str) -> Result<(), QlError> {
    if value.is_empty() || value.len() > MAX_MONERO_UR_LEN {
        return Err(QlError::Failed(format!("{field} is missing or too large")));
    }
    if value
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .any(|line| !line.to_ascii_lowercase().starts_with(expected_prefix))
    {
        return Err(QlError::Failed(format!(
            "{field} must contain {expected_prefix} UR frames"
        )));
    }
    Ok(())
}

fn validate_address(address: &str) -> Result<(), QlError> {
    if address.len() != EVM_ADDRESS_LEN
        || !address.starts_with("0x")
        || !address[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(QlError::Failed("invalid EVM address".into()));
    }
    Ok(())
}

fn validate_decimal(field: &str, value: &str) -> Result<(), QlError> {
    let canonical = value == "0"
        || (!value.is_empty()
            && !value.starts_with('0')
            && value.len() <= MAX_DECIMAL_LEN
            && value.bytes().all(|byte| byte.is_ascii_digit()));
    if !canonical {
        return Err(QlError::Failed(format!(
            "{field} is not a canonical unsigned decimal"
        )));
    }
    Ok(())
}

fn parse_xid(cbor: &[u8]) -> Result<XIDDocument, QlError> {
    let cbor = CBOR::try_from_data(cbor).map_err(QlError::msg)?;
    XIDDocument::try_from(cbor).map_err(QlError::msg)
}

fn seal_envoy(
    identity: &[u8],
    prime_xid: &[u8],
    message: QuantumLinkMessage,
) -> Result<Vec<Vec<u8>>, QlError> {
    let identity = QuantumLinkIdentity::from_bytes(identity).map_err(QlError::msg)?;
    let recipient = parse_xid(prime_xid)?;
    let private_keys = identity
        .private_keys
        .as_ref()
        .ok_or_else(|| QlError::Failed("identity contains no private keys".into()))?;
    let envelope = EnvoyMessage {
        message,
        timestamp: now_secs(),
        protocol_version: Some(PROTOCOL_VERSION),
    }
    .seal((private_keys, &identity.xid_document), &recipient);
    Ok(frames(&envelope.to_cbor_data()))
}

fn frames(cbor: &[u8]) -> Vec<Vec<u8>> {
    chunk(cbor).map(|chunk| chunk.to_vec()).collect()
}

fn now_secs() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as u32)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use foundation_api::pairing::PairingResponse;
    use foundation_api::passport::{
        PassportColor, PassportFirmwareVersion, PassportModel, PassportSerial,
    };
    use foundation_api::status::DeviceStatus;
    use foundation_api::wdk::{
        WdkMoneroSignTransactionResponse, WdkMoneroVerifyAddressResponse, WdkMoneroWalletMetadata,
        WdkMoneroWalletRemovalRequest,
    };

    #[test]
    fn validates_canonical_decimal_quantities() {
        assert!(validate_decimal("value", "0").is_ok());
        assert!(validate_decimal("value", "1000000").is_ok());
        assert!(validate_decimal("value", "").is_err());
        assert!(validate_decimal("value", "01").is_err());
        assert!(validate_decimal("value", "-1").is_err());
    }

    #[test]
    fn enforces_request_scope() {
        let request_id = [0_u8; REQUEST_ID_LEN];
        assert!(validate_request(&request_id, EVM_ACCOUNT_PATH, WDK_SEPOLIA_CHAIN_ID).is_ok());
        assert!(validate_request(&request_id, "m/44'/60'/0'/0/1", WDK_SEPOLIA_CHAIN_ID).is_err());
        assert!(validate_request(&request_id, EVM_ACCOUNT_PATH, 1).is_err());
        assert!(
            validate_request(&request_id[..15], EVM_ACCOUNT_PATH, WDK_SEPOLIA_CHAIN_ID).is_err()
        );
    }

    #[test]
    fn rejects_authenticated_messages_from_an_unpinned_passport() {
        let phone = QuantumLinkIdentity::generate();
        let expected_passport = QuantumLinkIdentity::generate();
        let other_passport = QuantumLinkIdentity::generate();
        let session = QlSession::new(phone.to_bytes()).unwrap();
        session
            .set_expected_peer(expected_passport.xid_document.to_cbor_data())
            .unwrap();

        let message = PassportMessage {
            message: QuantumLinkMessage::WdkRequestCancelled(WdkRequestCancelled {
                protocol_version: WDK_PROTOCOL_VERSION,
                request_id: vec![7; REQUEST_ID_LEN],
            }),
            status: DeviceStatus {
                version: "test".into(),
                battery_level: 100,
            },
            protocol_version: Some(PROTOCOL_VERSION),
        };
        let envelope = message.seal(
            (
                other_passport.private_keys.as_ref().unwrap(),
                &other_passport.xid_document,
            ),
            &phone.xid_document,
        );

        let mut result = Ok(None);
        for frame in frames(&envelope.to_cbor_data()) {
            result = session.feed(frame);
        }
        assert!(matches!(
            result,
            Err(QlError::Failed(message)) if message.contains("unexpected identity")
        ));
    }

    #[test]
    fn decodes_pairing_response_from_pinned_passport() {
        let phone = QuantumLinkIdentity::generate();
        let passport = QuantumLinkIdentity::generate();
        let session = QlSession::new(phone.to_bytes()).unwrap();
        session
            .set_expected_peer(passport.xid_document.to_cbor_data())
            .unwrap();

        let message = PassportMessage {
            message: QuantumLinkMessage::PairingResponse(PairingResponse {
                passport_model: PassportModel::Prime,
                passport_firmware_version: PassportFirmwareVersion("poc".into()),
                passport_serial: PassportSerial("TEST".into()),
                passport_color: PassportColor::Dark,
                onboarding_complete: true,
                device_name: Some("Passport Prime".into()),
            }),
            status: DeviceStatus {
                version: "test".into(),
                battery_level: 100,
            },
            protocol_version: Some(PROTOCOL_VERSION),
        };
        let envelope = message.seal(
            (
                passport.private_keys.as_ref().unwrap(),
                &passport.xid_document,
            ),
            &phone.xid_document,
        );

        let mut decoded = None;
        for frame in frames(&envelope.to_cbor_data()) {
            decoded = session.feed(frame).unwrap().or(decoded);
        }
        let decoded = decoded.expect("pairing response should reassemble");
        assert_eq!(decoded.kind, "PairingResponse");
        assert_eq!(decoded.device_name, "Passport Prime");
    }

    #[test]
    fn decodes_heartbeat_and_builds_authenticated_response() {
        let phone = QuantumLinkIdentity::generate();
        let passport = QuantumLinkIdentity::generate();
        let session = QlSession::new(phone.to_bytes()).unwrap();
        session
            .set_expected_peer(passport.xid_document.to_cbor_data())
            .unwrap();

        let message = PassportMessage {
            message: QuantumLinkMessage::Heartbeat(Heartbeat {}),
            status: DeviceStatus {
                version: "test".into(),
                battery_level: 100,
            },
            protocol_version: Some(PROTOCOL_VERSION),
        };
        let envelope = message.seal(
            (
                passport.private_keys.as_ref().unwrap(),
                &passport.xid_document,
            ),
            &phone.xid_document,
        );

        let mut decoded = None;
        for frame in frames(&envelope.to_cbor_data()) {
            decoded = session.feed(frame).unwrap().or(decoded);
        }
        assert_eq!(
            decoded.expect("heartbeat should reassemble").kind,
            "Heartbeat"
        );
        assert!(
            !build_heartbeat_response(phone.to_bytes(), passport.xid_document.to_cbor_data())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn builds_monero_signing_request_only_for_unsigned_tx_ur() {
        let phone = QuantumLinkIdentity::generate();
        let passport = QuantumLinkIdentity::generate();
        let request_id = vec![9; REQUEST_ID_LEN];

        assert!(build_wdk_monero_sign_transaction_request(
            phone.to_bytes(),
            passport.xid_document.to_cbor_data(),
            request_id.clone(),
            "ur:xmr-txunsigned/1-1/lpadtest".into(),
        )
        .is_ok());

        assert!(build_wdk_monero_sign_transaction_request(
            phone.to_bytes(),
            passport.xid_document.to_cbor_data(),
            request_id,
            "ur:xmr-output/1-1/lpadtest".into(),
        )
        .is_err());
    }

    #[test]
    fn builds_monero_address_verification_request_for_a_valid_wallet() {
        let phone = QuantumLinkIdentity::generate();
        let passport = QuantumLinkIdentity::generate();
        let request_id = vec![3; REQUEST_ID_LEN];
        let address =
            "48HHtdQvxyH5jwX5N6fAQD6rxx7EQT7GKZvsixtgJRkRaD8wHqwKp6eGSuStiUN5MHXR19vF3W4Jc7MumryYTTH7LGTfanS";

        assert!(build_wdk_monero_verify_address_request(
            phone.to_bytes(),
            passport.xid_document.to_cbor_data(),
            request_id.clone(),
            address.into(),
            2,
            7,
            address.into(),
        )
        .is_ok());
        assert!(build_wdk_monero_verify_address_request(
            phone.to_bytes(),
            passport.xid_document.to_cbor_data(),
            request_id,
            "not-a-monero-address".into(),
            2,
            7,
            address.into(),
        )
        .is_err());
        assert!(build_wdk_monero_verify_address_request(
            phone.to_bytes(),
            passport.xid_document.to_cbor_data(),
            vec![4; REQUEST_ID_LEN],
            address.into(),
            2,
            7,
            "not-a-monero-address".into(),
        )
        .is_err());
    }

    #[test]
    fn decodes_authenticated_monero_signed_transaction_response() {
        let phone = QuantumLinkIdentity::generate();
        let passport = QuantumLinkIdentity::generate();
        let session = QlSession::new(phone.to_bytes()).unwrap();
        session
            .set_expected_peer(passport.xid_document.to_cbor_data())
            .unwrap();
        let request_id = vec![5; REQUEST_ID_LEN];
        let signed_tx_ur = "ur:xmr-txsigned/1-1/lpadtest".to_string();

        let message = PassportMessage {
            message: QuantumLinkMessage::WdkMoneroSignTransactionResponse(
                WdkMoneroSignTransactionResponse {
                    protocol_version: WDK_PROTOCOL_VERSION,
                    request_id: request_id.clone(),
                    signed_tx_ur: signed_tx_ur.clone(),
                },
            ),
            status: DeviceStatus {
                version: "test".into(),
                battery_level: 100,
            },
            protocol_version: Some(PROTOCOL_VERSION),
        };
        let envelope = message.seal(
            (
                passport.private_keys.as_ref().unwrap(),
                &passport.xid_document,
            ),
            &phone.xid_document,
        );

        let mut decoded = None;
        for frame in frames(&envelope.to_cbor_data()) {
            decoded = session.feed(frame).unwrap().or(decoded);
        }
        let decoded = decoded.expect("signed transaction response should reassemble");
        assert_eq!(decoded.kind, "WdkMoneroSignTransactionResponse");
        assert_eq!(decoded.request_id, request_id);
        assert_eq!(decoded.signed_transaction_ur, signed_tx_ur);
    }

    #[test]
    fn decodes_authenticated_monero_verified_address_response() {
        let phone = QuantumLinkIdentity::generate();
        let passport = QuantumLinkIdentity::generate();
        let session = QlSession::new(phone.to_bytes()).unwrap();
        session
            .set_expected_peer(passport.xid_document.to_cbor_data())
            .unwrap();
        let request_id = vec![6; REQUEST_ID_LEN];
        let address =
            "48HHtdQvxyH5jwX5N6fAQD6rxx7EQT7GKZvsixtgJRkRaD8wHqwKp6eGSuStiUN5MHXR19vF3W4Jc7MumryYTTH7LGTfanS";

        let message = PassportMessage {
            message: QuantumLinkMessage::WdkMoneroVerifyAddressResponse(
                WdkMoneroVerifyAddressResponse {
                    protocol_version: WDK_PROTOCOL_VERSION,
                    request_id: request_id.clone(),
                    account_index: 2,
                    address_index: 7,
                    address: address.into(),
                },
            ),
            status: DeviceStatus {
                version: "test".into(),
                battery_level: 100,
            },
            protocol_version: Some(PROTOCOL_VERSION),
        };
        let envelope = message.seal(
            (
                passport.private_keys.as_ref().unwrap(),
                &passport.xid_document,
            ),
            &phone.xid_document,
        );

        let mut decoded = None;
        for frame in frames(&envelope.to_cbor_data()) {
            decoded = session.feed(frame).unwrap().or(decoded);
        }
        let decoded = decoded.expect("verified address response should reassemble");
        assert_eq!(decoded.kind, "WdkMoneroVerifyAddressResponse");
        assert_eq!(decoded.request_id, request_id);
        assert_eq!(decoded.account_index, 2);
        assert_eq!(decoded.address_index, 7);
        assert_eq!(decoded.address, address);
    }

    #[test]
    fn decodes_authenticated_monero_wallet_metadata() {
        let phone = QuantumLinkIdentity::generate();
        let passport = QuantumLinkIdentity::generate();
        let session = QlSession::new(phone.to_bytes()).unwrap();
        session
            .set_expected_peer(passport.xid_document.to_cbor_data())
            .unwrap();
        let address =
            "48HHtdQvxyH5jwX5N6fAQD6rxx7EQT7GKZvsixtgJRkRaD8wHqwKp6eGSuStiUN5MHXR19vF3W4Jc7MumryYTTH7LGTfanS";

        let message = PassportMessage {
            message: QuantumLinkMessage::WdkMoneroWalletMetadata(WdkMoneroWalletMetadata {
                protocol_version: WDK_PROTOCOL_VERSION,
                wallet_address: address.into(),
                wallet_name: "Travel Wallet".into(),
            }),
            status: DeviceStatus {
                version: "test".into(),
                battery_level: 100,
            },
            protocol_version: Some(PROTOCOL_VERSION),
        };
        let envelope = message.seal(
            (
                passport.private_keys.as_ref().unwrap(),
                &passport.xid_document,
            ),
            &phone.xid_document,
        );

        let mut decoded = None;
        for frame in frames(&envelope.to_cbor_data()) {
            decoded = session.feed(frame).unwrap().or(decoded);
        }
        let decoded = decoded.expect("wallet metadata should reassemble");
        assert_eq!(decoded.kind, "WdkMoneroWalletMetadata");
        assert_eq!(decoded.address, address);
        assert_eq!(decoded.wallet_name, "Travel Wallet");
    }

    #[test]
    fn decodes_removal_request_and_builds_acknowledgement() {
        let phone = QuantumLinkIdentity::generate();
        let passport = QuantumLinkIdentity::generate();
        let session = QlSession::new(phone.to_bytes()).unwrap();
        session
            .set_expected_peer(passport.xid_document.to_cbor_data())
            .unwrap();
        let request_id = vec![8; REQUEST_ID_LEN];
        let address =
            "48HHtdQvxyH5jwX5N6fAQD6rxx7EQT7GKZvsixtgJRkRaD8wHqwKp6eGSuStiUN5MHXR19vF3W4Jc7MumryYTTH7LGTfanS";
        let message = PassportMessage {
            message: QuantumLinkMessage::WdkMoneroWalletRemovalRequest(
                WdkMoneroWalletRemovalRequest {
                    protocol_version: WDK_PROTOCOL_VERSION,
                    request_id: request_id.clone(),
                    wallet_address: address.into(),
                    wallet_name: "Travel Wallet".into(),
                },
            ),
            status: DeviceStatus {
                version: "test".into(),
                battery_level: 100,
            },
            protocol_version: Some(PROTOCOL_VERSION),
        };
        let envelope = message.seal(
            (
                passport.private_keys.as_ref().unwrap(),
                &passport.xid_document,
            ),
            &phone.xid_document,
        );

        let mut decoded = None;
        for frame in frames(&envelope.to_cbor_data()) {
            decoded = session.feed(frame).unwrap().or(decoded);
        }
        let decoded = decoded.expect("wallet-removal request should reassemble");
        assert_eq!(decoded.kind, "WdkMoneroWalletRemovalRequest");
        assert_eq!(decoded.request_id, request_id);
        assert_eq!(decoded.address, address);
        assert_eq!(decoded.wallet_name, "Travel Wallet");
        assert!(!build_wdk_monero_wallet_removal_response(
            phone.to_bytes(),
            passport.xid_document.to_cbor_data(),
            request_id,
            address.into(),
            true,
        )
        .unwrap()
        .is_empty());
    }
}
