// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Wallet identity layer for the Cake signer.
//!
//! Slot 0 preserves the original shipped derivation exactly. Additional device
//! slots are domain-separated children of the KeyOS app seed. Imported Polyseed
//! and legacy Monero mnemonic phrases are stored encrypted under the app seed so
//! the signer can use them later without making Cake's accounts/subaddresses a
//! Prime-managed concept.

use std::collections::{BTreeMap, BTreeSet};

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use curve25519_dalek::scalar::Scalar;
use monero_seed::{Language as LegacyLanguage, Seed as LegacySeed};
use polyseed::{Language as PolyseedLanguage, Polyseed};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use super::{keccak256, keyimage::OutEntry, keys::MoneroKeys, Error, Result};

const SLOT_DOMAIN: &[u8] = b"foundation.cake-signer.wallet-slot.v1";
const STORE_AEAD_DOMAIN: &[u8] = b"foundation.cake-signer.wallet-store.aead.v1";
const STORE_NONCE_DOMAIN: &[u8] = b"foundation.cake-signer.wallet-store.nonce.v1";
const MAX_WALLETS: usize = 16;
// Cake uses wallet names as filenames, so keep Prime labels within Cake's
// cross-platform wallet-name contract.
const MAX_LABEL_CHARS: usize = 33;
const MAX_RECORD_ID_BYTES: usize = 96;
const MAX_SYNCED_OUTPUTS: usize = 8_192;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WalletKind {
    DeviceSlot,
    ImportedPolyseed,
    ImportedLegacy,
}

impl WalletKind {
    pub fn label(&self) -> &'static str {
        match self {
            WalletKind::DeviceSlot => "Prime-derived",
            WalletKind::ImportedPolyseed => "Imported Polyseed",
            WalletKind::ImportedLegacy => "Imported legacy seed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletRecord {
    pub id: String,
    pub label: String,
    pub kind: WalletKind,
    #[serde(default)]
    pub slot: u32,
    #[serde(default)]
    pub restore_height: u64,
    #[serde(default)]
    pub archived: bool,
    /// True once this wallet has participated in an authenticated Cake
    /// QuantumLink flow. Transport pairing is device-wide, but this flag keeps
    /// wallet-detail connection state scoped to the wallet Cake actually uses.
    #[serde(default)]
    pub cake_linked: bool,
    #[serde(default)]
    pub sealed_phrase: Option<SealedPhrase>,
    #[serde(default)]
    pub synced_outputs: BTreeMap<u32, OutEntry>,
}

impl WalletRecord {
    pub fn slot(slot: u32, restore_height: u64) -> Self {
        Self {
            id: slot_id(slot),
            label: if slot == 0 {
                "Passport Prime".into()
            } else {
                format!("Passport Prime {}", slot + 1)
            },
            kind: WalletKind::DeviceSlot,
            slot,
            restore_height,
            archived: false,
            cake_linked: false,
            sealed_phrase: None,
            synced_outputs: BTreeMap::new(),
        }
    }

    pub fn keys(&self, app_seed: &[u8; 32]) -> Result<MoneroKeys> {
        match self.kind {
            WalletKind::DeviceSlot => {
                Ok(MoneroKeys::from_app_seed(&slot_seed(app_seed, self.slot)))
            }
            WalletKind::ImportedPolyseed | WalletKind::ImportedLegacy => {
                let phrase = self.open_phrase(app_seed)?;
                let imported = ImportedSeed::parse_kind(&phrase, self.kind.clone())?;
                Ok(imported.keys)
            }
        }
    }

    pub fn seed_words(&self, app_seed: &[u8; 32]) -> Result<Zeroizing<String>> {
        match self.kind {
            WalletKind::DeviceSlot => Ok(MoneroKeys::seed_words(&slot_seed(app_seed, self.slot))),
            WalletKind::ImportedPolyseed | WalletKind::ImportedLegacy => self.open_phrase(app_seed),
        }
    }

    fn open_phrase(&self, app_seed: &[u8; 32]) -> Result<Zeroizing<String>> {
        let sealed = self
            .sealed_phrase
            .as_ref()
            .ok_or_else(|| Error::Seed("wallet seed is missing".into()))?;
        open_phrase(app_seed, &self.id, sealed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletBook {
    pub version: u32,
    pub selected_id: String,
    pub records: Vec<WalletRecord>,
}

impl WalletBook {
    pub fn new(default_restore_height: u64) -> Self {
        Self {
            version: 1,
            selected_id: slot_id(0),
            records: vec![WalletRecord::slot(0, default_restore_height)],
        }
    }

    pub fn normalize(&mut self, default_restore_height: u64) {
        self.version = 1;

        let selected_id = self.selected_id.clone();
        let mut seen_ids = BTreeSet::new();
        let mut seen_slots = BTreeSet::new();
        let mut records = Vec::with_capacity(self.records.len().min(MAX_WALLETS));

        for mut record in self.records.drain(..) {
            match record.kind {
                WalletKind::DeviceSlot => {
                    if record.slot as usize >= MAX_WALLETS {
                        continue;
                    }
                    let expected_id = slot_id(record.slot);
                    if record.id != expected_id || !seen_slots.insert(record.slot) {
                        continue;
                    }
                    if !seen_ids.insert(record.id.clone()) {
                        continue;
                    }
                    record.label = sanitize_label(&record.label, device_slot_label(record.slot));
                    record.restore_height = default_restore_height;
                    record.archived = record.slot != 0 && record.archived;
                    record.sealed_phrase = None;
                    trim_synced_outputs(&mut record.synced_outputs);
                    records.push(record);
                }
                WalletKind::ImportedPolyseed | WalletKind::ImportedLegacy => {
                    if record.sealed_phrase.is_none() || !is_valid_imported_id(&record.id) {
                        continue;
                    }
                    if !seen_ids.insert(record.id.clone()) {
                        continue;
                    }
                    record.label = sanitize_label(&record.label, record.kind.label().to_string());
                    record.slot = 0;
                    trim_synced_outputs(&mut record.synced_outputs);
                    records.push(record);
                }
            }
        }

        let slot_zero_id = slot_id(0);
        if let Some(pos) = records.iter().position(|r| r.id == slot_zero_id) {
            records.swap(0, pos);
            records[0].archived = false;
            records[0].restore_height = default_restore_height;
            records[0].sealed_phrase = None;
        } else {
            records.insert(0, WalletRecord::slot(0, default_restore_height));
        }
        if records.len() > MAX_WALLETS {
            records.truncate(MAX_WALLETS);
        }
        self.records = records;
        self.selected_id = selected_id;

        if self.selected().map(|r| r.archived).unwrap_or(true) {
            self.selected_id = self
                .records
                .iter()
                .find(|r| !r.archived)
                .map(|r| r.id.clone())
                .unwrap_or_else(|| slot_id(0));
        }
    }

    pub fn selected_index(&self) -> Option<usize> {
        self.records.iter().position(|r| r.id == self.selected_id)
    }

    pub fn selected(&self) -> Option<&WalletRecord> {
        self.selected_index().and_then(|i| self.records.get(i))
    }

    pub fn ensure_selected_usable(&mut self, app_seed: &[u8; 32]) -> bool {
        if self
            .selected()
            .filter(|wallet| !wallet.archived)
            .and_then(|wallet| wallet.keys(app_seed).ok())
            .is_some()
        {
            return false;
        }
        let Some(id) = self
            .records
            .iter()
            .filter(|wallet| !wallet.archived)
            .find(|wallet| wallet.keys(app_seed).is_ok())
            .map(|wallet| wallet.id.clone())
        else {
            return false;
        };
        self.selected_id = id;
        true
    }

    pub fn active_count(&self) -> usize {
        self.records.iter().filter(|r| !r.archived).count()
    }

    pub fn archived_count(&self) -> usize {
        self.records.iter().filter(|r| r.archived).count()
    }

    pub fn set_cake_linked(&mut self, id: &str, linked: bool) -> Result<bool> {
        let wallet = self
            .records
            .iter_mut()
            .find(|wallet| wallet.id == id)
            .ok_or_else(|| Error::Seed("wallet not found".into()))?;
        if linked && wallet.archived {
            return Err(Error::Seed(
                "archived wallet cannot be linked to Cake".into(),
            ));
        }
        let changed = wallet.cake_linked != linked;
        wallet.cake_linked = linked;
        Ok(changed)
    }

    pub fn clear_cake_links(&mut self) -> bool {
        let mut changed = false;
        for wallet in &mut self.records {
            changed |= wallet.cake_linked;
            wallet.cake_linked = false;
        }
        changed
    }

    pub fn can_archive_selected(&self) -> bool {
        self.selected()
            .map(|r| r.id != slot_id(0) && !r.archived)
            .unwrap_or(false)
            && self.active_count() > 1
    }

    pub fn can_restore_selected(&self) -> bool {
        self.selected()
            .map(|r| r.id != slot_id(0) && r.archived)
            .unwrap_or(false)
    }

    pub fn can_delete_selected(&self) -> bool {
        self.selected()
            .map(|r| r.id != slot_id(0) && r.archived)
            .unwrap_or(false)
            && self.records.len() > 1
    }

    pub fn select_next(&mut self) -> Option<&WalletRecord> {
        let active = self
            .records
            .iter()
            .enumerate()
            .filter(|(_, r)| !r.archived)
            .map(|(i, _)| i)
            .collect::<Vec<_>>();
        if active.is_empty() {
            return None;
        }
        let selected_pos = self
            .selected_index()
            .and_then(|i| active.iter().position(|candidate| *candidate == i))
            .unwrap_or(active.len().saturating_sub(1));
        let next = active[(selected_pos + 1) % active.len()];
        self.selected_id = self.records[next].id.clone();
        self.records.get(next)
    }

    pub fn select_id(&mut self, id: &str) -> Result<&WalletRecord> {
        let i = self
            .records
            .iter()
            .position(|r| r.id == id)
            .ok_or_else(|| Error::Seed("wallet not found".into()))?;
        self.selected_id = self.records[i].id.clone();
        Ok(&self.records[i])
    }

    pub fn add_device_slot(&mut self, default_restore_height: u64) -> Result<&WalletRecord> {
        if self.records.len() >= MAX_WALLETS {
            return Err(Error::Unsupported(format!(
                "maximum wallet count is {MAX_WALLETS}"
            )));
        }
        let next_slot = (1..MAX_WALLETS as u32)
            .find(|slot| {
                self.records
                    .iter()
                    .all(|r| !matches!(r.kind, WalletKind::DeviceSlot) || r.slot != *slot)
            })
            .ok_or_else(|| Error::Unsupported(format!("maximum wallet count is {MAX_WALLETS}")))?;
        let rec = WalletRecord::slot(next_slot, default_restore_height);
        self.selected_id = rec.id.clone();
        self.records.push(rec);
        Ok(self.records.last().expect("just pushed"))
    }

    pub fn rename_selected(&mut self, label: &str) -> Result<&WalletRecord> {
        let label = sanitize_label(label, String::new());
        if label.is_empty() {
            return Err(Error::Seed("wallet label required".into()));
        }
        let i = self
            .selected_index()
            .ok_or_else(|| Error::Seed("selected wallet missing".into()))?;
        self.records[i].label = label;
        Ok(&self.records[i])
    }

    pub fn delete_selected(&mut self) -> Result<WalletRecord> {
        if !self.can_delete_selected() {
            return Err(Error::Unsupported(
                "default wallet cannot be deleted".into(),
            ));
        }
        let i = self
            .selected_index()
            .ok_or_else(|| Error::Seed("selected wallet missing".into()))?;
        let removed = self.records.remove(i);
        self.selected_id = self
            .records
            .iter()
            .find(|wallet| !wallet.archived)
            .map(|r| r.id.clone())
            .unwrap_or_else(|| slot_id(0));
        Ok(removed)
    }

    pub fn import_seed(
        &mut self,
        app_seed: &[u8; 32],
        text: &str,
        imported_restore_height: u64,
    ) -> Result<&WalletRecord> {
        let imported = ImportedSeed::parse(text)?;
        if let Some(i) = self.records.iter().position(|r| r.id == imported.id) {
            self.records[i].archived = false;
            self.selected_id = self.records[i].id.clone();
            return self
                .selected()
                .ok_or_else(|| Error::Seed("selected imported wallet missing".into()));
        }
        if self.records.len() >= MAX_WALLETS {
            return Err(Error::Unsupported(format!(
                "maximum wallet count is {MAX_WALLETS}"
            )));
        }
        let count = self
            .records
            .iter()
            .filter(|r| r.kind == imported.kind)
            .count()
            + 1;
        let label = match imported.kind {
            WalletKind::ImportedPolyseed => format!("Imported Polyseed {count}"),
            WalletKind::ImportedLegacy => format!("Imported Legacy {count}"),
            WalletKind::DeviceSlot => unreachable!(),
        };
        let sealed_phrase = seal_phrase(app_seed, &imported.id, &imported.phrase)?;
        let rec = WalletRecord {
            id: imported.id.clone(),
            label,
            kind: imported.kind,
            slot: 0,
            restore_height: imported_restore_height,
            archived: false,
            cake_linked: false,
            sealed_phrase: Some(sealed_phrase),
            synced_outputs: BTreeMap::new(),
        };
        self.selected_id = rec.id.clone();
        self.records.push(rec);
        Ok(self.records.last().expect("just pushed"))
    }

    pub fn archive_selected(&mut self) -> Result<&WalletRecord> {
        if !self.can_archive_selected() {
            return Err(Error::Unsupported("this wallet cannot be archived".into()));
        }
        let i = self
            .selected_index()
            .ok_or_else(|| Error::Seed("selected wallet missing".into()))?;
        self.records[i].archived = true;
        Ok(&self.records[i])
    }

    pub fn restore_selected(&mut self) -> Result<&WalletRecord> {
        if !self.can_restore_selected() {
            return Err(Error::Unsupported("this wallet cannot be restored".into()));
        }
        let i = self
            .selected_index()
            .ok_or_else(|| Error::Seed("selected wallet missing".into()))?;
        self.records[i].archived = false;
        Ok(&self.records[i])
    }
}

pub fn to_json(book: &WalletBook) -> Result<String> {
    serde_json::to_string_pretty(book).map_err(|e| Error::Parse(format!("wallets serialize: {e}")))
}

pub fn from_json(s: &str, default_restore_height: u64) -> Result<WalletBook> {
    let mut book: WalletBook =
        serde_json::from_str(s).map_err(|e| Error::Parse(format!("wallets deserialize: {e}")))?;
    book.normalize(default_restore_height);
    Ok(book)
}

pub fn slot_seed(app_seed: &[u8; 32], slot: u32) -> [u8; 32] {
    if slot == 0 {
        return *app_seed;
    }
    let mut data = Vec::with_capacity(SLOT_DOMAIN.len() + 32 + 4);
    data.extend_from_slice(SLOT_DOMAIN);
    data.extend_from_slice(app_seed);
    data.extend_from_slice(&slot.to_le_bytes());
    keccak256(&data)
}

fn slot_id(slot: u32) -> String {
    format!("slot-{slot}")
}

fn device_slot_label(slot: u32) -> String {
    if slot == 0 {
        "Passport Prime".into()
    } else {
        format!("Passport Prime {}", slot + 1)
    }
}

fn sanitize_label(label: &str, fallback: String) -> String {
    let cleaned = label
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '_'))
        .take(MAX_LABEL_CHARS)
        .collect::<String>();
    if cleaned.is_empty() {
        fallback
    } else {
        cleaned
    }
}

fn trim_synced_outputs(outputs: &mut BTreeMap<u32, OutEntry>) {
    if outputs.len() <= MAX_SYNCED_OUTPUTS {
        return;
    }
    outputs.clear();
}

fn is_valid_imported_id(id: &str) -> bool {
    id.starts_with("import-")
        && id.len() <= MAX_RECORD_ID_BYTES
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedPhrase {
    pub nonce: String,
    pub ciphertext: String,
}

fn store_key(domain: &[u8], app_seed: &[u8; 32]) -> [u8; 32] {
    let mut data = Vec::with_capacity(domain.len() + app_seed.len());
    data.extend_from_slice(domain);
    data.extend_from_slice(app_seed);
    keccak256(&data)
}

fn seal_phrase(app_seed: &[u8; 32], id: &str, phrase: &str) -> Result<SealedPhrase> {
    let mut nonce_material =
        Vec::with_capacity(STORE_NONCE_DOMAIN.len() + 32 + id.len() + phrase.len());
    nonce_material.extend_from_slice(STORE_NONCE_DOMAIN);
    nonce_material.extend_from_slice(app_seed);
    nonce_material.extend_from_slice(id.as_bytes());
    nonce_material.extend_from_slice(phrase.as_bytes());
    let mut h1 = keccak256(&nonce_material);
    nonce_material.extend_from_slice(b".1");
    let mut h2 = keccak256(&nonce_material);
    let mut nonce = [0u8; 24];
    nonce[..16].copy_from_slice(&h1[..16]);
    nonce[16..].copy_from_slice(&h2[..8]);

    let key = Zeroizing::new(store_key(STORE_AEAD_DOMAIN, app_seed));
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: phrase.as_bytes(),
                aad: id.as_bytes(),
            },
        )
        .map_err(|_| Error::Seed("wallet seed encryption failed".into()))?;
    nonce_material.zeroize();
    h1.zeroize();
    h2.zeroize();
    let nonce_text = STANDARD_NO_PAD.encode(nonce);
    nonce.zeroize();
    Ok(SealedPhrase {
        nonce: nonce_text,
        ciphertext: STANDARD_NO_PAD.encode(&ciphertext),
    })
}

fn open_phrase(app_seed: &[u8; 32], id: &str, sealed: &SealedPhrase) -> Result<Zeroizing<String>> {
    let mut nonce = STANDARD_NO_PAD
        .decode(sealed.nonce.as_bytes())
        .map_err(|_| Error::Seed("wallet seed nonce is invalid".into()))?;
    if nonce.len() != 24 {
        return Err(Error::Seed("wallet seed nonce length is invalid".into()));
    }
    let mut ciphertext = STANDARD_NO_PAD
        .decode(sealed.ciphertext.as_bytes())
        .map_err(|_| Error::Seed("wallet seed ciphertext is invalid".into()))?;
    let key = Zeroizing::new(store_key(STORE_AEAD_DOMAIN, app_seed));
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: id.as_bytes(),
            },
        )
        .map_err(|_| {
            ciphertext.zeroize();
            nonce.zeroize();
            Error::Seed("wallet seed authentication failed".into())
        })?;
    ciphertext.zeroize();
    nonce.zeroize();
    match String::from_utf8(plaintext) {
        Ok(phrase) => Ok(Zeroizing::new(phrase)),
        Err(e) => {
            let mut bytes = e.into_bytes();
            bytes.zeroize();
            Err(Error::Seed("wallet seed is not UTF-8".into()))
        }
    }
}

struct ImportedSeed {
    id: String,
    kind: WalletKind,
    phrase: Zeroizing<String>,
    keys: MoneroKeys,
}

impl ImportedSeed {
    fn parse(text: &str) -> Result<Self> {
        let phrase = normalize_phrase(text);
        let word_count = phrase.split_whitespace().count();
        if word_count == 16 {
            if let Ok(seed) = Polyseed::from_string(PolyseedLanguage::English, phrase.clone()) {
                return Ok(Self::from_polyseed(seed));
            }
        }
        if word_count == 24 || word_count == 25 {
            for lang in LEGACY_LANGUAGES {
                if let Ok(seed) = LegacySeed::from_string(lang, phrase.clone()) {
                    return Ok(Self::from_legacy(seed, lang));
                }
            }
        }
        Err(Error::Seed(format!(
            "unsupported Monero seed: expected 16-word Polyseed or 24/25-word legacy seed, got {word_count} words"
        )))
    }

    fn parse_kind(phrase: &str, kind: WalletKind) -> Result<Self> {
        match kind {
            WalletKind::ImportedPolyseed => {
                let seed = Polyseed::from_string(
                    PolyseedLanguage::English,
                    Zeroizing::new(phrase.to_string()),
                )
                .map_err(|e| Error::Seed(format!("Polyseed parse failed: {e:?}")))?;
                Ok(Self::from_polyseed(seed))
            }
            WalletKind::ImportedLegacy => {
                let phrase = Zeroizing::new(phrase.to_string());
                for lang in LEGACY_LANGUAGES {
                    if let Ok(seed) = LegacySeed::from_string(lang, phrase.clone()) {
                        return Ok(Self::from_legacy(seed, lang));
                    }
                }
                Err(Error::Seed("legacy Monero seed parse failed".into()))
            }
            WalletKind::DeviceSlot => Err(Error::Seed(
                "device slots do not have imported phrases".into(),
            )),
        }
    }

    fn from_polyseed(seed: Polyseed) -> Self {
        let phrase = seed.to_string();
        let key = seed.key();
        let keys = MoneroKeys::from_spend_key_bytes(*key);
        Self {
            id: imported_id("polyseed", &phrase),
            kind: WalletKind::ImportedPolyseed,
            phrase,
            keys,
        }
    }

    fn from_legacy(seed: LegacySeed, language: LegacyLanguage) -> Self {
        let phrase = seed.to_string();
        let spend = seed.entropy();
        debug_assert!(bool::from(Scalar::from_canonical_bytes(*spend).is_some()));
        let keys = MoneroKeys::from_spend_key_bytes(*spend);
        let id = imported_id(legacy_language_label(language), &phrase);
        Self {
            id,
            kind: WalletKind::ImportedLegacy,
            phrase,
            keys,
        }
    }
}

fn normalize_phrase(text: &str) -> Zeroizing<String> {
    Zeroizing::new(text.split_whitespace().collect::<Vec<_>>().join(" "))
}

fn imported_id(kind: &str, phrase: &str) -> String {
    let mut data = Vec::with_capacity(kind.len() + phrase.len());
    data.extend_from_slice(kind.as_bytes());
    data.extend_from_slice(phrase.as_bytes());
    let h = keccak256(&data);
    format!("import-{}-{}", kind, hex::encode(&h[..8]))
}

const LEGACY_LANGUAGES: [LegacyLanguage; 13] = [
    LegacyLanguage::English,
    LegacyLanguage::DeprecatedEnglish,
    LegacyLanguage::Chinese,
    LegacyLanguage::Dutch,
    LegacyLanguage::French,
    LegacyLanguage::Spanish,
    LegacyLanguage::German,
    LegacyLanguage::Italian,
    LegacyLanguage::Portuguese,
    LegacyLanguage::Japanese,
    LegacyLanguage::Russian,
    LegacyLanguage::Esperanto,
    LegacyLanguage::Lojban,
];

fn legacy_language_label(language: LegacyLanguage) -> &'static str {
    match language {
        LegacyLanguage::Chinese => "legacy-chinese",
        LegacyLanguage::English => "legacy-english",
        LegacyLanguage::Dutch => "legacy-dutch",
        LegacyLanguage::French => "legacy-french",
        LegacyLanguage::Spanish => "legacy-spanish",
        LegacyLanguage::German => "legacy-german",
        LegacyLanguage::Italian => "legacy-italian",
        LegacyLanguage::Portuguese => "legacy-portuguese",
        LegacyLanguage::Japanese => "legacy-japanese",
        LegacyLanguage::Russian => "legacy-russian",
        LegacyLanguage::Esperanto => "legacy-esperanto",
        LegacyLanguage::Lojban => "legacy-lojban",
        LegacyLanguage::DeprecatedEnglish => "legacy-deprecated-english",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEV_SEED: [u8; 32] = [0x11; 32];

    #[test]
    fn slot_zero_preserves_app_seed_derivation() {
        assert_eq!(slot_seed(&DEV_SEED, 0), DEV_SEED);
        assert_ne!(slot_seed(&DEV_SEED, 1), DEV_SEED);
    }

    #[test]
    fn polyseed_import_round_trips() {
        let phrase = crate::monero::polyseed::seed_words(&DEV_SEED);
        let imported = ImportedSeed::parse(&phrase).unwrap();
        assert_eq!(imported.kind, WalletKind::ImportedPolyseed);
        assert_eq!(
            imported
                .keys
                .primary_address(super::super::Network::Mainnet),
            MoneroKeys::from_app_seed(&DEV_SEED).primary_address(super::super::Network::Mainnet)
        );
    }

    #[test]
    fn legacy_import_uses_monero_original_entropy() {
        let phrase = "washing thirsty occur lectures tuesday fainted toxic adapt \
                      abnormal memoir nylon mostly building shrugged online ember northern \
                      ruby woes dauntless boil family illness inroads northern";
        let imported = ImportedSeed::parse(phrase).unwrap();
        assert_eq!(imported.kind, WalletKind::ImportedLegacy);
        assert_eq!(
            hex::encode(imported.keys.spend_secret_bytes()),
            "c0af65c0dd837e666b9d0dfed62745f4df35aed7ea619b2798a709f0fe545403"
        );
    }

    #[test]
    fn sealed_phrase_authenticates() {
        let phrase = "alpha beta gamma";
        let sealed = seal_phrase(&DEV_SEED, "wallet", phrase).unwrap();
        assert_eq!(&*open_phrase(&DEV_SEED, "wallet", &sealed).unwrap(), phrase);
        assert!(open_phrase(&[0x22; 32], "wallet", &sealed).is_err());
    }

    #[test]
    fn wallet_book_starts_with_slot_zero() {
        let book = WalletBook::new(123);
        let selected = book.selected().unwrap();
        assert_eq!(selected.id, "slot-0");
        assert_eq!(selected.restore_height, 123);
    }

    #[test]
    fn wallet_delete_requires_archive_first() {
        let mut book = WalletBook::new(123);
        assert!(!book.can_delete_selected());
        assert!(book.delete_selected().is_err());
        book.add_device_slot(123).unwrap();
        assert!(!book.can_delete_selected());
        assert!(book.can_archive_selected());
        book.archive_selected().unwrap();
        book.select_id("slot-1").unwrap();
        assert!(book.can_restore_selected());
        assert!(book.can_delete_selected());
        let removed = book.delete_selected().unwrap();
        assert_eq!(removed.id, "slot-1");
        assert_eq!(book.selected().unwrap().id, "slot-0");
    }

    #[test]
    fn wallet_names_follow_cake_filename_rules() {
        let mut book = WalletBook::new(123);
        let renamed = book
            .rename_selected(" Travel/Wallet🙂_2026-with-a-very-long-suffix ")
            .unwrap();
        assert_eq!(renamed.label, "TravelWallet_2026-with-a-very-lon");
        assert_eq!(renamed.label.chars().count(), MAX_LABEL_CHARS);
    }

    #[test]
    fn device_slots_reuse_lowest_missing_index() {
        let mut book = WalletBook::new(123);
        assert_eq!(book.add_device_slot(123).unwrap().id, "slot-1");
        assert_eq!(book.add_device_slot(123).unwrap().id, "slot-2");
        book.select_id("slot-1").unwrap();
        book.archive_selected().unwrap();
        assert_eq!(book.delete_selected().unwrap().id, "slot-1");
        assert_eq!(book.add_device_slot(123).unwrap().id, "slot-1");
    }

    #[test]
    fn normalize_rejects_mismatched_device_slot_records() {
        let json = r#"{
          "version": 99,
          "selected_id": "slot-0",
          "records": [
            {
              "id": "slot-0",
              "label": "Looks like default",
              "kind": "DeviceSlot",
              "slot": 7,
              "restore_height": 999999999,
              "archived": true
            }
          ]
        }"#;
        let book = from_json(json, 123).unwrap();
        assert_eq!(book.version, 1);
        assert_eq!(book.records.len(), 1);
        let selected = book.selected().unwrap();
        assert_eq!(selected.id, "slot-0");
        assert_eq!(selected.slot, 0);
        assert_eq!(selected.restore_height, 123);
        assert!(!selected.archived);
        assert!(selected.synced_outputs.is_empty());
    }

    #[test]
    fn wallet_book_persists_synced_outputs() {
        let mut book = WalletBook::new(123);
        book.records[0].synced_outputs.insert(
            0,
            OutEntry {
                pubkey: [1; 32],
                tx_pubkey: [2; 32],
                additional: vec![[3; 32]],
                internal_idx: 4,
                major: 5,
                minor: 6,
            },
        );

        let json = to_json(&book).unwrap();
        let restored = from_json(&json, 123).unwrap();
        let entry = restored.records[0].synced_outputs.get(&0).unwrap();

        assert_eq!(entry.pubkey, [1; 32]);
        assert_eq!(entry.tx_pubkey, [2; 32]);
        assert_eq!(entry.additional, vec![[3; 32]]);
        assert_eq!(entry.internal_idx, 4);
        assert_eq!(entry.major, 5);
        assert_eq!(entry.minor, 6);
    }

    #[test]
    fn cake_link_state_is_scoped_to_each_wallet() {
        let mut book = WalletBook::new(123);
        book.set_cake_linked("slot-0", true).unwrap();
        book.add_device_slot(123).unwrap();
        book.set_cake_linked("slot-1", true).unwrap();

        assert!(book.selected().unwrap().cake_linked);
        assert!(
            book.records
                .iter()
                .find(|wallet| wallet.id == "slot-0")
                .unwrap()
                .cake_linked
        );

        book.set_cake_linked("slot-1", false).unwrap();
        assert!(!book.selected().unwrap().cake_linked);
        assert!(
            book.records
                .iter()
                .find(|wallet| wallet.id == "slot-0")
                .unwrap()
                .cake_linked
        );

        let restored = from_json(&to_json(&book).unwrap(), 123).unwrap();
        assert!(!restored.selected().unwrap().cake_linked);
        assert!(
            restored
                .records
                .iter()
                .find(|wallet| wallet.id == "slot-0")
                .unwrap()
                .cake_linked
        );

        let mut cleared = restored;
        assert!(cleared.clear_cake_links());
        assert!(cleared.records.iter().all(|wallet| !wallet.cake_linked));
        assert!(!cleared.clear_cake_links());
    }

    #[test]
    fn duplicate_import_restores_even_at_wallet_limit() {
        let phrase = crate::monero::polyseed::seed_words(&DEV_SEED);
        let mut book = WalletBook::new(123);
        let imported_id = book.import_seed(&DEV_SEED, &phrase, 0).unwrap().id.clone();
        book.archive_selected().unwrap();
        while book.records.len() < MAX_WALLETS {
            book.add_device_slot(123).unwrap();
        }
        let restored = book.import_seed(&DEV_SEED, &phrase, 0).unwrap();
        assert_eq!(restored.id, imported_id);
        assert!(!restored.archived);
    }

    #[test]
    fn unusable_selected_import_falls_back_to_slot_zero() {
        let phrase = crate::monero::polyseed::seed_words(&DEV_SEED);
        let mut book = WalletBook::new(123);
        let imported_id = book.import_seed(&DEV_SEED, &phrase, 0).unwrap().id.clone();
        let imported = book
            .records
            .iter_mut()
            .find(|wallet| wallet.id == imported_id)
            .unwrap();
        imported.sealed_phrase.as_mut().unwrap().ciphertext = "tampered".into();

        assert!(book.ensure_selected_usable(&DEV_SEED));
        assert_eq!(book.selected().unwrap().id, "slot-0");
    }
}
