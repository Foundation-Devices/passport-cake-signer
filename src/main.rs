// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Cake Wallet Signer — a Monero cold-signer for Passport Prime.
//!
//! Passport is NOT the wallet: Cake Wallet mobile (a watch-only wallet) builds
//! the transaction. This app holds the spend key, parses the unsigned tx,
//! shows what it does, and signs it. All Monero logic lives in `src/monero`.
//!
//! Transport is the easiest path: microSD/USB file exchange of the standard
//! wallet2 artifacts. QR (animated UR, CupCake-style) is a fast-follow.

#![allow(clippy::crate_in_macro_def)]

mod master_key;
mod monero;
mod qr;

use std::{
    cell::OnceCell,
    collections::{BTreeMap, HashMap, HashSet},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use gui_permissions::GuiPermissions;
use monero::{keys::MoneroKeys, signer, txset, wallets, Network, TxSummary};
use quantum_link::{
    foundation_api::wdk::{
        WdkMoneroKeyImageSyncResponse, WdkMoneroSignTransactionResponse,
        WdkMoneroWatchCredentialsResponse, WdkRequestRejected, WDK_PROTOCOL_VERSION,
    },
    messages::{
        PublishMoneroKeyImages, PublishMoneroSignedTransaction, PublishMoneroWatchCredentials,
        RejectWdkRequest, SubscribeMoneroKeyImageSyncRequest,
        SubscribeMoneroSignTransactionRequest, SubscribeMoneroWatchCredentialsRequest,
        SubscribeWdkRequestCancelled,
    },
};
use slint_keyos_platform::{
    app, async_archive,
    gui_server_api::navigation::{
        filepicker::{AllowedLocations, Location as PickLocation, SelectFileOptions},
        qrscanner::{ScanQrOptions, ScanQrResult},
    },
    navigation::{open_qr_scanner, select_file},
    slint::{ComponentHandle, ModelRc, SharedString, VecModel},
    spawn_local, spawn_worker, subscribe_archive,
};

// `app!` injects the permission-parameterized `FileSystem` alias (via
// fs::use_api!), the `AppWindow`/`Callbacks`/`TrId`/`AppContext` types, and the
// `tr` helpers — so we deliberately do NOT `use fs::FileSystem` (that raw,
// unparameterized type would shadow the alias and break the permission bounds).
app!("Cake");
quantum_link::use_api!();

use quantum_link_permissions::QuantumLinkPermissions;

// Mainnet: the real Cake Wallet mobile app is mainnet-only, so the pairing
// address must be a mainnet (`4…`) address. The signing code is network-agnostic
// (serai signs for whatever network the unsigned tx is on). Switch back to
// Stagenet only for offline CLI testing with monero-wallet-cli.
const DEFAULT_NETWORK: Network = Network::Mainnet;
const DATA_SUBDIR: &str = ".passport-cake-signer-keyos";
const EXPORT_DIR: &str = "cake"; // subdir used when the user picks a location root
const MAX_TXSET_BYTES: u64 = 4_194_304; // 4 MiB; Monero tx sets are larger than PSBTs
const MAX_TXSET_QR_BYTES: usize = MAX_TXSET_BYTES as usize;
const MAX_SEED_FILE_BYTES: u64 = 16_384;
const MAX_SEED_TEXT_CHARS: usize = 4_096;
const MAX_ADDRESS_QR_BYTES: usize = 512;
const MAX_CACHED_OUTPUTS_PER_WALLET: usize = 8_192;
const FEE_PER_WEIGHT: u64 = 20_000; // ≈ wallet2's fee; clears the network minimum
                                    // Restore height embedded in the view-only pairing QR (mainnet). Conservatively
                                    // set just BEFORE the wallet's Polyseed birthday (2026-01-01) so Cake's
                                    // watch-only scan never starts after a deposit, while skipping the full
                                    // from-genesis rescan. Underestimated on purpose: too low only costs scan time,
                                    // too high would miss funds. (The 16-word Polyseed carries its own birthday.)
const PAIR_RESTORE_HEIGHT: u64 = 3_400_000;

// File-exchange names for the Cake mobile watch-only wallet.
const VIEW_ONLY_FILE: &str = "cake-view-only.txt"; // address + private view key (one-time pairing)
const KEY_IMAGES_FILE: &str = "cake-key-images"; // exported key images
const SIGNED_TX_FILE: &str = "signed_monero_tx"; // wallet2 signed_tx_set; Cake imports to broadcast
const WALLET_BOOK_FILE: &str = "wallets.json";
const IMPORTED_RESTORE_HEIGHT: u64 = 0; // Imported seeds may be old; full scan is safest.
const VERIFY_ACCOUNT_LIMIT: u32 = 4;
const VERIFY_SUBADDRESS_LIMIT: u32 = 100;

thread_local! {
    static UI: OnceCell<AppWindow> = const { OnceCell::new() };
}

/// Live app state shared across UI callbacks.
struct AppState {
    app_seed: [u8; 32],
    network: Network,
    data_dir: PathBuf,
    wallet_book: wallets::WalletBook,
    /// The unsigned tx under review. The raw bytes are re-processed by the
    /// signer, and the wallet id prevents stale scans from surviving selection
    /// changes or long-running signer jobs.
    pending: Option<PendingTx>,
    /// The most recently produced signed_tx_set, for the animated-QR handoff
    /// to Cake (in addition to the file export).
    last_signed: Option<WalletArtifact>,
    /// The most recently produced key_image_export (answer to Cake's xmr-output
    /// sync), for the xmr-keyimage animated-QR handoff.
    last_keyimages: Option<WalletArtifact>,
    /// True while a signer thread is building the signed_tx_set.
    signing: bool,
    /// Monotonic guard for background unsigned-tx parsing jobs.
    tx_request_id: u64,
    /// Cache derived Monero addresses so repeated verification does not redo
    /// hundreds of scalar multiplications on the UI path.
    address_cache: HashMap<String, AddressHit>,
    /// Monotonic guard for background address verification jobs.
    verify_request_id: u64,
    /// QL request ids explicitly cancelled by Cake while a worker may still be
    /// parsing/signing. Workers are not interruptible, so completion checks this
    /// set before publishing a response.
    cancelled_ql_requests: HashSet<Vec<u8>>,
}

struct PendingTx {
    wallet_id: String,
    raw: Vec<u8>,
}

#[derive(Clone)]
struct WalletArtifact {
    wallet_id: String,
    bytes: Vec<u8>,
}

impl AppState {
    fn active_wallet(&self) -> monero::Result<&wallets::WalletRecord> {
        self.wallet_book
            .selected()
            .ok_or_else(|| monero::Error::Seed("no active wallet".into()))
    }

    fn keys(&self) -> monero::Result<MoneroKeys> {
        self.active_wallet()?.keys(&self.app_seed)
    }

    fn clear_wallet_artifacts(&mut self) {
        self.pending = None;
        self.last_signed = None;
        self.last_keyimages = None;
        self.signing = false;
    }

    fn invalidate_wallet_artifacts(&mut self) -> u64 {
        self.clear_wallet_artifacts();
        self.tx_request_id = self.tx_request_id.wrapping_add(1);
        self.tx_request_id
    }
}

fn app_main(_cx: AppContext, ui: AppWindow) {
    log_server::init_wait(env!("CARGO_CRATE_NAME")).unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("Starting Cake Wallet Signer");

    UI.with(|slot| {
        slot.set(ui.clone_strong()).ok();
    });

    let app_seed = match master_key::app_seed() {
        Ok(seed) => seed,
        Err(_) => {
            set_status(&ui, "App seed unavailable. Log in and reopen.");
            ui.run().expect("UI running");
            return;
        }
    };

    let data_dir = data_dir();
    #[cfg(not(keyos))]
    if let Err(e) = std::fs::create_dir_all(&data_dir) {
        log::error!("cannot create data dir {}: {e}", data_dir.display());
    }

    let mut wallet_book = load_wallet_book(&data_dir).unwrap_or_else(|e| {
        log::warn!("could not load wallet book: {e}");
        wallets::WalletBook::new(PAIR_RESTORE_HEIGHT)
    });
    if wallet_book.ensure_selected_usable(&app_seed) {
        if let Err(e) = save_wallet_book(&data_dir, &wallet_book) {
            log::warn!("could not persist wallet fallback selection: {e}");
        }
    }

    let state = Arc::new(Mutex::new(AppState {
        app_seed,
        network: DEFAULT_NETWORK,
        data_dir,
        wallet_book,
        pending: None,
        last_signed: None,
        last_keyimages: None,
        signing: false,
        tx_request_id: 0,
        address_cache: HashMap::new(),
        verify_request_id: 0,
        cancelled_ql_requests: HashSet::new(),
    }));

    // Warm the CryptoNight-derived chacha file key off the GUI thread. Software
    // CryptoNight on the Cortex-A5 takes ~5s, and every wallet2 decrypt/encrypt needs
    // the same key (it depends only on the view secret). Computing it now, while the
    // user is still on the home screen, means the first key-image sync / unsigned-tx
    // review / signing is instant instead of stalling after the scan.
    {
        let state = state.clone();
        std::thread::spawn(move || {
            if let Ok(keys) = state.lock().unwrap().keys() {
                let vs = keys.view_secret_bytes();
                txset::warm_chacha_key(&vs);
            }
        });
    }

    refresh_wallet_ui(&ui, &state);

    // -- export view-only credentials (one-time pairing) --------------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_export_view_only(move || {
            let Some(ui) = weak.upgrade() else { return };
            let st = state.lock().unwrap();
            let keys = match st.keys() {
                Ok(keys) => keys,
                Err(e) => {
                    drop(st);
                    set_status(&ui, &format!("{e}"));
                    return;
                }
            };
            let view_key = keys.private_view_key_hex();
            let address = keys.primary_address(st.network);
            let payload = format!("address: {address}\nview_key: {view_key}\n");
            drop(st);
            finish_export(
                &ui,
                VIEW_ONLY_FILE,
                payload.as_bytes(),
                "View-only wallet exported. Import it into Cake Wallet on your phone.",
            );
        });
    }

    // -- export key images --------------------------------------------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_export_key_images(move || {
            let Some(ui) = weak.upgrade() else { return };
            let st = state.lock().unwrap();
            let keys = match st.keys() {
                Ok(keys) => keys,
                Err(e) => {
                    drop(st);
                    set_status(&ui, &format!("{e}"));
                    return;
                }
            };
            // TODO: enumerate owned outputs + compute key images, then encode.
            match txset::encode_key_images(&[], &keys.private_view_key_hex()) {
                Ok(bytes) => {
                    drop(st);
                    finish_export(
                        &ui,
                        KEY_IMAGES_FILE,
                        &bytes,
                        "Key images exported. Import them into Cake Wallet to refresh spent status.",
                    );
                }
                Err(e) => set_status(&ui, &format!("Not ready: {e}")),
            }
        });
    }

    // -- import an unsigned tx and populate the review screen ----------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_import_unsigned_tx(move || {
            let Some(ui) = weak.upgrade() else { return };
            let bytes = match read_via_picker(MAX_TXSET_BYTES) {
                Ok(b) => b,
                Err(e) => {
                    let msg = format!("{e}");
                    if !msg.contains("cancelled") {
                        set_status(&ui, &msg);
                    }
                    return;
                }
            };
            load_unsigned_tx_for_wallet(&ui, &state, bytes);
        });
    }

    // -- prepare the static pairing QR (view-only credentials) --------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_prepare_pair_qr(move || {
            let Some(ui) = weak.upgrade() else { return };
            let st = state.lock().unwrap();
            let keys = match st.keys() {
                Ok(keys) => keys,
                Err(e) => {
                    drop(st);
                    set_status(&ui, &format!("{e}"));
                    return;
                }
            };
            let wallet = match st.active_wallet() {
                Ok(wallet) => wallet,
                Err(e) => {
                    drop(st);
                    set_status(&ui, &format!("{e}"));
                    return;
                }
            };
            let json = qr::pair_json(
                &wallet.label,
                &keys.primary_address(st.network),
                &keys.private_view_key_hex(),
                wallet.restore_height,
            );
            drop(st);
            ui.global::<Callbacks>().set_pair_json(json.into());
        });
    }

    // -- prepare the recovery-seed screen (16-word Polyseed) ----------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_prepare_seed_words(move || {
            let Some(ui) = weak.upgrade() else { return };
            let st = state.lock().unwrap();
            let words = match st.active_wallet().and_then(|w| w.seed_words(&st.app_seed)) {
                Ok(words) => words,
                Err(e) => {
                    drop(st);
                    set_status(&ui, &format!("{e}"));
                    return;
                }
            };
            drop(st);
            ui.global::<Callbacks>()
                .set_seed_qr_text(words.as_str().into());
            let words = words
                .split_whitespace()
                .map(SharedString::from)
                .collect::<Vec<SharedString>>();
            ui.global::<Callbacks>()
                .set_seed_words(ModelRc::new(VecModel::from(words)));
        });
    }
    {
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_clear_seed_words(move || {
            let Some(ui) = weak.upgrade() else { return };
            ui.global::<Callbacks>()
                .set_seed_words(ModelRc::<SharedString>::default());
            ui.global::<Callbacks>().set_seed_qr_text("".into());
        });
    }

    // -- wallet identity controls -----------------------------------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_switch_next_wallet(move || {
            let Some(ui) = weak.upgrade() else { return };
            let (data_dir, book) = {
                let mut st = state.lock().unwrap();
                if st.wallet_book.select_next().is_none() {
                    drop(st);
                    set_status(&ui, "No wallet slots available.");
                    return;
                }
                st.invalidate_wallet_artifacts();
                (st.data_dir.clone(), st.wallet_book.clone())
            };
            if let Err(e) = save_wallet_book(&data_dir, &book) {
                set_status(&ui, &format!("Could not save wallet selection: {e}"));
                return;
            }
            reset_transaction_ui(&ui);
            refresh_wallet_ui(&ui, &state);
            warm_active_wallet(&state);
            set_status(&ui, "");
        });
    }
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_add_device_wallet_slot(move || {
            let Some(ui) = weak.upgrade() else {
                return false;
            };
            let result = {
                let mut st = state.lock().unwrap();
                match st.wallet_book.add_device_slot(PAIR_RESTORE_HEIGHT) {
                    Ok(_) => {
                        st.invalidate_wallet_artifacts();
                        st.address_cache.clear();
                        Ok((st.data_dir.clone(), st.wallet_book.clone()))
                    }
                    Err(e) => Err(e),
                }
            };
            let (data_dir, book) = match result {
                Ok(result) => result,
                Err(e) => {
                    set_status(&ui, &format!("{e}"));
                    return false;
                }
            };
            if let Err(e) = save_wallet_book(&data_dir, &book) {
                set_status(&ui, &format!("Could not save wallet slot: {e}"));
                return false;
            }
            reset_transaction_ui(&ui);
            refresh_wallet_ui(&ui, &state);
            warm_active_wallet(&state);
            set_status(&ui, "");
            true
        });
    }
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_select_wallet(move |id| {
            let Some(ui) = weak.upgrade() else {
                return false;
            };
            select_wallet(&ui, &state, id.as_str(), true)
        });
    }
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>()
            .on_select_first_active_wallet(move || {
                let Some(ui) = weak.upgrade() else {
                    return false;
                };
                select_first_active_wallet(&ui, &state)
            });
    }
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_import_seed_text(move |seed| {
            let Some(ui) = weak.upgrade() else {
                return false;
            };
            import_seed_text(&ui, &state, seed.as_str(), IMPORTED_RESTORE_HEIGHT)
        });
    }
    {
        ui.global::<Callbacks>()
            .on_seed_import_preview(move |seed| seed_import_preview(seed.as_str()).into());
    }
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_import_seed_file(move || {
            let Some(ui) = weak.upgrade() else {
                return false;
            };
            let bytes = match read_via_picker(MAX_SEED_FILE_BYTES) {
                Ok(bytes) => bytes,
                Err(e) => {
                    let msg = format!("{e}");
                    if !msg.contains("cancelled") {
                        set_status(&ui, &msg);
                    }
                    return false;
                }
            };
            let phrase = match String::from_utf8(bytes) {
                Ok(phrase) => phrase,
                Err(_) => {
                    set_status(&ui, "Seed file must be UTF-8 text.");
                    return false;
                }
            };
            import_seed_text(&ui, &state, &phrase, IMPORTED_RESTORE_HEIGHT)
        });
    }
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_import_seed_qr(move || {
            let Some(ui) = weak.upgrade() else {
                return false;
            };
            import_seed_qr(&ui, &state)
        });
    }
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>()
            .on_rename_active_wallet(move |label| {
                let Some(ui) = weak.upgrade() else {
                    return false;
                };
                let result = {
                    let mut st = state.lock().unwrap();
                    match st.wallet_book.rename_selected(label.as_str()) {
                        Ok(_) => {
                            st.address_cache.clear();
                            Ok((st.data_dir.clone(), st.wallet_book.clone()))
                        }
                        Err(e) => Err(e),
                    }
                };
                let (data_dir, book) = match result {
                    Ok(result) => result,
                    Err(e) => {
                        set_status(&ui, &format!("{e}"));
                        return false;
                    }
                };
                if let Err(e) = save_wallet_book(&data_dir, &book) {
                    set_status(&ui, &format!("Could not save wallet label: {e}"));
                    return false;
                }
                refresh_wallet_ui(&ui, &state);
                set_status(&ui, "");
                true
            });
    }
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_archive_active_wallet(move || {
            let Some(ui) = weak.upgrade() else {
                return false;
            };
            let result = {
                let mut st = state.lock().unwrap();
                match st.wallet_book.archive_selected() {
                    Ok(_) => {
                        st.invalidate_wallet_artifacts();
                        st.address_cache.clear();
                        Ok((st.data_dir.clone(), st.wallet_book.clone()))
                    }
                    Err(e) => Err(e),
                }
            };
            let (data_dir, book) = match result {
                Ok(result) => result,
                Err(e) => {
                    set_status(&ui, &format!("{e}"));
                    return false;
                }
            };
            if let Err(e) = save_wallet_book(&data_dir, &book) {
                set_status(&ui, &format!("Could not save wallet archive: {e}"));
                return false;
            }
            reset_transaction_ui(&ui);
            refresh_wallet_ui(&ui, &state);
            warm_active_wallet(&state);
            set_status(&ui, "");
            true
        });
    }
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_restore_active_wallet(move || {
            let Some(ui) = weak.upgrade() else {
                return false;
            };
            let result = {
                let mut st = state.lock().unwrap();
                match st.wallet_book.restore_selected() {
                    Ok(_) => {
                        st.invalidate_wallet_artifacts();
                        st.address_cache.clear();
                        Ok((st.data_dir.clone(), st.wallet_book.clone()))
                    }
                    Err(e) => Err(e),
                }
            };
            let (data_dir, book) = match result {
                Ok(result) => result,
                Err(e) => {
                    set_status(&ui, &format!("{e}"));
                    return false;
                }
            };
            if let Err(e) = save_wallet_book(&data_dir, &book) {
                set_status(&ui, &format!("Could not save wallet restore: {e}"));
                return false;
            }
            reset_transaction_ui(&ui);
            refresh_wallet_ui(&ui, &state);
            warm_active_wallet(&state);
            set_status(&ui, "");
            true
        });
    }
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_delete_active_wallet(move || {
            let Some(ui) = weak.upgrade() else {
                return false;
            };
            let result = {
                let mut st = state.lock().unwrap();
                match st.wallet_book.delete_selected() {
                    Ok(_) => {
                        st.invalidate_wallet_artifacts();
                        st.address_cache.clear();
                        Ok((st.data_dir.clone(), st.wallet_book.clone()))
                    }
                    Err(e) => Err(e),
                }
            };
            let (data_dir, book) = match result {
                Ok(result) => result,
                Err(e) => {
                    set_status(&ui, &format!("{e}"));
                    return false;
                }
            };
            if let Err(e) = save_wallet_book(&data_dir, &book) {
                set_status(&ui, &format!("Could not save wallet deletion: {e}"));
                return false;
            }
            reset_transaction_ui(&ui);
            refresh_wallet_ui(&ui, &state);
            warm_active_wallet(&state);
            set_status(&ui, "");
            true
        });
    }
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_clear_verify_address(move || {
            let Some(ui) = weak.upgrade() else { return };
            bump_verify_request(&state);
            clear_verify_ui(&ui);
        });
    }
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_verify_address_scan(move || {
            let Some(ui) = weak.upgrade() else { return };
            verify_address_scan(&ui, &state);
        });
    }
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>()
            .on_verify_address_index(move |account, index| {
                let Some(ui) = weak.upgrade() else {
                    return false;
                };
                verify_address_index(&ui, &state, account.as_str(), index.as_str())
            });
    }

    // -- animated UR frames for the signed tx (Prime → Cake) ----------------
    {
        let state = state.clone();
        ui.global::<Callbacks>().on_get_signed_ur(move |max_size| {
            let st = state.lock().unwrap();
            let active_id = st.active_wallet().ok().map(|wallet| wallet.id.clone());
            match active_id
                .as_deref()
                .and_then(|id| artifact_bytes_for_wallet(id, &st.last_signed))
            {
                Some(blob) => qr::ur_parts(qr::UR_TX_SIGNED, blob, max_size),
                None => slint_keyos_platform::slint::ModelRc::default(),
            }
        });
    }

    // -- animated UR frames for the key images (Prime → Cake sync) -----------
    {
        let state = state.clone();
        ui.global::<Callbacks>()
            .on_get_keyimage_ur(move |max_size| {
                let st = state.lock().unwrap();
                let active_id = st.active_wallet().ok().map(|wallet| wallet.id.clone());
                match active_id
                    .as_deref()
                    .and_then(|id| artifact_bytes_for_wallet(id, &st.last_keyimages))
                {
                    Some(blob) => qr::ur_parts(qr::UR_KEY_IMAGE, blob, max_size),
                    None => slint_keyos_platform::slint::ModelRc::default(),
                }
            });
    }

    // -- scan an unsigned tx UR straight off Cake (Cake → Prime) ------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_scan_unsigned_tx(move || {
            let Some(ui) = weak.upgrade() else { return };
            ui.global::<Callbacks>().set_tx_loaded(false);
            ui.global::<Callbacks>().set_tx_loading(false);
            ui.global::<Callbacks>().set_keyimages_ready(false);
            ui.global::<Callbacks>().set_signed_ok(false);
            ui.global::<Callbacks>().set_signing(false);
            ui.global::<Callbacks>().set_status_text("".into());
            {
                let mut st = state.lock().unwrap();
                st.pending = None;
                st.last_signed = None;
                st.last_keyimages = None;
                st.signing = false;
            }
            let opts = ScanQrOptions {
                header_title: "Sign transaction".into(),
                message: "Show the animated code from Cake Wallet (Send → QR).".into(),
                ..ScanQrOptions::default()
            };
            let scan = match open_qr_scanner::<GuiPermissions>(opts) {
                Ok(Some(s)) => s,
                Ok(None) => return,
                Err(e) => {
                    set_status(&ui, &format!("Scanner error: {e:?}"));
                    return;
                }
            };
            ui.global::<Callbacks>().set_tx_loaded(false);
            ui.global::<Callbacks>().set_keyimages_ready(false);
            let (ur_type, data) = match scan {
                ScanQrResult::Ur2 { ur_type, data, .. } => (ur_type, data),
                // Single-frame / cancel / partial results: stay quiet (the scanner
                // re-fires as it assembles the multi-part UR from Cake).
                _ => return,
            };
            let raw = match qr::ur_payload_limited(&data, MAX_TXSET_QR_BYTES) {
                Ok(raw) => raw,
                Err(e) => {
                    set_status(&ui, e);
                    return;
                }
            };
            let mut st = state.lock().unwrap();
            let keys = match st.keys() {
                Ok(keys) => keys,
                Err(e) => {
                    drop(st);
                    set_status(&ui, &format!("{e}"));
                    return;
                }
            };
            if ur_type == qr::UR_OUTPUT {
                // Cake's key-image sync: import outputs, return key images.
                let wallet_id = match st.active_wallet() {
                    Ok(wallet) if !wallet.archived => wallet.id.clone(),
                    Ok(_) => {
                        drop(st);
                        set_status(&ui, "Restore this wallet before syncing key images.");
                        return;
                    }
                    Err(e) => {
                        drop(st);
                        set_status(&ui, &format!("{e}"));
                        return;
                    }
                };
                match monero::keyimage::parse_output_export_file(&raw, &keys) {
                    Some(export) if export.entries.is_empty() => {
                        drop(st);
                        set_status(
                            &ui,
                            "Cake did not send any outputs for key-image sync. Recreate the Cake watch-only wallet to force a full output export.",
                        );
                    }
                    Some(export) => {
                        let wallet = match st.wallet_book.records.iter_mut().find(|wallet| wallet.id == wallet_id) {
                            Some(wallet) => wallet,
                            None => {
                                drop(st);
                                set_status(&ui, "Selected wallet is missing.");
                                return;
                            }
                        };
                        let response_export = match cache_and_choose_keyimage_export(&mut wallet.synced_outputs, export) {
                            KeyImageSyncDecision::Export(response_export) => response_export,
                            KeyImageSyncDecision::MissingPrefix(missing) => {
                                let have = if missing.missing_from == 0 {
                                    "none".to_string()
                                } else {
                                    format!("0 through {}", missing.missing_from.saturating_sub(1))
                                };
                                drop(st);
                                set_status(
                                    &ui,
                                    &format!(
                                        "Prime needs Cake outputs 0 through {}. This scan has {have}. Switch Cake to Outputs (all), then scan again.",
                                        missing.total.saturating_sub(1)
                                    ),
                                );
                                return;
                            }
                        };
                        let save = (st.data_dir.clone(), st.wallet_book.clone());
                        let info = keyimage_sync_detail(&response_export);
                        let Some(ki) = monero::keyimage::build_key_image_export(&response_export, &keys) else {
                            drop(st);
                            set_status(&ui, "Could not build key images from those outputs.");
                            return;
                        };
                        st.last_keyimages = Some(WalletArtifact { wallet_id, bytes: ki });
                        drop(st);
                        if let Err(e) = save_wallet_book(&save.0, &save.1) {
                            set_status(&ui, &format!("Could not save Cake output sync: {e}"));
                            return;
                        }
                        ui.global::<Callbacks>().set_keyimage_sync_detail(info.into());
                        ui.global::<Callbacks>().set_keyimages_ready(true);
                        ui.global::<Callbacks>().set_status_text("".into());
                    }
                    None => {
                        drop(st);
                        set_status(&ui, "Could not build key images from those outputs.");
                    }
                }
            } else if ur_type == qr::UR_TX_UNSIGNED {
                drop(st);
                load_unsigned_tx_for_wallet(&ui, &state, raw);
            } else {
                drop(st);
                set_status(&ui, &format!("Unexpected QR type: {ur_type}"));
            }
        });
    }

    // -- sign the pending tx and cache the signed set for QR handoff ----------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_sign_transaction(move || {
            let Some(ui) = weak.upgrade() else { return };
            // Only the real-success path flips this true; the UI navigates to the
            // signed-QR screen ONLY when this is true (no fake success).
            ui.global::<Callbacks>().set_signed_ok(false);
            ui.global::<Callbacks>().set_signing(false);
            ui.global::<Callbacks>().set_status_text("".into());
            let (wallet_id, raw, keys, network) = {
                let mut st = state.lock().unwrap();
                if st.signing {
                    return;
                }
                st.last_signed = None;
                let Some(pending) = st.pending.as_ref() else {
                    drop(st);
                    set_status(&ui, "No transaction loaded.");
                    return;
                };
                let active_wallet = match st.active_wallet() {
                    Ok(wallet) => wallet,
                    Err(e) => {
                        drop(st);
                        set_status(&ui, &format!("{e}"));
                        return;
                    }
                };
                if active_wallet.archived {
                    drop(st);
                    set_status(&ui, "Restore this wallet before signing.");
                    return;
                }
                if pending.wallet_id != active_wallet.id {
                    drop(st);
                    set_status(&ui, wrong_wallet_sign_message());
                    return;
                }
                let keys = match st.keys() {
                    Ok(keys) => keys,
                    Err(e) => {
                        drop(st);
                        set_status(&ui, &format!("{e}"));
                        return;
                    }
                };
                let network = st.network;
                let wallet_id = pending.wallet_id.clone();
                let raw = pending.raw.clone();
                st.signing = true;
                (wallet_id, raw, keys, network)
            };
            ui.global::<Callbacks>().set_signing(true);

            let state = state.clone();
            std::thread::spawn(move || {
                // Sign the wallet2 unsigned tx with serai (CLSAG + Bulletproof+) and
                // package it as a wallet2 `signed_tx_set` — the exact file Cake loads
                // via "Import signed transaction" → submit_transfer. FEE_PER_WEIGHT
                // clears the network minimum (≈ the wallet2 fee).
                let result = signer::build_signed_tx_set(&raw, &keys, network, FEE_PER_WEIGHT);
                queue_with_ui(move |ui| {
                    let mut st = state.lock().unwrap();
                    st.signing = false;
                    let still_current = st
                        .active_wallet()
                        .map(|wallet| wallet.id == wallet_id)
                        .unwrap_or(false)
                        && st
                            .pending
                            .as_ref()
                            .map(|pending| pending.wallet_id == wallet_id)
                            .unwrap_or(false);
                    if !still_current {
                        drop(st);
                        ui.global::<Callbacks>().set_signing(false);
                        ui.global::<Callbacks>().set_signed_ok(false);
                        set_status(
                            ui,
                            "Wallet changed while signing. Scan the transaction again.",
                        );
                        return;
                    }
                    match result {
                        Ok(bytes) => {
                            // Stash for the animated-QR handoff. Saving to file is an
                            // explicit follow-up action on the QR screen.
                            st.last_signed = Some(WalletArtifact { wallet_id, bytes });
                            drop(st);
                            ui.global::<Callbacks>().set_signing(false);
                            ui.global::<Callbacks>().set_signed_ok(true);
                            ui.global::<Callbacks>().set_status_text("".into());
                        }
                        Err(signer::SignError::Decrypt) => {
                            drop(st);
                            ui.global::<Callbacks>().set_signing(false);
                            set_status(ui, wrong_wallet_sign_message());
                        }
                        Err(e) => {
                            drop(st);
                            ui.global::<Callbacks>().set_signing(false);
                            set_status(ui, &format!("Cannot sign: {e}"));
                        }
                    }
                });
            });
        });
    }

    // -- optional signed-tx file export --------------------------------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_save_signed_tx(move || {
            let Some(ui) = weak.upgrade() else { return };
            let st = state.lock().unwrap();
            let active_id = st.active_wallet().ok().map(|wallet| wallet.id.clone());
            let Some(bytes) = active_id
                .as_deref()
                .and_then(|id| artifact_bytes_for_wallet(id, &st.last_signed))
                .map(Vec::from)
            else {
                drop(st);
                set_status(&ui, "No signed transaction to save.");
                return;
            };
            drop(st);
            finish_export(
                &ui,
                SIGNED_TX_FILE,
                &bytes,
                "Saved signed_monero_tx to file.",
            );
        });
    }

    // Simulator only: seed the CLI-verified demo unsigned tx into user storage
    // so the file picker can select it (the pinned dev seed makes this wallet
    // match the fixture, so Import decodes it for real). No-op on device.
    // Stable filename + skip-if-present so repeated boots don't pile up suffixed
    // copies (`unsigned_monero_tx-001`, `-002`, …). The fixture is a STAGENET tx,
    // so only seed it on a stagenet build — on mainnet it would just fail to sign.
    #[cfg(not(target_os = "xous"))]
    if matches!(DEFAULT_NETWORK, Network::Stagenet) {
        const DEMO_UNSIGNED: &[u8] = include_bytes!("../resources/demo_unsigned_monero_tx");
        match seed_demo_unsigned("unsigned_monero_tx", DEMO_UNSIGNED) {
            Ok(p) => log::info!("demo unsigned tx ready at {p}"),
            Err(e) => log::warn!("could not seed demo unsigned tx: {e}"),
        }
    }

    init_quantum_link(&state);

    // No default status line — it only appears for real errors/progress.
    ui.run().expect("UI running");
}

// ---------------------------------------------------------------------------
// UI helpers
// ---------------------------------------------------------------------------

fn queue_with_ui(f: impl FnOnce(&AppWindow) + Send + 'static) {
    slint_keyos_platform::spawn(async move {
        UI.with(|ui| f(ui.get().expect("UI initialized")));
    })
    .detach();
}

fn init_quantum_link(state: &Arc<Mutex<AppState>>) {
    {
        let state = state.clone();
        spawn_local(async move {
            let mut events =
                subscribe_archive::<QuantumLinkPermissions, _>(SubscribeWdkRequestCancelled);
            while let Some(request) = events.next().await {
                mark_ql_request_cancelled(&state, request.request_id);
            }
        })
        .detach();
    }

    {
        let state = state.clone();
        spawn_local(async move {
            let mut events = subscribe_archive::<QuantumLinkPermissions, _>(
                SubscribeMoneroWatchCredentialsRequest,
            );
            while let Some(request) = events.next().await {
                begin_ql_request(&state, &request.request_id);
                let response = build_ql_watch_credentials(&state, request.request_id.clone());
                match response {
                    Ok(message) => {
                        if take_ql_request_cancelled(&state, &request.request_id) {
                            continue;
                        }
                        if let Err(e) = async_archive::<QuantumLinkPermissions, _>(message).await {
                            log::warn!("failed to publish Monero watch credentials over QL: {e:?}");
                        }
                    }
                    Err(message) => {
                        if !take_ql_request_cancelled(&state, &request.request_id) {
                            reject_wdk_request(request.request_id, message).await;
                        }
                    }
                }
            }
        })
        .detach();
    }

    {
        let state = state.clone();
        spawn_local(async move {
            let mut events =
                subscribe_archive::<QuantumLinkPermissions, _>(SubscribeMoneroKeyImageSyncRequest);
            while let Some(request) = events.next().await {
                begin_ql_request(&state, &request.request_id);
                let request_id = request.request_id.clone();
                let outputs_ur = request.outputs_ur.clone();
                let state = state.clone();
                let state_for_worker = state.clone();
                let result = spawn_worker(async move {
                    build_ql_key_image_ur(&state_for_worker, request_id.clone(), &outputs_ur)
                })
                .await;
                match result {
                    Ok(message) => {
                        if take_ql_request_cancelled(&state, &request.request_id) {
                            continue;
                        }
                        if let Err(e) = async_archive::<QuantumLinkPermissions, _>(message).await {
                            log::warn!("failed to publish Monero key images over QL: {e:?}");
                        }
                    }
                    Err(message) => {
                        if !take_ql_request_cancelled(&state, &request.request_id) {
                            reject_wdk_request(request.request_id, message).await;
                        }
                    }
                }
            }
        })
        .detach();
    }

    {
        let state = state.clone();
        spawn_local(async move {
            let mut events = subscribe_archive::<QuantumLinkPermissions, _>(
                SubscribeMoneroSignTransactionRequest,
            );
            while let Some(request) = events.next().await {
                begin_ql_request(&state, &request.request_id);
                let request_id = request.request_id.clone();
                let unsigned_tx_ur = request.unsigned_tx_ur.clone();
                let state = state.clone();
                let state_for_worker = state.clone();
                let result = spawn_worker(async move {
                    build_ql_signed_tx_ur(&state_for_worker, request_id.clone(), &unsigned_tx_ur)
                })
                .await;
                match result {
                    Ok(message) => {
                        if take_ql_request_cancelled(&state, &request.request_id) {
                            continue;
                        }
                        if let Err(e) = async_archive::<QuantumLinkPermissions, _>(message).await {
                            log::warn!(
                                "failed to publish Monero signed transaction over QL: {e:?}"
                            );
                        }
                    }
                    Err(message) => {
                        if !take_ql_request_cancelled(&state, &request.request_id) {
                            reject_wdk_request(request.request_id, message).await;
                        }
                    }
                }
            }
        })
        .detach();
    }
}

fn begin_ql_request(state: &Arc<Mutex<AppState>>, request_id: &[u8]) {
    state
        .lock()
        .unwrap()
        .cancelled_ql_requests
        .remove(request_id);
}

fn mark_ql_request_cancelled(state: &Arc<Mutex<AppState>>, request_id: Vec<u8>) {
    let mut st = state.lock().unwrap();
    if st.cancelled_ql_requests.len() >= 64 {
        st.cancelled_ql_requests.clear();
    }
    st.cancelled_ql_requests.insert(request_id);
}

fn take_ql_request_cancelled(state: &Arc<Mutex<AppState>>, request_id: &[u8]) -> bool {
    state
        .lock()
        .unwrap()
        .cancelled_ql_requests
        .remove(request_id)
}

fn build_ql_watch_credentials(
    state: &Arc<Mutex<AppState>>,
    request_id: Vec<u8>,
) -> Result<PublishMoneroWatchCredentials, String> {
    let st = state.lock().unwrap();
    let wallet = st.active_wallet().map_err(|e| format!("{e}"))?;
    if wallet.archived {
        return Err("Restore this wallet before pairing it with Cake.".into());
    }
    let keys = wallet.keys(&st.app_seed).map_err(|e| format!("{e}"))?;
    Ok(PublishMoneroWatchCredentials {
        response: WdkMoneroWatchCredentialsResponse {
            protocol_version: WDK_PROTOCOL_VERSION,
            request_id,
            address: keys.primary_address(st.network),
            watch_key: keys.private_view_key_hex(),
            restore_height: Some(wallet.restore_height),
        },
    })
}

fn build_ql_key_image_ur(
    state: &Arc<Mutex<AppState>>,
    request_id: Vec<u8>,
    outputs_ur: &str,
) -> Result<PublishMoneroKeyImages, String> {
    let raw = qr::ur_text_payload_limited(outputs_ur, qr::UR_OUTPUT, MAX_TXSET_QR_BYTES)
        .map_err(str::to_string)?;

    let (key_images, save) = {
        let mut st = state.lock().unwrap();
        let app_seed = st.app_seed;
        let mut matched = None;

        for (index, wallet) in st.wallet_book.records.iter().enumerate() {
            if wallet.archived {
                continue;
            }
            let Ok(keys) = wallet.keys(&app_seed) else {
                continue;
            };
            if let Some(export) = monero::keyimage::parse_output_export_file(&raw, &keys) {
                matched = Some((index, wallet.id.clone(), keys, export));
                break;
            }
        }

        let Some((index, wallet_id, keys, export)) = matched else {
            return Err("These Cake outputs do not match any active Prime wallet.".into());
        };
        if export.entries.is_empty() {
            return Err("Cake did not send any outputs for key-image sync.".into());
        }

        let response_export = {
            let wallet = &mut st.wallet_book.records[index];
            match cache_and_choose_keyimage_export(&mut wallet.synced_outputs, export) {
                KeyImageSyncDecision::Export(response_export) => response_export,
                KeyImageSyncDecision::MissingPrefix(missing) => {
                    return Err(format!(
                        "Prime needs Cake outputs 0 through {} before it can sync spent outputs.",
                        missing.total.saturating_sub(1)
                    ));
                }
            }
        };

        let key_images = monero::keyimage::build_key_image_export(&response_export, &keys)
            .ok_or_else(|| "Could not build key images from those outputs.".to_string())?;
        st.last_keyimages = Some(WalletArtifact {
            wallet_id,
            bytes: key_images.clone(),
        });
        (key_images, (st.data_dir.clone(), st.wallet_book.clone()))
    };

    if let Err(e) = save_wallet_book(&save.0, &save.1) {
        log::warn!("could not persist QL key-image sync cache: {e}");
    }

    Ok(PublishMoneroKeyImages {
        response: WdkMoneroKeyImageSyncResponse {
            protocol_version: WDK_PROTOCOL_VERSION,
            request_id,
            key_images_ur: qr::ur_string(qr::UR_KEY_IMAGE, &key_images, 500),
        },
    })
}

fn build_ql_signed_tx_ur(
    state: &Arc<Mutex<AppState>>,
    request_id: Vec<u8>,
    unsigned_tx_ur: &str,
) -> Result<PublishMoneroSignedTransaction, String> {
    let raw = qr::ur_text_payload_limited(unsigned_tx_ur, qr::UR_TX_UNSIGNED, MAX_TXSET_QR_BYTES)
        .map_err(str::to_string)?;

    let (wallet_id, keys, network) = find_ql_signing_wallet(state, &raw)?;
    let signed = signer::build_signed_tx_set(&raw, &keys, network, FEE_PER_WEIGHT)
        .map_err(|e| format!("Cannot sign: {e}"))?;

    {
        let mut st = state.lock().unwrap();
        st.last_signed = Some(WalletArtifact {
            wallet_id,
            bytes: signed.clone(),
        });
    }

    Ok(PublishMoneroSignedTransaction {
        response: WdkMoneroSignTransactionResponse {
            protocol_version: WDK_PROTOCOL_VERSION,
            request_id,
            signed_tx_ur: qr::ur_string(qr::UR_TX_SIGNED, &signed, 500),
        },
    })
}

fn find_ql_signing_wallet(
    state: &Arc<Mutex<AppState>>,
    raw: &[u8],
) -> Result<(String, MoneroKeys, Network), String> {
    let st = state.lock().unwrap();
    let app_seed = st.app_seed;
    let network = st.network;

    let mut last_parse_error = None;
    for wallet in &st.wallet_book.records {
        if wallet.archived {
            continue;
        }
        let Ok(keys) = wallet.keys(&app_seed) else {
            continue;
        };
        let view_secret = keys.view_secret_bytes();
        let spend_pub = keys.public_spend();
        match txset::UnsignedTxSet::parse(raw, &view_secret, &spend_pub, network) {
            Ok(_) => return Ok((wallet.id.clone(), keys, network)),
            Err(e) if is_wrong_wallet_tx_error(&e) => {}
            Err(e) => last_parse_error = Some(e),
        }
    }

    if let Some(e) = last_parse_error {
        Err(friendly_unsigned_tx_error(&e))
    } else {
        Err("This transaction does not match any active Prime wallet.".into())
    }
}

async fn reject_wdk_request(request_id: Vec<u8>, message: String) {
    let rejection = RejectWdkRequest {
        response: WdkRequestRejected {
            protocol_version: WDK_PROTOCOL_VERSION,
            request_id,
            reason_code: 1,
            message,
        },
    };
    if let Err(e) = async_archive::<QuantumLinkPermissions, _>(rejection).await {
        log::warn!("failed to reject WDK request over QL: {e:?}");
    }
}

fn load_unsigned_tx_for_wallet(ui: &AppWindow, state: &Arc<Mutex<AppState>>, bytes: Vec<u8>) {
    reset_transaction_ui(ui);
    let request_id = {
        let mut st = state.lock().unwrap();
        st.invalidate_wallet_artifacts()
    };
    ui.global::<Callbacks>().set_tx_loading(true);
    set_status(ui, "Reading transaction...");

    let state = state.clone();
    std::thread::spawn(move || {
        let result = prepare_unsigned_tx_for_wallet(&state, request_id, bytes);
        queue_with_ui(move |ui| {
            if state.lock().unwrap().tx_request_id != request_id {
                return;
            }
            ui.global::<Callbacks>().set_tx_loading(false);
            match result {
                LoadUnsignedTxResult::Loaded { summary } => {
                    refresh_wallet_ui(ui, &state);
                    warm_active_wallet(&state);
                    populate_review(ui, &summary);
                    ui.global::<Callbacks>().set_tx_loaded(true);
                    ui.global::<Callbacks>().set_status_text("".into());
                }
                LoadUnsignedTxResult::Error(message) => {
                    ui.global::<Callbacks>().set_tx_loaded(false);
                    set_status(ui, &message);
                }
                LoadUnsignedTxResult::Stale => {}
            }
        });
    });
}

enum LoadUnsignedTxResult {
    Loaded { summary: TxSummary },
    Error(String),
    Stale,
}

fn prepare_unsigned_tx_for_wallet(
    state: &Arc<Mutex<AppState>>,
    request_id: u64,
    bytes: Vec<u8>,
) -> LoadUnsignedTxResult {
    let active = {
        let st = state.lock().unwrap();
        if st.tx_request_id != request_id {
            return LoadUnsignedTxResult::Stale;
        }
        let wallet = match st.active_wallet() {
            Ok(wallet) => wallet.clone(),
            Err(e) => {
                return LoadUnsignedTxResult::Error(format!("{e}"));
            }
        };
        if wallet.archived {
            return LoadUnsignedTxResult::Error("Restore this wallet before signing.".into());
        }
        let keys = match wallet.keys(&st.app_seed) {
            Ok(keys) => keys,
            Err(e) => {
                return LoadUnsignedTxResult::Error(format!("{e}"));
            }
        };
        (wallet, keys, st.network)
    };

    let view_secret = active.1.view_secret_bytes();
    let spend_pub = active.1.public_spend();
    match txset::UnsignedTxSet::parse(&bytes, &view_secret, &spend_pub, active.2) {
        Ok(unsigned) => {
            return store_loaded_unsigned_tx(
                state,
                request_id,
                active.0.id.clone(),
                unsigned,
                bytes,
            );
        }
        Err(e) if !is_wrong_wallet_tx_error(&e) => {
            return LoadUnsignedTxResult::Error(friendly_unsigned_tx_error(&e));
        }
        Err(_) => {}
    }

    match find_matching_unsigned_tx_wallet(state, &active.0.id, &bytes) {
        WalletTxMatch::Other { wallet, unsigned } => {
            if wallet.archived {
                return LoadUnsignedTxResult::Error(format!(
                    "This transaction belongs to archived wallet \"{}\". Restore that wallet before signing.",
                    wallet.label
                ));
            }

            let summary = unsigned.summary().clone();
            let save = {
                let mut st = state.lock().unwrap();
                if st.tx_request_id != request_id {
                    return LoadUnsignedTxResult::Stale;
                }
                if let Err(e) = st.wallet_book.select_id(&wallet.id) {
                    return LoadUnsignedTxResult::Error(format!("{e}"));
                }
                st.clear_wallet_artifacts();
                let data_dir = st.data_dir.clone();
                let book = st.wallet_book.clone();
                st.pending = Some(PendingTx {
                    wallet_id: wallet.id.clone(),
                    raw: bytes,
                });
                (data_dir, book)
            };
            if let Err(e) = save_wallet_book(&save.0, &save.1) {
                log::warn!("could not persist wallet switch for transaction: {e}");
            }
            LoadUnsignedTxResult::Loaded { summary }
        }
        WalletTxMatch::ParseError { wallet, error } => LoadUnsignedTxResult::Error(format!(
            "This transaction appears to belong to \"{}\", but Prime could not read it: {}",
            wallet.label,
            friendly_unsigned_tx_error(&error)
        )),
        WalletTxMatch::None => LoadUnsignedTxResult::Error(wrong_wallet_load_message().into()),
    }
}

enum WalletTxMatch {
    Other {
        wallet: wallets::WalletRecord,
        unsigned: txset::UnsignedTxSet,
    },
    ParseError {
        wallet: wallets::WalletRecord,
        error: monero::Error,
    },
    None,
}

fn find_matching_unsigned_tx_wallet(
    state: &Arc<Mutex<AppState>>,
    active_id: &str,
    bytes: &[u8],
) -> WalletTxMatch {
    let (wallets, app_seed, network) = {
        let st = state.lock().unwrap();
        (st.wallet_book.records.clone(), st.app_seed, st.network)
    };

    for wallet in wallets {
        if wallet.id == active_id {
            continue;
        }
        let Ok(keys) = wallet.keys(&app_seed) else {
            continue;
        };
        let view_secret = keys.view_secret_bytes();
        let spend_pub = keys.public_spend();
        match txset::UnsignedTxSet::parse(bytes, &view_secret, &spend_pub, network) {
            Ok(unsigned) => return WalletTxMatch::Other { wallet, unsigned },
            Err(e) if !is_wrong_wallet_tx_error(&e) => {
                return WalletTxMatch::ParseError { wallet, error: e };
            }
            Err(_) => {}
        }
    }

    WalletTxMatch::None
}

fn store_loaded_unsigned_tx(
    state: &Arc<Mutex<AppState>>,
    request_id: u64,
    wallet_id: String,
    unsigned: txset::UnsignedTxSet,
    bytes: Vec<u8>,
) -> LoadUnsignedTxResult {
    let summary = unsigned.summary().clone();
    let mut st = state.lock().unwrap();
    if st.tx_request_id != request_id {
        return LoadUnsignedTxResult::Stale;
    }
    st.pending = Some(PendingTx {
        wallet_id,
        raw: bytes,
    });
    st.last_signed = None;
    st.last_keyimages = None;
    LoadUnsignedTxResult::Loaded { summary }
}

fn is_wrong_wallet_tx_error(error: &monero::Error) -> bool {
    matches!(error, monero::Error::Parse(msg) if msg.contains("authentication signature invalid"))
}

fn friendly_unsigned_tx_error(error: &monero::Error) -> String {
    match error {
        monero::Error::Parse(msg) if msg.contains("bad magic") => {
            "This is not a Monero unsigned transaction from Cake.".into()
        }
        monero::Error::Parse(msg) if msg.contains("too short") => {
            "The transaction data is incomplete. Scan the whole animated QR again.".into()
        }
        _ => format!("{error}"),
    }
}

fn wrong_wallet_load_message() -> &'static str {
    "This transaction does not match the selected Prime wallet. It may belong to another Cake wallet, or the scan/file may be incomplete."
}

fn wrong_wallet_sign_message() -> &'static str {
    "This transaction no longer matches the selected wallet. Open the wallet paired with Cake and scan the transaction again."
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MissingKeyImagePrefix {
    missing_from: u32,
    total: u32,
}

enum KeyImageSyncDecision {
    Export(monero::keyimage::OutputExport),
    MissingPrefix(MissingKeyImagePrefix),
}

fn cache_and_choose_keyimage_export(
    cache: &mut BTreeMap<u32, monero::keyimage::OutEntry>,
    export: monero::keyimage::OutputExport,
) -> KeyImageSyncDecision {
    if cache.len() > MAX_CACHED_OUTPUTS_PER_WALLET
        || export.total as usize > MAX_CACHED_OUTPUTS_PER_WALLET
    {
        cache.clear();
    }
    for (i, entry) in export.entries.iter().cloned().enumerate() {
        let Some(index) = export.offset.checked_add(i as u32) else {
            break;
        };
        if cache.len() >= MAX_CACHED_OUTPUTS_PER_WALLET && !cache.contains_key(&index) {
            cache.clear();
            return KeyImageSyncDecision::MissingPrefix(MissingKeyImagePrefix {
                missing_from: 0,
                total: export.total,
            });
        }
        cache.insert(index, entry);
    }

    let mut cached_entries = Vec::new();
    let mut index = 0u32;
    while let Some(entry) = cache.get(&index) {
        cached_entries.push(entry.clone());
        index = index.saturating_add(1);
        if index == u32::MAX {
            break;
        }
    }

    if index >= export.total {
        cached_entries.truncate(export.total as usize);
        return KeyImageSyncDecision::Export(monero::keyimage::OutputExport {
            offset: 0,
            total: export.total,
            entries: cached_entries,
        });
    }

    KeyImageSyncDecision::MissingPrefix(MissingKeyImagePrefix {
        missing_from: index,
        total: export.total,
    })
}

fn keyimage_sync_detail(export: &monero::keyimage::OutputExport) -> String {
    let count = export.entries.len();
    let end = export.offset.saturating_add(count.saturating_sub(1) as u32);
    if count == 1 {
        format!(
            "Returning key image for Cake output {} of {}.",
            export.offset, export.total
        )
    } else if export.offset == 0 {
        format!(
            "Returning {count} key images from Cake output 0 through {end} of {}.",
            export.total
        )
    } else {
        format!(
            "Returning {count} key images from Cake output {} through {end}. If Cake still says a key image is missing, recreate the Cake watch-only wallet to force a full sync.",
            export.offset
        )
    }
}

fn artifact_bytes_for_wallet<'a>(
    wallet_id: &str,
    artifact: &'a Option<WalletArtifact>,
) -> Option<&'a [u8]> {
    let artifact = artifact.as_ref()?;
    (artifact.wallet_id == wallet_id).then_some(artifact.bytes.as_slice())
}

fn set_status(ui: &AppWindow, msg: &str) {
    ui.global::<Callbacks>().set_status_text(msg.into());
}

fn reset_transaction_ui(ui: &AppWindow) {
    let cb = ui.global::<Callbacks>();
    cb.set_tx_loaded(false);
    cb.set_tx_loading(false);
    cb.set_keyimages_ready(false);
    cb.set_keyimage_sync_detail("".into());
    cb.set_signed_ok(false);
    cb.set_signing(false);
    cb.set_dest_address("".into());
    cb.set_dest_addresses(model_from_strings(Vec::new()));
    cb.set_dest_address_labels(model_from_strings(Vec::new()));
}

fn clear_verify_ui(ui: &AppWindow) {
    let cb = ui.global::<Callbacks>();
    cb.set_verify_ready(false);
    cb.set_verify_matched(false);
    cb.set_verify_title("".into());
    cb.set_verify_detail("".into());
    cb.set_verify_address("".into());
}

fn refresh_wallet_ui(ui: &AppWindow, state: &Arc<Mutex<AppState>>) {
    let cb = ui.global::<Callbacks>();
    let st = state.lock().unwrap();
    match st
        .active_wallet()
        .and_then(|wallet| wallet.keys(&st.app_seed).map(|keys| (wallet, keys)))
    {
        Ok((wallet, keys)) => {
            let address = keys.primary_address(st.network);
            let active_rows = st
                .wallet_book
                .records
                .iter()
                .filter(|wallet| !wallet.archived)
                .map(wallet_row)
                .collect::<Vec<_>>();
            let archived_rows = st
                .wallet_book
                .records
                .iter()
                .filter(|wallet| wallet.archived)
                .map(wallet_row)
                .collect::<Vec<_>>();
            cb.set_wallet_label(wallet.label.clone().into());
            cb.set_wallet_rename_value(wallet.label.clone().into());
            cb.set_wallet_id(wallet.id.clone().into());
            cb.set_wallet_kind(wallet.kind.label().into());
            cb.set_wallet_address(truncate(&address).into());
            cb.set_wallet_address_full(address.clone().into());
            cb.set_wallet_detail("".into());
            cb.set_wallet_list(model_from_strings(Vec::new()));
            cb.set_wallets(ModelRc::new(VecModel::from(active_rows)));
            cb.set_archived_wallets(ModelRc::new(VecModel::from(archived_rows)));
            cb.set_wallet_derived(matches!(wallet.kind, wallets::WalletKind::DeviceSlot));
            cb.set_wallet_count(st.wallet_book.active_count() as i32);
            cb.set_archived_wallet_count(st.wallet_book.archived_count() as i32);
            cb.set_wallet_archived(wallet.archived);
            cb.set_wallet_can_archive(st.wallet_book.can_archive_selected());
            cb.set_wallet_can_restore(st.wallet_book.can_restore_selected());
            cb.set_wallet_can_delete(st.wallet_book.can_delete_selected());
            cb.set_primary_address(truncate(&address).into());
        }
        Err(e) => {
            let active_rows = st
                .wallet_book
                .records
                .iter()
                .filter(|wallet| !wallet.archived)
                .map(wallet_row)
                .collect::<Vec<_>>();
            let archived_rows = st
                .wallet_book
                .records
                .iter()
                .filter(|wallet| wallet.archived)
                .map(wallet_row)
                .collect::<Vec<_>>();
            cb.set_wallet_id("".into());
            cb.set_wallet_label("Wallet unavailable".into());
            cb.set_wallet_rename_value("".into());
            cb.set_wallet_kind("Error".into());
            cb.set_wallet_address("".into());
            cb.set_wallet_address_full("".into());
            cb.set_wallet_detail("".into());
            cb.set_wallet_list(model_from_strings(Vec::new()));
            cb.set_wallets(ModelRc::new(VecModel::from(active_rows)));
            cb.set_archived_wallets(ModelRc::new(VecModel::from(archived_rows)));
            cb.set_wallet_derived(false);
            cb.set_wallet_count(st.wallet_book.active_count() as i32);
            cb.set_archived_wallet_count(st.wallet_book.archived_count() as i32);
            cb.set_wallet_archived(false);
            cb.set_wallet_can_archive(false);
            cb.set_wallet_can_restore(false);
            cb.set_wallet_can_delete(false);
            cb.set_primary_address("".into());
            cb.set_status_text(format!("{e}").into());
        }
    }
}

fn wallet_row(wallet: &wallets::WalletRecord) -> WalletRow {
    WalletRow {
        id: wallet.id.clone().into(),
        name: wallet.label.clone().into(),
        kind: wallet.kind.label().into(),
        address: "".into(),
        detail: "".into(),
        archived: wallet.archived,
        derived: matches!(wallet.kind, wallets::WalletKind::DeviceSlot),
    }
}

fn model_from_strings(values: Vec<String>) -> ModelRc<SharedString> {
    let values = values
        .into_iter()
        .map(SharedString::from)
        .collect::<Vec<_>>();
    ModelRc::new(VecModel::from(values))
}

fn warm_active_wallet(state: &Arc<Mutex<AppState>>) {
    let wallet_seed = {
        let st = state.lock().unwrap();
        st.active_wallet()
            .ok()
            .cloned()
            .map(|wallet| (wallet, st.app_seed))
    };
    if let Some((wallet, app_seed)) = wallet_seed {
        std::thread::spawn(move || {
            let Ok(keys) = wallet.keys(&app_seed) else {
                return;
            };
            let view_secret = keys.view_secret_bytes();
            txset::warm_chacha_key(&view_secret);
        });
    }
}

fn select_wallet(
    ui: &AppWindow,
    state: &Arc<Mutex<AppState>>,
    id: &str,
    allow_archived: bool,
) -> bool {
    {
        let mut st = state.lock().unwrap();
        let archived = match st.wallet_book.select_id(id) {
            Ok(wallet) => wallet.archived,
            Err(e) => {
                return {
                    drop(st);
                    set_status(ui, &format!("{e}"));
                    false
                }
            }
        };
        if archived && !allow_archived {
            return {
                drop(st);
                set_status(ui, "Archived wallets must be restored before use.");
                false
            };
        }
        st.invalidate_wallet_artifacts();
    }
    reset_transaction_ui(ui);
    refresh_wallet_ui(ui, state);
    warm_active_wallet(state);
    set_status(ui, "");
    true
}

fn select_first_active_wallet(ui: &AppWindow, state: &Arc<Mutex<AppState>>) -> bool {
    let result = {
        let mut st = state.lock().unwrap();
        if st
            .active_wallet()
            .map(|wallet| !wallet.archived)
            .unwrap_or(false)
        {
            return true;
        }
        let Some(id) = st
            .wallet_book
            .records
            .iter()
            .find(|wallet| !wallet.archived)
            .map(|wallet| wallet.id.clone())
        else {
            drop(st);
            set_status(ui, "No active wallets.");
            return false;
        };
        match st.wallet_book.select_id(&id) {
            Ok(_) => {
                st.invalidate_wallet_artifacts();
                Ok((st.data_dir.clone(), st.wallet_book.clone()))
            }
            Err(e) => Err(e),
        }
    };
    let (data_dir, book) = match result {
        Ok(result) => result,
        Err(e) => {
            set_status(ui, &format!("{e}"));
            return false;
        }
    };
    if let Err(e) = save_wallet_book(&data_dir, &book) {
        set_status(ui, &format!("Could not save wallet selection: {e}"));
        return false;
    }
    reset_transaction_ui(ui);
    refresh_wallet_ui(ui, state);
    warm_active_wallet(state);
    true
}

fn import_seed_qr(ui: &AppWindow, state: &Arc<Mutex<AppState>>) -> bool {
    let opts = ScanQrOptions {
        header_title: "Import Cake seed".into(),
        message: "Scan the seed QR exported by Cake Wallet.".into(),
        ..ScanQrOptions::default()
    };
    let scan = match open_qr_scanner::<GuiPermissions>(opts) {
        Ok(Some(scan)) => scan,
        Ok(None) => return false,
        Err(e) => {
            set_status(ui, &format!("Scanner error: {e:?}"));
            return false;
        }
    };
    let raw = match scan {
        ScanQrResult::Qr { data, .. } => {
            if data.len() > MAX_SEED_TEXT_CHARS {
                set_status(ui, "Seed QR is too large.");
                return false;
            }
            match String::from_utf8(data) {
                Ok(s) => s,
                Err(_) => {
                    set_status(ui, "Seed QR must be UTF-8 text.");
                    return false;
                }
            }
        }
        _ => {
            set_status(ui, "Scan Cake's seed QR, not an animated transaction QR.");
            return false;
        }
    };
    let parsed = match parse_cake_seed_qr(&raw) {
        Ok(parsed) => parsed,
        Err(e) => {
            set_status(ui, &e);
            return false;
        }
    };
    import_seed_text(
        ui,
        state,
        &parsed.phrase,
        parsed.restore_height.unwrap_or(IMPORTED_RESTORE_HEIGHT),
    )
}

struct ParsedSeedQr {
    phrase: String,
    restore_height: Option<u64>,
}

fn parse_cake_seed_qr(raw: &str) -> std::result::Result<ParsedSeedQr, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("Seed QR was empty.".into());
    }
    if let Some(query) = trimmed
        .strip_prefix("monero-wallet:")
        .or_else(|| trimmed.strip_prefix("MONERO-WALLET:"))
        .and_then(|s| s.split_once('?').map(|(_, q)| q))
    {
        let mut phrase = None;
        let mut restore_height = None;
        for pair in query.split('&') {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let key = percent_decode(key)?;
            let value = percent_decode(value)?;
            match key.as_str() {
                "seed" if !value.trim().is_empty() => phrase = Some(value),
                "height" if !value.trim().is_empty() => {
                    restore_height = value.trim().parse::<u64>().ok();
                }
                _ => {}
            }
        }
        let phrase =
            phrase.ok_or_else(|| "Cake seed QR did not include seed words.".to_string())?;
        return Ok(ParsedSeedQr {
            phrase,
            restore_height,
        });
    }
    Ok(ParsedSeedQr {
        phrase: trimmed.to_string(),
        restore_height: None,
    })
}

fn percent_decode(value: &str) -> std::result::Result<String, String> {
    let mut out = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3])
                    .map_err(|_| "Seed QR has invalid escaping.")?;
                let byte =
                    u8::from_str_radix(hex, 16).map_err(|_| "Seed QR has invalid escaping.")?;
                out.push(byte);
                i += 3;
            }
            b'%' => return Err("Seed QR has invalid escaping.".into()),
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| "Seed QR has invalid UTF-8 escaping.".into())
}

fn import_seed_text(
    ui: &AppWindow,
    state: &Arc<Mutex<AppState>>,
    phrase: &str,
    restore_height: u64,
) -> bool {
    let phrase = phrase.trim();
    if phrase.is_empty() {
        set_status(ui, "Seed words required.");
        return false;
    }
    if phrase.len() > MAX_SEED_TEXT_CHARS {
        set_status(ui, "Seed text is too large.");
        return false;
    }
    let result = {
        let mut st = state.lock().unwrap();
        let app_seed = st.app_seed;
        match st
            .wallet_book
            .import_seed(&app_seed, phrase, restore_height)
        {
            Ok(_) => {
                st.invalidate_wallet_artifacts();
                st.address_cache.clear();
                Ok((st.data_dir.clone(), st.wallet_book.clone()))
            }
            Err(e) => Err(e),
        }
    };
    let (data_dir, book) = match result {
        Ok(result) => result,
        Err(e) => {
            set_status(ui, &format!("{e}"));
            return false;
        }
    };
    if let Err(e) = save_wallet_book(&data_dir, &book) {
        set_status(ui, &format!("Could not save imported wallet: {e}"));
        return false;
    }
    reset_transaction_ui(ui);
    refresh_wallet_ui(ui, state);
    warm_active_wallet(state);
    set_status(ui, "");
    true
}

fn seed_import_preview(phrase: &str) -> String {
    let count = phrase.split_whitespace().count();
    match count {
        0 => "Type or paste 16-word Polyseed or 24/25-word legacy Monero seed.".into(),
        16 => "16 words: Polyseed candidate.".into(),
        24 | 25 => "Legacy Monero seed candidate.".into(),
        _ => format!("{count} words: expected 16, 24, or 25 words."),
    }
}

fn verify_address_scan(ui: &AppWindow, state: &Arc<Mutex<AppState>>) {
    clear_verify_ui(ui);
    set_status(ui, "");
    let opts = ScanQrOptions {
        header_title: "Verify Monero address".into(),
        message: "Scan an address from Cake Wallet.".into(),
        ..ScanQrOptions::default()
    };
    let scan = match open_qr_scanner::<GuiPermissions>(opts) {
        Ok(Some(scan)) => scan,
        Ok(None) => return,
        Err(e) => {
            set_status(ui, &format!("Scanner error: {e:?}"));
            return;
        }
    };
    let address = match scan {
        ScanQrResult::Qr { data, .. } => {
            if data.len() > MAX_ADDRESS_QR_BYTES {
                set_verify_result(
                    ui,
                    false,
                    "QR too large",
                    "Scan a normal Monero address QR from Cake Wallet.",
                    "",
                );
                return;
            }
            match String::from_utf8(data) {
                Ok(s) => match normalize_scanned_monero_address(&s) {
                    Ok(address) => address,
                    Err(AddressScanError::Bitcoin) => {
                        set_verify_result(
                            ui,
                            false,
                            "Bitcoin address",
                            "This QR contains a Bitcoin address. This screen only verifies Monero addresses from Cake Wallet.",
                            "",
                        );
                        return;
                    }
                    Err(AddressScanError::NotMonero) => {
                        set_verify_result(
                            ui,
                            false,
                            "Not a Monero address",
                            "Scan a Monero receive address from Cake Wallet, or use the account/subaddress fields below.",
                            "",
                        );
                        return;
                    }
                },
                Err(_) => {
                    set_verify_result(
                        ui,
                        false,
                        "Invalid QR",
                        "Address QR was not UTF-8 text.",
                        "",
                    );
                    return;
                }
            }
        }
        ScanQrResult::LeftClicked | ScanQrResult::RightClicked => return,
        _ => {
            set_verify_result(
                ui,
                false,
                "Not an address QR",
                "Scan a Cake Wallet address QR, not an animated transaction QR.",
                "",
            );
            return;
        }
    };
    if address.is_empty() {
        set_verify_result(ui, false, "Invalid QR", "Address QR was empty.", "");
        return;
    }
    verify_scanned_address_async(ui, state, address);
}

fn verify_address_index(
    ui: &AppWindow,
    state: &Arc<Mutex<AppState>>,
    account: &str,
    index: &str,
) -> bool {
    bump_verify_request(state);
    let account = match parse_verify_index(account, "account") {
        Ok(v) => v,
        Err(e) => {
            set_status(ui, &e);
            return false;
        }
    };
    let index = match parse_verify_index(index, "subaddress") {
        Ok(v) => v,
        Err(e) => {
            set_status(ui, &e);
            return false;
        }
    };
    let result: monero::Result<(String, String)> = {
        let st = state.lock().unwrap();
        match st.active_wallet() {
            Ok(wallet) => match wallet.keys(&st.app_seed) {
                Ok(keys) => Ok((
                    wallet.label.clone(),
                    keys.address_at(st.network, account, index),
                )),
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        }
    };
    let (label, address) = match result {
        Ok(result) => result,
        Err(e) => {
            set_status(ui, &format!("{e}"));
            return false;
        }
    };
    set_verify_result(
        ui,
        true,
        "Derived address",
        &format!("{label} · account {account} / subaddress {index}"),
        &address,
    );
    set_status(ui, "");
    true
}

fn parse_verify_index(value: &str, label: &str) -> std::result::Result<u32, String> {
    value
        .trim()
        .parse::<u32>()
        .map_err(|_| format!("{label} must be a whole number"))
}

fn bump_verify_request(state: &Arc<Mutex<AppState>>) -> u64 {
    let mut st = state.lock().unwrap();
    st.verify_request_id = st.verify_request_id.wrapping_add(1);
    st.verify_request_id
}

fn verify_scanned_address_async(ui: &AppWindow, state: &Arc<Mutex<AppState>>, address: String) {
    let request_id = bump_verify_request(state);

    if let Some(hit) = cached_wallet_address(state, &address) {
        set_verified_address_result(ui, &address, Some(hit));
        return;
    }

    set_verify_result(
        ui,
        false,
        "Checking address",
        "Searching local wallets and common subaddress indexes.",
        &address,
    );

    let state = state.clone();
    std::thread::spawn(move || {
        let hit = find_wallet_address(&state, &address);
        queue_with_ui(move |ui| {
            if state.lock().unwrap().verify_request_id != request_id {
                return;
            }
            set_verified_address_result(ui, &address, hit);
        });
    });
}

fn set_verified_address_result(ui: &AppWindow, address: &str, hit: Option<AddressHit>) {
    match hit {
        Some(hit) => {
            set_verify_result(
                ui,
                true,
                "Address verified",
                &format!(
                    "{} · account {} / subaddress {}",
                    hit.wallet_label, hit.account, hit.index
                ),
                address,
            );
        }
        None => {
            set_verify_result(
                ui,
                false,
                "Address not found",
                &format!(
                    "Checked local wallets through accounts 0-{} and subaddresses 0-{}. Use Show for a specific higher index.",
                    VERIFY_ACCOUNT_LIMIT - 1,
                    VERIFY_SUBADDRESS_LIMIT - 1
                ),
                address,
            );
        }
    }
}

#[derive(Clone)]
struct AddressHit {
    wallet_label: String,
    account: u32,
    index: u32,
}

fn cached_wallet_address(state: &Arc<Mutex<AppState>>, address: &str) -> Option<AddressHit> {
    state.lock().unwrap().address_cache.get(address).cloned()
}

fn find_wallet_address(state: &Arc<Mutex<AppState>>, address: &str) -> Option<AddressHit> {
    if let Some(hit) = cached_wallet_address(state, address) {
        return Some(hit);
    }

    let (mut wallets, selected_id, app_seed, network) = {
        let st = state.lock().unwrap();
        (
            st.wallet_book.records.clone(),
            st.wallet_book.selected_id.clone(),
            st.app_seed,
            st.network,
        )
    };
    wallets.sort_by_key(|wallet| if wallet.id == selected_id { 0 } else { 1 });
    let mut derived = Vec::<(String, AddressHit)>::new();
    let mut found = None;

    for wallet in wallets {
        let Ok(keys) = wallet.keys(&app_seed) else {
            continue;
        };
        for account in 0..VERIFY_ACCOUNT_LIMIT {
            for index in 0..VERIFY_SUBADDRESS_LIMIT {
                let derived_address = keys.address_at(network, account, index);
                let hit = AddressHit {
                    wallet_label: wallet.label.clone(),
                    account,
                    index,
                };
                if derived_address == address && found.is_none() {
                    found = Some(hit.clone());
                }
                derived.push((derived_address, hit));
            }
        }
    }

    let mut st = state.lock().unwrap();
    for (derived_address, hit) in derived {
        st.address_cache.insert(derived_address, hit);
    }
    found
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressScanError {
    Bitcoin,
    NotMonero,
}

fn normalize_scanned_monero_address(raw: &str) -> std::result::Result<String, AddressScanError> {
    if looks_like_bitcoin_address_qr(raw) {
        return Err(AddressScanError::Bitcoin);
    }

    let address = normalize_monero_address(raw);
    if address.is_empty()
        || monero::address::is_valid_standard_or_subaddress(&address, DEFAULT_NETWORK)
    {
        Ok(address)
    } else if looks_like_bitcoin_address_qr(&address) {
        Err(AddressScanError::Bitcoin)
    } else {
        Err(AddressScanError::NotMonero)
    }
}

fn normalize_monero_address(raw: &str) -> String {
    let trimmed = raw.trim();
    let without_scheme = trimmed
        .strip_prefix("monero:")
        .or_else(|| trimmed.strip_prefix("MONERO:"))
        .unwrap_or(trimmed);
    without_scheme
        .split('?')
        .next()
        .unwrap_or(without_scheme)
        .trim()
        .to_string()
}

fn looks_like_bitcoin_address_qr(raw: &str) -> bool {
    let trimmed = raw.trim();
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("bitcoin:") {
        return true;
    }

    let address = trimmed.split('?').next().unwrap_or(trimmed).trim();
    let lower_address = address.to_ascii_lowercase();
    lower_address.starts_with("bc1")
        || lower_address.starts_with("tb1")
        || lower_address.starts_with("bcrt1")
        || is_likely_bitcoin_base58_address(address)
}

fn is_likely_bitcoin_base58_address(address: &str) -> bool {
    let len = address.len();
    if !(26..=35).contains(&len) {
        return false;
    }
    let Some(first) = address.chars().next() else {
        return false;
    };
    matches!(first, '1' | '3' | 'm' | 'n' | '2') && address.chars().all(is_base58_char)
}

fn is_base58_char(c: char) -> bool {
    matches!(
        c,
        '1'..='9'
            | 'A'..='H'
            | 'J'..='N'
            | 'P'..='Z'
            | 'a'..='k'
            | 'm'..='z'
    )
}

fn set_verify_result(ui: &AppWindow, matched: bool, title: &str, detail: &str, address: &str) {
    let cb = ui.global::<Callbacks>();
    cb.set_verify_ready(true);
    cb.set_verify_matched(matched);
    cb.set_verify_title(title.into());
    cb.set_verify_detail(detail.into());
    cb.set_verify_address(address.into());
    cb.set_status_text("".into());
}

fn populate_review(ui: &AppWindow, s: &TxSummary) {
    let cb = ui.global::<Callbacks>();
    cb.set_amount_xmr(monero::format_xmr(s.amount_atomic).into());
    cb.set_change_xmr(monero::format_xmr(s.change_atomic).into());
    // Fee is implicit and not yet computed (= inputs − outputs); show a dash
    // rather than a misleading 0 until the source walk lands.
    cb.set_fee_xmr(if s.fee_atomic == 0 {
        "—".into()
    } else {
        monero::format_xmr(s.fee_atomic).into()
    });
    cb.set_output_count(s.output_count as i32);
    cb.set_dest_address(truncate(s.destinations.first().map(String::as_str).unwrap_or("")).into());
    cb.set_dest_addresses(model_from_strings(s.destinations.clone()));
    cb.set_dest_address_labels(model_from_strings(
        s.destinations.iter().map(|addr| truncate(addr)).collect(),
    ));
    let indices = if s.subaddr_indices.is_empty() {
        "none".to_string()
    } else {
        s.subaddr_indices
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    cb.set_tx_account_info(
        format!("Account {} / subaddresses {indices}", s.subaddr_account).into(),
    );
}

/// Export `bytes` via the folder picker, then report success/failure to the UI.
fn finish_export(ui: &AppWindow, filename: &str, bytes: &[u8], ok_msg: &str) {
    match export_via_picker(filename, bytes) {
        Ok(dest) => set_status(ui, &format!("{ok_msg} (saved to {dest})")),
        Err(e) => {
            let msg = format!("{e}");
            if !msg.contains("cancelled") {
                set_status(ui, &msg);
            }
        }
    }
}

fn truncate(addr: &str) -> String {
    if addr.len() <= 16 {
        addr.to_string()
    } else {
        format!("{}…{}", &addr[..8], &addr[addr.len() - 8..])
    }
}

// ---------------------------------------------------------------------------
// File picker I/O — mirrors the Liana signer's helpers (same KeyOS API), with
// the close-before-flush sequence that survives card removal on FAT media.
// ---------------------------------------------------------------------------

fn data_dir() -> PathBuf {
    #[cfg(keyos)]
    {
        PathBuf::from(DATA_SUBDIR)
    }
    #[cfg(not(keyos))]
    {
        let mut p = std::env::temp_dir();
        p.push(DATA_SUBDIR);
        p
    }
}

fn load_wallet_book(dir: &Path) -> anyhow::Result<wallets::WalletBook> {
    load_wallet_book_impl(dir)
}

#[cfg(not(keyos))]
fn load_wallet_book_impl(dir: &Path) -> anyhow::Result<wallets::WalletBook> {
    let path = dir.join(WALLET_BOOK_FILE);
    if !path.exists() {
        return Ok(wallets::WalletBook::new(PAIR_RESTORE_HEIGHT));
    }
    let text = std::fs::read_to_string(path)?;
    wallets::from_json(&text, PAIR_RESTORE_HEIGHT).map_err(|e| anyhow::anyhow!("{e}"))
}

#[cfg(keyos)]
fn load_wallet_book_impl(_dir: &Path) -> anyhow::Result<wallets::WalletBook> {
    let fs = FileSystem::default();
    match read_text_fs_limited(
        &fs,
        WALLET_BOOK_FILE,
        fs::Location::AppData,
        65_536,
        "wallets",
    ) {
        Ok(text) => {
            wallets::from_json(&text, PAIR_RESTORE_HEIGHT).map_err(|e| anyhow::anyhow!("{e}"))
        }
        Err(_) => Ok(wallets::WalletBook::new(PAIR_RESTORE_HEIGHT)),
    }
}

fn save_wallet_book(dir: &Path, book: &wallets::WalletBook) -> anyhow::Result<()> {
    save_wallet_book_impl(dir, book)
}

#[cfg(not(keyos))]
fn save_wallet_book_impl(dir: &Path, book: &wallets::WalletBook) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    let json = wallets::to_json(book).map_err(|e| anyhow::anyhow!("{e}"))?;
    std::fs::write(dir.join(WALLET_BOOK_FILE), json)?;
    Ok(())
}

#[cfg(keyos)]
fn save_wallet_book_impl(_dir: &Path, book: &wallets::WalletBook) -> anyhow::Result<()> {
    use std::io::{Seek, SeekFrom, Write};

    let json = wallets::to_json(book).map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut fs = FileSystem::default();
    {
        let mut file = fs
            .open_file(
                WALLET_BOOK_FILE,
                fs::Location::AppData,
                fs::OpenFlags {
                    read: true,
                    write: true,
                    create: true,
                },
            )
            .map_err(|e| anyhow::anyhow!("open {WALLET_BOOK_FILE}: {e:?}"))?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(json.as_bytes())?;
        file.truncate()
            .map_err(|e| anyhow::anyhow!("truncate {WALLET_BOOK_FILE}: {e:?}"))?;
        file.flush()?;
    }
    fs.flush(fs::Location::AppData)
        .map_err(|e| anyhow::anyhow!("flush app data: {e:?}"))?;
    Ok(())
}

fn map_location(loc: PickLocation) -> fs::Location {
    match loc {
        PickLocation::Internal => fs::Location::User,
        PickLocation::Airlock => fs::Location::Airlock,
        PickLocation::External => fs::Location::Usb,
    }
}

fn loc_label(loc: fs::Location) -> &'static str {
    match loc {
        fs::Location::Usb => "usb:/",
        fs::Location::Airlock => "airlock:/",
        fs::Location::User => "user:/",
        _ => "",
    }
}

/// Open the file picker (file-selection mode), read the chosen file, return its
/// raw bytes. Used to load an unsigned tx that Cake Wallet exported.
fn read_via_picker(max: u64) -> anyhow::Result<Vec<u8>> {
    let options = SelectFileOptions::default().with_allowed_locations(AllowedLocations::All);
    let result = select_file::<GuiPermissions>(options)
        .map_err(|e| anyhow::anyhow!("picker error: {e:?}"))?;
    let Some(result) = result else {
        anyhow::bail!("cancelled");
    };
    let Some((path, loc)) = result.files().first().cloned() else {
        anyhow::bail!("no file selected");
    };
    let filesystem = FileSystem::default();
    read_bytes_fs_limited(&filesystem, &path, map_location(loc), max)
}

/// Read a file's bytes through the KeyOS FileSystem, capped at `max`.
fn read_bytes_fs_limited(
    filesystem: &FileSystem,
    path: &str,
    location: fs::Location,
    max: u64,
) -> anyhow::Result<Vec<u8>> {
    use std::io::Read;
    let file = filesystem
        .open_file(
            path.to_string(),
            location,
            fs::OpenFlags {
                read: true,
                write: false,
                create: false,
            },
        )
        .map_err(|e| anyhow::anyhow!("open {path}: {e:?}"))?;
    let mut buf = Vec::new();
    file.take(max.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| anyhow::anyhow!("read {path}: {e:?}"))?;
    if buf.len() as u64 > max {
        anyhow::bail!("{path} is too large (maximum {max} bytes)");
    }
    Ok(buf)
}

#[cfg(keyos)]
fn read_text_fs_limited(
    filesystem: &FileSystem,
    path: &str,
    location: fs::Location,
    max: u64,
    label: &str,
) -> anyhow::Result<String> {
    let bytes = read_bytes_fs_limited(filesystem, path, location, max)?;
    String::from_utf8(bytes).map_err(|_| anyhow::anyhow!("{label} file is not UTF-8"))
}

/// Open the folder picker and write `filename` into the chosen folder/location
/// (SD, USB, internal, or Airlock), committing in the order that survives card
/// removal on FAT media (write -> File::flush -> close -> FileSystem::flush).
fn export_via_picker(filename: &str, bytes: &[u8]) -> anyhow::Result<String> {
    let options = SelectFileOptions::default()
        .with_dir_selection_mode(true)
        .with_allowed_locations(AllowedLocations::All);
    let result = select_file::<GuiPermissions>(options)
        .map_err(|e| anyhow::anyhow!("picker error: {e:?}"))?;
    let Some(result) = result else {
        anyhow::bail!("cancelled");
    };
    let Some((dir, loc)) = result.files().first().cloned() else {
        anyhow::bail!("no folder selected");
    };
    let dir = dir.trim_end_matches('/').to_string();
    let dir = if dir.is_empty() {
        EXPORT_DIR.to_string()
    } else {
        dir
    };
    write_export(filename, bytes, map_location(loc), &dir)
}

/// Write `bytes` to a fresh file inside `dir` at `location`. The directory-entry
/// flush on close is the critical step on FAT/SD (see the Liana signer notes):
/// chunked write -> `File::flush` (writes the dir entry) -> close -> fs flush.
fn write_export(
    filename: &str,
    bytes: &[u8],
    location: fs::Location,
    dir: &str,
) -> anyhow::Result<String> {
    use std::io::Write;
    let mut filesystem = FileSystem::default();
    let directory = filesystem.create_dir(dir, location).map_err(|e| {
        if matches!(e, fs::Error::NoMedia) {
            match location {
                fs::Location::Airlock => anyhow::anyhow!(
                    "Disconnect Passport from your computer first, then save (Airlock is in use while connected)"
                ),
                fs::Location::Usb => anyhow::anyhow!("No SD card or USB drive found"),
                _ => anyhow::anyhow!("Storage not available"),
            }
        } else {
            anyhow::anyhow!("open {dir}: {e:?}")
        }
    })?;
    let unique = directory
        .pick_next_filename(filename, None)
        .map_err(|e| anyhow::anyhow!("pick filename: {e:?}"))?;
    let path = format!("{dir}/{unique}");
    {
        let mut file = filesystem
            .open_file(
                path.clone(),
                location,
                fs::OpenFlags {
                    read: false,
                    write: true,
                    create: true,
                },
            )
            .map_err(|e| anyhow::anyhow!("open {path}: {e:?}"))?;
        let mut written = 0usize;
        while written < bytes.len() {
            let end = (written + 512).min(bytes.len());
            let n = file
                .write(&bytes[written..end])
                .map_err(|e| anyhow::anyhow!("write {path} @{written}: {e:?}"))?;
            if n == 0 {
                anyhow::bail!("write returned 0 at offset {written} of {}", bytes.len());
            }
            written += n;
        }
        file.flush()
            .map_err(|e| anyhow::anyhow!("flush {path}: {e:?}"))?;
    } // drop file -> CloseFile (re-commits the directory entry)
    drop(directory); // CloseDir
    filesystem
        .flush(location)
        .map_err(|e| anyhow::anyhow!("flush fs: {e:?}"))?;
    Ok(format!("{}{}", loc_label(location), path))
}

/// Simulator demo seeding: write `bytes` to `cake/<filename>` at a STABLE name,
/// skipping if the file already exists so repeated boots don't accumulate
/// suffixed copies. (Unlike [`write_export`], which auto-suffixes on collision.)
#[cfg(not(target_os = "xous"))]
fn seed_demo_unsigned(filename: &str, bytes: &[u8]) -> anyhow::Result<String> {
    use std::io::Write;
    let location = fs::Location::User;
    let mut filesystem = FileSystem::default();
    let directory = filesystem
        .create_dir(EXPORT_DIR, location)
        .map_err(|e| anyhow::anyhow!("open {EXPORT_DIR}: {e:?}"))?;
    let path = format!("{EXPORT_DIR}/{filename}");
    // Already seeded on a prior boot? Leave it; nothing to do.
    if filesystem
        .open_file(
            path.clone(),
            location,
            fs::OpenFlags {
                read: true,
                write: false,
                create: false,
            },
        )
        .is_ok()
    {
        drop(directory);
        return Ok(format!("{}{} (existing)", loc_label(location), path));
    }
    {
        let mut file = filesystem
            .open_file(
                path.clone(),
                location,
                fs::OpenFlags {
                    read: false,
                    write: true,
                    create: true,
                },
            )
            .map_err(|e| anyhow::anyhow!("open {path}: {e:?}"))?;
        let mut written = 0usize;
        while written < bytes.len() {
            let end = (written + 512).min(bytes.len());
            let n = file
                .write(&bytes[written..end])
                .map_err(|e| anyhow::anyhow!("write {path} @{written}: {e:?}"))?;
            if n == 0 {
                anyhow::bail!("write returned 0 at offset {written} of {}", bytes.len());
            }
            written += n;
        }
        file.flush()
            .map_err(|e| anyhow::anyhow!("flush {path}: {e:?}"))?;
    }
    drop(directory);
    filesystem
        .flush(location)
        .map_err(|e| anyhow::anyhow!("flush fs: {e:?}"))?;
    Ok(format!("{}{}", loc_label(location), path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_output_entry(n: u8) -> monero::keyimage::OutEntry {
        monero::keyimage::OutEntry {
            pubkey: [n; 32],
            tx_pubkey: [n.wrapping_add(1); 32],
            additional: Vec::new(),
            internal_idx: 0,
            major: 0,
            minor: 0,
        }
    }

    #[test]
    fn parses_cake_seed_uri() {
        let parsed =
            parse_cake_seed_qr("monero-wallet:?seed=alpha+beta%20gamma&height=3400000").unwrap();
        assert_eq!(parsed.phrase, "alpha beta gamma");
        assert_eq!(parsed.restore_height, Some(3_400_000));
    }

    #[test]
    fn parses_plain_seed_qr_text() {
        let parsed = parse_cake_seed_qr("alpha beta gamma").unwrap();
        assert_eq!(parsed.phrase, "alpha beta gamma");
        assert_eq!(parsed.restore_height, None);
    }

    #[test]
    fn detects_bitcoin_address_qrs_before_monero_search() {
        assert_eq!(
            normalize_scanned_monero_address("bitcoin:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"),
            Err(AddressScanError::Bitcoin)
        );
        assert_eq!(
            normalize_scanned_monero_address("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"),
            Err(AddressScanError::Bitcoin)
        );
    }

    #[test]
    fn accepts_monero_shaped_address_qrs() {
        let address =
            "4APTP4HYNScMjNQdwkXCw2fYnVtJas2nxSSpCP3bBzSmKXEbdKjjvyWZCbtyNjaYXSc4RHQgiYtWqWpUpY1qC5KR7sUspfD";
        assert_eq!(
            normalize_scanned_monero_address(&format!("monero:{address}?tx_amount=1")).unwrap(),
            address
        );
    }

    #[test]
    fn wallet_artifacts_are_hidden_from_other_wallets() {
        let artifact = Some(WalletArtifact {
            wallet_id: "slot-0".into(),
            bytes: vec![1, 2, 3],
        });

        assert_eq!(
            artifact_bytes_for_wallet("slot-0", &artifact),
            Some([1, 2, 3].as_slice())
        );
        assert_eq!(artifact_bytes_for_wallet("slot-1", &artifact), None);
        assert_eq!(
            artifact_bytes_for_wallet("imported-deadbeef", &artifact),
            None
        );
    }

    #[test]
    fn missing_wallet_artifact_has_no_qr_payload() {
        assert_eq!(artifact_bytes_for_wallet("slot-0", &None), None);
    }

    #[test]
    fn keyimage_sync_rejects_incremental_tail_without_cached_prefix() {
        let mut cache = BTreeMap::new();
        let export = monero::keyimage::OutputExport {
            offset: 2,
            total: 3,
            entries: vec![dummy_output_entry(2)],
        };

        match cache_and_choose_keyimage_export(&mut cache, export) {
            KeyImageSyncDecision::MissingPrefix(missing) => {
                assert_eq!(missing.missing_from, 0);
                assert_eq!(missing.total, 3);
            }
            KeyImageSyncDecision::Export(_) => panic!("partial tail should not be exported"),
        }
    }

    #[test]
    fn keyimage_sync_rejects_incomplete_prefix_from_zero() {
        let mut cache = BTreeMap::new();
        let export = monero::keyimage::OutputExport {
            offset: 0,
            total: 3,
            entries: vec![dummy_output_entry(0), dummy_output_entry(1)],
        };

        match cache_and_choose_keyimage_export(&mut cache, export) {
            KeyImageSyncDecision::MissingPrefix(missing) => {
                assert_eq!(missing.missing_from, 2);
                assert_eq!(missing.total, 3);
            }
            KeyImageSyncDecision::Export(_) => panic!("incomplete prefix should not be exported"),
        }
    }

    #[test]
    fn keyimage_sync_exports_complete_prefix() {
        let mut cache = BTreeMap::new();
        let export = monero::keyimage::OutputExport {
            offset: 0,
            total: 2,
            entries: vec![dummy_output_entry(0), dummy_output_entry(1)],
        };

        let KeyImageSyncDecision::Export(repaired) =
            cache_and_choose_keyimage_export(&mut cache, export)
        else {
            panic!("complete prefix should be exported");
        };

        assert_eq!(repaired.offset, 0);
        assert_eq!(repaired.total, 2);
        assert_eq!(repaired.entries.len(), 2);
    }

    #[test]
    fn keyimage_sync_repairs_incremental_tail_with_cached_prefix() {
        let mut cache = BTreeMap::new();
        let first = monero::keyimage::OutputExport {
            offset: 0,
            total: 3,
            entries: vec![dummy_output_entry(0), dummy_output_entry(1)],
        };
        let second = monero::keyimage::OutputExport {
            offset: 2,
            total: 3,
            entries: vec![dummy_output_entry(2)],
        };

        assert!(matches!(
            cache_and_choose_keyimage_export(&mut cache, first),
            KeyImageSyncDecision::MissingPrefix(MissingKeyImagePrefix {
                missing_from: 2,
                total: 3
            })
        ));

        let KeyImageSyncDecision::Export(repaired) =
            cache_and_choose_keyimage_export(&mut cache, second)
        else {
            panic!("cached prefix should produce a repair export");
        };

        assert_eq!(repaired.offset, 0);
        assert_eq!(repaired.total, 3);
        assert_eq!(repaired.entries.len(), 3);
        assert_eq!(repaired.entries[0].pubkey, [0; 32]);
        assert_eq!(repaired.entries[1].pubkey, [1; 32]);
        assert_eq!(repaired.entries[2].pubkey, [2; 32]);
    }
}
