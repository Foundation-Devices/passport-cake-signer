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

mod master_key;
mod monero;
mod qr;

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use gui_permissions::GuiPermissions;
use monero::{keys::MoneroKeys, signer, txset, wallets, Network, TxSummary};
use slint_keyos_platform::{
    app,
    gui_server_api::navigation::{
        filepicker::{AllowedLocations, Location as PickLocation, SelectFileOptions},
        qrscanner::{ScanQrOptions, ScanQrResult},
    },
    navigation::{open_qr_scanner, select_file},
    slint::{ComponentHandle, ModelRc, SharedString, VecModel},
};

// `app!` injects the permission-parameterized `FileSystem` alias (via
// fs::use_api!), the `AppWindow`/`Callbacks`/`TrId`/`AppContext` types, and the
// `tr` helpers — so we deliberately do NOT `use fs::FileSystem` (that raw,
// unparameterized type would shadow the alias and break the permission bounds).
app!("Cake");

// Mainnet: the real Cake Wallet mobile app is mainnet-only, so the pairing
// address must be a mainnet (`4…`) address. The signing code is network-agnostic
// (serai signs for whatever network the unsigned tx is on). Switch back to
// Stagenet only for offline CLI testing with monero-wallet-cli.
const DEFAULT_NETWORK: Network = Network::Mainnet;
const DATA_SUBDIR: &str = ".passport-cake-signer-keyos";
const EXPORT_DIR: &str = "cake"; // subdir used when the user picks a location root
const MAX_TXSET_BYTES: u64 = 4_194_304; // 4 MiB; Monero tx sets are larger than PSBTs
const MAX_SEED_FILE_BYTES: u64 = 16_384;
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

/// Live app state shared across UI callbacks.
struct AppState {
    app_seed: [u8; 32],
    network: Network,
    data_dir: PathBuf,
    wallet_book: wallets::WalletBook,
    /// The unsigned tx under review: (parsed summary, raw file bytes). The raw
    /// bytes are re-processed by the signer.
    pending: Option<(txset::UnsignedTxSet, Vec<u8>)>,
    /// The most recently produced signed_tx_set, for the animated-QR handoff
    /// to Cake (in addition to the file export).
    last_signed: Option<Vec<u8>>,
    /// The most recently produced key_image_export (answer to Cake's xmr-output
    /// sync), for the xmr-keyimage animated-QR handoff.
    last_keyimages: Option<Vec<u8>>,
}

impl AppState {
    fn active_wallet(&self) -> monero::Result<&wallets::WalletRecord> {
        self.wallet_book.selected().ok_or_else(|| monero::Error::Seed("no active wallet".into()))
    }

    fn keys(&self) -> monero::Result<MoneroKeys> { self.active_wallet()?.keys(&self.app_seed) }

    fn clear_wallet_artifacts(&mut self) {
        self.pending = None;
        self.last_signed = None;
        self.last_keyimages = None;
    }
}

fn app_main(_cx: AppContext, ui: AppWindow) {
    log_server::init_wait(env!("CARGO_CRATE_NAME")).unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("Starting Cake Wallet Signer");

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

    let wallet_book = load_wallet_book(&data_dir).unwrap_or_else(|e| {
        log::warn!("could not load wallet book: {e}");
        wallets::WalletBook::new(PAIR_RESTORE_HEIGHT)
    });

    let state = Arc::new(Mutex::new(AppState {
        app_seed,
        network: DEFAULT_NETWORK,
        data_dir,
        wallet_book,
        pending: None,
        last_signed: None,
        last_keyimages: None,
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
            let mut st = state.lock().unwrap();
            let keys = match st.keys() {
                Ok(keys) => keys,
                Err(e) => {
                    drop(st);
                    set_status(&ui, &format!("{e}"));
                    return;
                }
            };
            let view_secret = keys.view_secret_bytes();
            let spend_pub = keys.public_spend();
            let network = st.network;
            match txset::UnsignedTxSet::parse(&bytes, &view_secret, &spend_pub, network) {
                Ok(unsigned) => {
                    populate_review(&ui, unsigned.summary());
                    st.pending = Some((unsigned, bytes));
                    ui.global::<Callbacks>().set_tx_loaded(true);
                    ui.global::<Callbacks>().set_status_text("".into());
                }
                Err(e) => {
                    ui.global::<Callbacks>().set_tx_loaded(false);
                    set_status(&ui, &format!("{e}"));
                }
            }
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
            let words = words.split_whitespace().map(SharedString::from).collect::<Vec<SharedString>>();
            ui.global::<Callbacks>().set_seed_words(ModelRc::new(VecModel::from(words)));
        });
    }
    {
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_clear_seed_words(move || {
            let Some(ui) = weak.upgrade() else { return };
            ui.global::<Callbacks>().set_seed_words(ModelRc::<SharedString>::default());
        });
    }

    // -- wallet identity controls -----------------------------------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_switch_next_wallet(move || {
            let Some(ui) = weak.upgrade() else { return };
            let (data_dir, book, label) = {
                let mut st = state.lock().unwrap();
                let Some(wallet) = st.wallet_book.select_next().cloned() else {
                    drop(st);
                    set_status(&ui, "No wallet slots available.");
                    return;
                };
                st.clear_wallet_artifacts();
                (st.data_dir.clone(), st.wallet_book.clone(), wallet.label)
            };
            if let Err(e) = save_wallet_book(&data_dir, &book) {
                set_status(&ui, &format!("Could not save wallet selection: {e}"));
                return;
            }
            reset_transaction_ui(&ui);
            refresh_wallet_ui(&ui, &state);
            warm_active_wallet(&state);
            set_status(&ui, &format!("Active wallet: {label}"));
        });
    }
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_add_device_wallet_slot(move || {
            let Some(ui) = weak.upgrade() else { return false };
            let result = {
                let mut st = state.lock().unwrap();
                match st.wallet_book.add_device_slot(PAIR_RESTORE_HEIGHT) {
                    Ok(wallet) => {
                        let label = wallet.label.clone();
                        st.clear_wallet_artifacts();
                        Ok((st.data_dir.clone(), st.wallet_book.clone(), label))
                    }
                    Err(e) => Err(e),
                }
            };
            let (data_dir, book, label) = match result {
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
            set_status(&ui, &format!("Added wallet: {label}"));
            true
        });
    }
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_select_wallet(move |id| {
            let Some(ui) = weak.upgrade() else { return false };
            select_wallet(&ui, &state, id.as_str(), true)
        });
    }
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_select_first_active_wallet(move || {
            let Some(ui) = weak.upgrade() else { return false };
            select_first_active_wallet(&ui, &state)
        });
    }
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_import_seed_text(move |seed| {
            let Some(ui) = weak.upgrade() else { return false };
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
            let Some(ui) = weak.upgrade() else { return false };
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
            let Some(ui) = weak.upgrade() else { return false };
            import_seed_qr(&ui, &state)
        });
    }
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_rename_active_wallet(move |label| {
            let Some(ui) = weak.upgrade() else { return false };
            let result = {
                let mut st = state.lock().unwrap();
                match st.wallet_book.rename_selected(label.as_str()) {
                    Ok(wallet) => {
                        let label = wallet.label.clone();
                        Ok((st.data_dir.clone(), st.wallet_book.clone(), label))
                    }
                    Err(e) => Err(e),
                }
            };
            let (data_dir, book, label) = match result {
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
            set_status(&ui, &format!("Renamed wallet: {label}"));
            true
        });
    }
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_archive_active_wallet(move || {
            let Some(ui) = weak.upgrade() else { return false };
            let result = {
                let mut st = state.lock().unwrap();
                let label = st.active_wallet().map(|wallet| wallet.label.clone());
                match (label, st.wallet_book.archive_selected()) {
                    (Ok(label), Ok(_)) => {
                        st.clear_wallet_artifacts();
                        Ok((st.data_dir.clone(), st.wallet_book.clone(), label))
                    }
                    (Err(e), _) | (_, Err(e)) => Err(e),
                }
            };
            let (data_dir, book, label) = match result {
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
            set_status(&ui, &format!("Archived wallet: {label}"));
            true
        });
    }
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_restore_active_wallet(move || {
            let Some(ui) = weak.upgrade() else { return false };
            let result = {
                let mut st = state.lock().unwrap();
                match st.wallet_book.restore_selected() {
                    Ok(wallet) => {
                        let label = wallet.label.clone();
                        st.clear_wallet_artifacts();
                        Ok((st.data_dir.clone(), st.wallet_book.clone(), label))
                    }
                    Err(e) => Err(e),
                }
            };
            let (data_dir, book, label) = match result {
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
            set_status(&ui, &format!("Restored wallet: {label}"));
            true
        });
    }
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_delete_active_wallet(move || {
            let Some(ui) = weak.upgrade() else { return false };
            let result = {
                let mut st = state.lock().unwrap();
                match st.wallet_book.delete_selected() {
                    Ok(wallet) => {
                        let label = wallet.label;
                        st.clear_wallet_artifacts();
                        Ok((st.data_dir.clone(), st.wallet_book.clone(), label))
                    }
                    Err(e) => Err(e),
                }
            };
            let (data_dir, book, label) = match result {
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
            set_status(&ui, &format!("Deleted wallet: {label}"));
            true
        });
    }
    {
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_clear_verify_address(move || {
            let Some(ui) = weak.upgrade() else { return };
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
        ui.global::<Callbacks>().on_verify_address_index(move |account, index| {
            let Some(ui) = weak.upgrade() else { return false };
            verify_address_index(&ui, &state, account.as_str(), index.as_str())
        });
    }

    // -- animated UR frames for the signed tx (Prime → Cake) ----------------
    {
        let state = state.clone();
        ui.global::<Callbacks>().on_get_signed_ur(move |max_size| {
            let st = state.lock().unwrap();
            match st.last_signed.as_ref() {
                Some(blob) => qr::ur_parts(qr::UR_TX_SIGNED, blob, max_size),
                None => slint_keyos_platform::slint::ModelRc::default(),
            }
        });
    }

    // -- animated UR frames for the key images (Prime → Cake sync) -----------
    {
        let state = state.clone();
        ui.global::<Callbacks>().on_get_keyimage_ur(move |max_size| {
            let st = state.lock().unwrap();
            match st.last_keyimages.as_ref() {
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
            ui.global::<Callbacks>().set_keyimages_ready(false);
            ui.global::<Callbacks>().set_signed_ok(false);
            ui.global::<Callbacks>().set_status_text("".into());
            {
                let mut st = state.lock().unwrap();
                st.pending = None;
                st.last_signed = None;
                st.last_keyimages = None;
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
            let raw = qr::ur_payload(&data);
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
                match monero::keyimage::export_key_images(&raw, &keys) {
                    Some(ki) => {
                        st.last_keyimages = Some(ki);
                        drop(st);
                        ui.global::<Callbacks>().set_keyimages_ready(true);
                        ui.global::<Callbacks>().set_status_text("".into());
                    }
                    None => {
                        drop(st);
                        set_status(&ui, "Could not build key images from those outputs.");
                    }
                }
            } else if ur_type == qr::UR_TX_UNSIGNED {
                let view_secret = keys.view_secret_bytes();
                let spend_pub = keys.public_spend();
                let network = st.network;
                match txset::UnsignedTxSet::parse(&raw, &view_secret, &spend_pub, network) {
                    Ok(unsigned) => {
                        populate_review(&ui, unsigned.summary());
                        st.pending = Some((unsigned, raw));
                        drop(st);
                        ui.global::<Callbacks>().set_tx_loaded(true);
                        ui.global::<Callbacks>().set_status_text("".into());
                    }
                    Err(e) => {
                        drop(st);
                        set_status(&ui, &format!("{e}"));
                    }
                }
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
            ui.global::<Callbacks>().set_status_text("".into());
            let mut st = state.lock().unwrap();
            st.last_signed = None;
            let Some((_, raw)) = st.pending.as_ref() else {
                drop(st);
                set_status(&ui, "No transaction loaded.");
                return;
            };
            let keys = match st.keys() {
                Ok(keys) => keys,
                Err(e) => {
                    drop(st);
                    set_status(&ui, &format!("{e}"));
                    return;
                }
            };
            let network = st.network;
            let raw = raw.clone();
            drop(st);
            // Sign the wallet2 unsigned tx with serai (CLSAG + Bulletproof+) and
            // package it as a wallet2 `signed_tx_set` — the exact file Cake loads
            // via "Import signed transaction" → submit_transfer. FEE_PER_WEIGHT
            // clears the network minimum (≈ the wallet2 fee).
            let result = signer::build_signed_tx_set(&raw, &keys, network, FEE_PER_WEIGHT);
            match result {
                Ok(bytes) => {
                    // Stash for the animated-QR handoff. Saving to file is an
                    // explicit follow-up action on the QR screen.
                    state.lock().unwrap().last_signed = Some(bytes.clone());
                    ui.global::<Callbacks>().set_signed_ok(true);
                    ui.global::<Callbacks>().set_status_text("".into());
                }
                Err(e) => set_status(&ui, &format!("Cannot sign: {e}")),
            }
        });
    }

    // -- optional signed-tx file export --------------------------------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_save_signed_tx(move || {
            let Some(ui) = weak.upgrade() else { return };
            let st = state.lock().unwrap();
            let Some(bytes) = st.last_signed.as_ref().cloned() else {
                drop(st);
                set_status(&ui, "No signed transaction to save.");
                return;
            };
            drop(st);
            finish_export(&ui, SIGNED_TX_FILE, &bytes, "Saved signed_monero_tx to file.");
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

    // No default status line — it only appears for real errors/progress.
    ui.run().expect("UI running");
}

// ---------------------------------------------------------------------------
// UI helpers
// ---------------------------------------------------------------------------

fn set_status(ui: &AppWindow, msg: &str) { ui.global::<Callbacks>().set_status_text(msg.into()); }

fn reset_transaction_ui(ui: &AppWindow) {
    let cb = ui.global::<Callbacks>();
    cb.set_tx_loaded(false);
    cb.set_keyimages_ready(false);
    cb.set_signed_ok(false);
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
    match st.active_wallet().and_then(|wallet| wallet.keys(&st.app_seed).map(|keys| (wallet, keys))) {
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
            cb.set_wallet_id("".into());
            cb.set_wallet_label("Wallet unavailable".into());
            cb.set_wallet_rename_value("".into());
            cb.set_wallet_kind("Error".into());
            cb.set_wallet_address("".into());
            cb.set_wallet_address_full("".into());
            cb.set_wallet_detail("".into());
            cb.set_wallet_list(model_from_strings(Vec::new()));
            cb.set_wallets(ModelRc::new(VecModel::from(Vec::<WalletRow>::new())));
            cb.set_archived_wallets(ModelRc::new(VecModel::from(Vec::<WalletRow>::new())));
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
    let values = values.into_iter().map(SharedString::from).collect::<Vec<_>>();
    ModelRc::new(VecModel::from(values))
}

fn warm_active_wallet(state: &Arc<Mutex<AppState>>) {
    let wallet_seed = {
        let st = state.lock().unwrap();
        st.active_wallet().ok().cloned().map(|wallet| (wallet, st.app_seed))
    };
    if let Some((wallet, app_seed)) = wallet_seed {
        std::thread::spawn(move || {
            let Ok(keys) = wallet.keys(&app_seed) else { return };
            let view_secret = keys.view_secret_bytes();
            txset::warm_chacha_key(&view_secret);
        });
    }
}

fn select_wallet(ui: &AppWindow, state: &Arc<Mutex<AppState>>, id: &str, allow_archived: bool) -> bool {
    {
        let mut st = state.lock().unwrap();
        let archived = match st.wallet_book.select_id(id) {
            Ok(wallet) => wallet.archived,
            Err(e) => return {
                drop(st);
                set_status(ui, &format!("{e}"));
                false
            },
        };
        if archived && !allow_archived {
            return {
                drop(st);
                set_status(ui, "Archived wallets must be restored before use.");
                false
            };
        }
        st.clear_wallet_artifacts();
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
        if st.active_wallet().map(|wallet| !wallet.archived).unwrap_or(false) {
            return true;
        }
        let Some(id) = st.wallet_book.records.iter().find(|wallet| !wallet.archived).map(|wallet| wallet.id.clone())
        else {
            drop(st);
            set_status(ui, "No active wallets.");
            return false;
        };
        match st.wallet_book.select_id(&id) {
            Ok(_) => {
                st.clear_wallet_artifacts();
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
        ScanQrResult::Qr { data, .. } => match String::from_utf8(data) {
            Ok(s) => s,
            Err(_) => {
                set_status(ui, "Seed QR must be UTF-8 text.");
                return false;
            }
        },
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
    import_seed_text(ui, state, &parsed.phrase, parsed.restore_height.unwrap_or(IMPORTED_RESTORE_HEIGHT))
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
        let phrase = phrase.ok_or_else(|| "Cake seed QR did not include seed words.".to_string())?;
        return Ok(ParsedSeedQr { phrase, restore_height });
    }
    Ok(ParsedSeedQr { phrase: trimmed.to_string(), restore_height: None })
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
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).map_err(|_| "Seed QR has invalid escaping.")?;
                let byte = u8::from_str_radix(hex, 16).map_err(|_| "Seed QR has invalid escaping.")?;
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

fn import_seed_text(ui: &AppWindow, state: &Arc<Mutex<AppState>>, phrase: &str, restore_height: u64) -> bool {
    let phrase = phrase.trim();
    if phrase.is_empty() {
        set_status(ui, "Seed words required.");
        return false;
    }
    let result = {
        let mut st = state.lock().unwrap();
        let app_seed = st.app_seed;
        match st.wallet_book.import_seed(&app_seed, phrase, restore_height) {
            Ok(wallet) => {
                let label = wallet.label.clone();
                st.clear_wallet_artifacts();
                Ok((st.data_dir.clone(), st.wallet_book.clone(), label))
            }
            Err(e) => Err(e),
        }
    };
    let (data_dir, book, label) = match result {
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
    set_status(ui, &format!("Imported wallet: {label}"));
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
        ScanQrResult::Qr { data, .. } => match String::from_utf8(data) {
            Ok(s) => normalize_monero_address(&s),
            Err(_) => {
                set_verify_result(ui, false, "Invalid QR", "Address QR was not UTF-8 text.", "");
                return;
            }
        },
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
    match find_wallet_address(state, &address) {
        Some(hit) => {
            set_verify_result(
                ui,
                true,
                "Address verified",
                &format!("{} · account {} / subaddress {}", hit.wallet_label, hit.account, hit.index),
                &address,
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
                &address,
            );
        }
    }
}

fn verify_address_index(ui: &AppWindow, state: &Arc<Mutex<AppState>>, account: &str, index: &str) -> bool {
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
                Ok(keys) => Ok((wallet.label.clone(), keys.address_at(st.network, account, index))),
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
    true
}

fn parse_verify_index(value: &str, label: &str) -> std::result::Result<u32, String> {
    value.trim().parse::<u32>().map_err(|_| format!("{label} must be a whole number"))
}

struct AddressHit {
    wallet_label: String,
    account: u32,
    index: u32,
}

fn find_wallet_address(state: &Arc<Mutex<AppState>>, address: &str) -> Option<AddressHit> {
    let st = state.lock().unwrap();
    let mut wallets = st.wallet_book.records.iter().collect::<Vec<_>>();
    wallets.sort_by_key(|wallet| if wallet.id == st.wallet_book.selected_id { 0 } else { 1 });
    for wallet in wallets {
        let Ok(keys) = wallet.keys(&st.app_seed) else { continue };
        for account in 0..VERIFY_ACCOUNT_LIMIT {
            for index in 0..VERIFY_SUBADDRESS_LIMIT {
                if keys.address_at(st.network, account, index) == address {
                    return Some(AddressHit { wallet_label: wallet.label.clone(), account, index });
                }
            }
        }
    }
    None
}

fn normalize_monero_address(raw: &str) -> String {
    let trimmed = raw.trim();
    let without_scheme =
        trimmed.strip_prefix("monero:").or_else(|| trimmed.strip_prefix("MONERO:")).unwrap_or(trimmed);
    without_scheme.split('?').next().unwrap_or(without_scheme).trim().to_string()
}

fn set_verify_result(ui: &AppWindow, matched: bool, title: &str, detail: &str, address: &str) {
    let cb = ui.global::<Callbacks>();
    cb.set_verify_ready(true);
    cb.set_verify_matched(matched);
    cb.set_verify_title(title.into());
    cb.set_verify_detail(detail.into());
    cb.set_verify_address(address.into());
}

fn populate_review(ui: &AppWindow, s: &TxSummary) {
    let cb = ui.global::<Callbacks>();
    cb.set_amount_xmr(monero::format_xmr(s.amount_atomic).into());
    cb.set_change_xmr(monero::format_xmr(s.change_atomic).into());
    // Fee is implicit and not yet computed (= inputs − outputs); show a dash
    // rather than a misleading 0 until the source walk lands.
    cb.set_fee_xmr(if s.fee_atomic == 0 { "—".into() } else { monero::format_xmr(s.fee_atomic).into() });
    cb.set_output_count(s.output_count as i32);
    cb.set_dest_address(truncate(s.destinations.first().map(String::as_str).unwrap_or("")).into());
    cb.set_dest_addresses(model_from_strings(s.destinations.clone()));
    cb.set_dest_address_labels(model_from_strings(
        s.destinations
            .iter()
            .enumerate()
            .map(|(i, addr)| {
                let amount = s
                    .destination_amounts_atomic
                    .get(i)
                    .copied()
                    .map(monero::format_xmr)
                    .unwrap_or_else(|| "?".into());
                format!("{amount} XMR · {}", truncate(addr))
            })
            .collect(),
    ));
    let indices = if s.subaddr_indices.is_empty() {
        "none".to_string()
    } else {
        s.subaddr_indices.iter().map(u32::to_string).collect::<Vec<_>>().join(", ")
    };
    cb.set_tx_account_info(format!("Account {} / subaddresses {indices}", s.subaddr_account).into());
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

fn load_wallet_book(dir: &PathBuf) -> anyhow::Result<wallets::WalletBook> { load_wallet_book_impl(dir) }

#[cfg(not(keyos))]
fn load_wallet_book_impl(dir: &PathBuf) -> anyhow::Result<wallets::WalletBook> {
    let path = dir.join(WALLET_BOOK_FILE);
    if !path.exists() {
        return Ok(wallets::WalletBook::new(PAIR_RESTORE_HEIGHT));
    }
    let text = std::fs::read_to_string(path)?;
    wallets::from_json(&text, PAIR_RESTORE_HEIGHT).map_err(|e| anyhow::anyhow!("{e}"))
}

#[cfg(keyos)]
fn load_wallet_book_impl(_dir: &PathBuf) -> anyhow::Result<wallets::WalletBook> {
    let fs = FileSystem::default();
    match read_text_fs_limited(&fs, WALLET_BOOK_FILE, fs::Location::AppData, 65_536, "wallets") {
        Ok(text) => wallets::from_json(&text, PAIR_RESTORE_HEIGHT).map_err(|e| anyhow::anyhow!("{e}")),
        Err(_) => Ok(wallets::WalletBook::new(PAIR_RESTORE_HEIGHT)),
    }
}

fn save_wallet_book(dir: &PathBuf, book: &wallets::WalletBook) -> anyhow::Result<()> {
    save_wallet_book_impl(dir, book)
}

#[cfg(not(keyos))]
fn save_wallet_book_impl(dir: &PathBuf, book: &wallets::WalletBook) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    let json = wallets::to_json(book).map_err(|e| anyhow::anyhow!("{e}"))?;
    std::fs::write(dir.join(WALLET_BOOK_FILE), json)?;
    Ok(())
}

#[cfg(keyos)]
fn save_wallet_book_impl(_dir: &PathBuf, book: &wallets::WalletBook) -> anyhow::Result<()> {
    use std::io::{Seek, SeekFrom, Write};

    let json = wallets::to_json(book).map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut fs = FileSystem::default();
    {
        let mut file = fs
            .open_file(
                WALLET_BOOK_FILE,
                fs::Location::AppData,
                fs::OpenFlags { read: true, write: true, create: true },
            )
            .map_err(|e| anyhow::anyhow!("open {WALLET_BOOK_FILE}: {e:?}"))?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(json.as_bytes())?;
        file.truncate().map_err(|e| anyhow::anyhow!("truncate {WALLET_BOOK_FILE}: {e:?}"))?;
        file.flush()?;
    }
    fs.flush(fs::Location::AppData).map_err(|e| anyhow::anyhow!("flush app data: {e:?}"))?;
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
    let result =
        select_file::<GuiPermissions>(options).map_err(|e| anyhow::anyhow!("picker error: {e:?}"))?;
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
        .open_file(path.to_string(), location, fs::OpenFlags { read: true, write: false, create: false })
        .map_err(|e| anyhow::anyhow!("open {path}: {e:?}"))?;
    let mut buf = Vec::new();
    file.take(max).read_to_end(&mut buf).map_err(|e| anyhow::anyhow!("read {path}: {e:?}"))?;
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
    let result =
        select_file::<GuiPermissions>(options).map_err(|e| anyhow::anyhow!("picker error: {e:?}"))?;
    let Some(result) = result else {
        anyhow::bail!("cancelled");
    };
    let Some((dir, loc)) = result.files().first().cloned() else {
        anyhow::bail!("no folder selected");
    };
    let dir = dir.trim_end_matches('/').to_string();
    let dir = if dir.is_empty() { EXPORT_DIR.to_string() } else { dir };
    write_export(filename, bytes, map_location(loc), &dir)
}

/// Write `bytes` to a fresh file inside `dir` at `location`. The directory-entry
/// flush on close is the critical step on FAT/SD (see the Liana signer notes):
/// chunked write -> `File::flush` (writes the dir entry) -> close -> fs flush.
fn write_export(filename: &str, bytes: &[u8], location: fs::Location, dir: &str) -> anyhow::Result<String> {
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
    let unique =
        directory.pick_next_filename(filename, None).map_err(|e| anyhow::anyhow!("pick filename: {e:?}"))?;
    let path = format!("{dir}/{unique}");
    {
        let mut file = filesystem
            .open_file(path.clone(), location, fs::OpenFlags { read: false, write: true, create: true })
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
        file.flush().map_err(|e| anyhow::anyhow!("flush {path}: {e:?}"))?;
    } // drop file -> CloseFile (re-commits the directory entry)
    drop(directory); // CloseDir
    filesystem.flush(location).map_err(|e| anyhow::anyhow!("flush fs: {e:?}"))?;
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
        .open_file(path.clone(), location, fs::OpenFlags { read: true, write: false, create: false })
        .is_ok()
    {
        drop(directory);
        return Ok(format!("{}{} (existing)", loc_label(location), path));
    }
    {
        let mut file = filesystem
            .open_file(path.clone(), location, fs::OpenFlags { read: false, write: true, create: true })
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
        file.flush().map_err(|e| anyhow::anyhow!("flush {path}: {e:?}"))?;
    }
    drop(directory);
    filesystem.flush(location).map_err(|e| anyhow::anyhow!("flush fs: {e:?}"))?;
    Ok(format!("{}{}", loc_label(location), path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cake_seed_uri() {
        let parsed = parse_cake_seed_qr("monero-wallet:?seed=alpha+beta%20gamma&height=3400000").unwrap();
        assert_eq!(parsed.phrase, "alpha beta gamma");
        assert_eq!(parsed.restore_height, Some(3_400_000));
    }

    #[test]
    fn parses_plain_seed_qr_text() {
        let parsed = parse_cake_seed_qr("alpha beta gamma").unwrap();
        assert_eq!(parsed.phrase, "alpha beta gamma");
        assert_eq!(parsed.restore_height, None);
    }
}
