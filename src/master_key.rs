// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Device app seed, backed by KeyOS `security.app_seed()`.
//!
//! On real hardware the 32-byte app seed is device-bound and only available
//! once the user is logged in. Hosted simulator builds keep a deterministic
//! fallback so local development remains usable without a hardware login.
//!
//! The Monero spend/view keys are derived from this seed in [`crate::monero::keys`].

security::use_api!();

/// Fetch the 32-byte app seed. Hardware must never fall back to a known key.
#[cfg(keyos)]
pub fn app_seed() -> Result<[u8; 32], security::AccessDenied> { Security::default().app_seed() }

/// Simulator: pin the deterministic dev wallet (seed 0x11*32). This makes the
/// app's Monero wallet match the CLI-verified test fixtures, so "Export
/// view-only" yields the known stagenet address and "Import" can decode the
/// `unsigned_monero_tx` fixture built for that same wallet.
#[cfg(not(keyos))]
pub fn app_seed() -> Result<[u8; 32], security::AccessDenied> {
    let _ = Security::default; // keep the generated API referenced
    Ok([0x11; 32])
}
