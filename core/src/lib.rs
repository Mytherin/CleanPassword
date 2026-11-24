//! CleanPassword's shared core, used by the Chrome extension (through
//! `wasm/`) and the iPhone app and its AutoFill extension (through `ffi/`).
//!
//! - [`vault`]: the vault: items, the master password, what each device
//!   keeps (always encrypted), unlocking and locking.
//! - [`sync`]: syncing a vault with a folder in an S3 bucket, over a
//!   [`s3::Transport`] the app supplies (`fetch` in Chrome, a native HTTP
//!   client on iOS), so the same engine runs everywhere.
//! - [`crypto`]: Argon2id and XChaCha20-Poly1305.
//! - [`generator`] and [`rules`]: passwords, passphrases and Apple-style
//!   passwords, following websites' own password rules.
//! - [`matching`]: which items belong to a web page.
//! - [`totp`]: one-time codes.
//! - [`import`]: Bitwarden (JSON, password-protected JSON, CSV) and other
//!   CSV exports, and a Bitwarden-compatible export.

pub mod crypto;
mod error;
pub mod generator;
pub mod import;
pub mod item;
pub mod matching;
pub mod passkey;
pub mod rules;
pub mod s3;
pub mod ssh;
pub mod sync;
pub mod totp;
pub mod vault;

pub use error::{Error, Result};
pub use item::{Field, HistoryEntry, Item, ItemData, ItemKind, ItemUri, UriMatch};
pub use vault::{AwsCredentials, S3Config, Vault};
