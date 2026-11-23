/// Something that couldn't be done, with a message fit to show.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("wrong master password")]
    WrongPassword,
    #[error("{0}")]
    Invalid(String),
    #[error("there's no item with that id")]
    NotFound,
    /// The S3 folder holds another vault than this device's.
    #[error("this S3 folder holds a different vault")]
    DifferentVault,
    /// Another device changed the master password (and the vault key):
    /// lock, and unlock with the new password.
    #[error("the master password was changed on another device: lock the vault and unlock it with the new master password")]
    PasswordChangedElsewhere,
    /// A copy of the vault key kept for unlocking without the master
    /// password (Face ID, a PIN, a browser session) from before the master
    /// password changed.
    #[error("the master password was changed: unlock with the master password")]
    StaleKey,
    #[error("{0}")]
    S3(#[from] crate::s3::S3Error),
    #[error("couldn't reach S3: {0}")]
    Network(String),
    #[error("{0}")]
    Import(String),
}

impl Error {
    pub fn invalid(message: impl Into<String>) -> Error {
        Error::Invalid(message.into())
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
