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
