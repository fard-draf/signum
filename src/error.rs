use std::error::Error as StdError;
use std::fmt::Display;

use base64::DecodeError;
use ed25519_dalek::SignatureError as DalekSignatureError;
use ed25519_dalek::ed25519::Error as DalekError;
use inquire::InquireError;
use std::io::Error as IOError;

#[derive(Debug)]
pub enum AppError {
    DalekSignatureError(DalekSignatureError),
    IOError(std::io::Error),
    InquireError(inquire::error::InquireError),
    DecodeError(base64::DecodeError),
    InvalidKey,
    KeyLength,
    InvalidPath,
    Error,
}

impl Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DalekSignatureError(e) => write!(f, "Signature error: {}", e),
            Self::IOError(e) => write!(f, "Input error: {}", e),
            Self::InquireError(e) => write!(f, "Inquire Error: {}", e),
            Self::DecodeError(e) => write!(f, "Decode error: {}", e),
            Self::InvalidKey => write!(f, "Invalid key"),
            Self::KeyLength => write!(f, "Invalid key lenght"),
            Self::InvalidPath => write!(f, "Invalid path"),
            Self::Error => panic!(),
        }
    }
}

impl From<DalekSignatureError> for AppError {
    fn from(value: DalekSignatureError) -> Self {
        AppError::DalekSignatureError(value)
    }
}

impl From<IOError> for AppError {
    fn from(value: IOError) -> Self {
        AppError::IOError(value)
    }
}

impl From<InquireError> for AppError {
    fn from(value: InquireError) -> Self {
        AppError::InquireError(value)
    }
}

impl From<DecodeError> for AppError {
    fn from(value: base64::DecodeError) -> Self {
        AppError::DecodeError(value)
    }
}
