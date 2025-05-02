use std::error::Error as StdError;
use std::fmt::Display;

use ed25519_dalek::SignatureError as DalekSignatureError;
use ed25519_dalek::ed25519::Error as DalekError;
use std::io::Error as IOError;

#[derive(Debug)]
pub enum AppError {
    DalekSignatureError(DalekSignatureError),
    InputError(std::io::Error),
    Decode(base64::DecodeError),
    InvalidKey,
    KeyLength,
}

impl Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DalekSignatureError(e) => write!(f, "Signature error: {}", e),
            Self::InputError(e) => write!(f, "Input error: {}", e),
            Self::Decode(e) => write!(f, "Decode error: {}", e),
            Self::InvalidKey => write!(f, "Invalid key"),
            Self::KeyLength => write!(f, "Invalid key lenght"),
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
        AppError::InputError(value)
    }
}

impl From<base64::DecodeError> for AppError {
    fn from(value: base64::DecodeError) -> Self {
        AppError::Decode(value)
    }
}
