use base64::{Engine as _, engine::general_purpose};
use ed25519_dalek::SigningKey;
use std::fs::{self, write};

use crate::error::AppError;

// Save private key
pub fn save_signing_key_to_file(key: &SigningKey, path: &str) -> Result<(), AppError> {
    let encoded = general_purpose::STANDARD.encode(key.to_bytes());
    write(path, encoded).map_err(AppError::from)
}


// Load the saved private key
pub fn load_signing_key_from_file(path: &str) -> Result<SigningKey, AppError> {
    let encoded = fs::read_to_string(path)?;
    let bytes = general_purpose::STANDARD.decode(encoded.trim())?;
    let raw: [u8; 32] = bytes.try_into().map_err(|_| AppError::KeyLength)?;
    let key = SigningKey::from_bytes(&raw);

    Ok(key)
}
