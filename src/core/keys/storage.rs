use ed25519_dalek::SigningKey;
use std::fs::{self};
use zeroize::Zeroize;

use crate::{
    core::crypto::sym::{decrypt_data, encrypt_data},
    error::{AppError, ErrEncrypt, ErrIO},
};

// Save private key
pub fn save_signing_key_to_file(
    key: &SigningKey,
    path: &str,
    encryption_key: &[u8; 32],
) -> Result<(), AppError> {
    let mut key_bytes = key.to_bytes();
    let encrypted = encrypt_data(&key_bytes, encryption_key)?;

    fs::write(path, &encrypted).map_err(|e| AppError::IO(ErrIO::IoError(e)))?;
    key_bytes.zeroize();

    Ok(())
}

// Load the saved private key
pub fn load_signing_key_from_file(
    path: &str,
    encryption_key: &[u8; 32],
) -> Result<SigningKey, AppError> {
    let encrypted = fs::read(path).map_err(|e| AppError::IO(ErrIO::IoError(e)))?;
    let mut decrypted = decrypt_data(&encrypted, encryption_key)?;
    let raw: [u8; 32] = decrypted
        .as_slice()
        .try_into()
        .map_err(|_| AppError::Encrypt(ErrEncrypt::InvalidKey))?;
    let key = SigningKey::from_bytes(&raw);
    decrypted.zeroize();

    Ok(key)
}
