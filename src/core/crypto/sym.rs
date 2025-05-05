use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};
use chacha20poly1305::{
    AeadCore, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, OsRng},
};

use crate::{
    error::{AppError, ErrArgon2, ErrCypher},
    user::domain::{User, UserPassword},
};

pub fn encrypt_data(plaintxt: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, AppError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

    let mut ciphertxt = cipher
        .encrypt(&nonce, plaintxt)
        .map_err(|_| AppError::Cypher(ErrCypher::EncryptionFailed))?;

    let mut result = nonce.to_vec();
    result.append(&mut ciphertxt);
    Ok(result)
}

pub fn decrypt_data(encrypted_data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, AppError> {
    if encrypted_data.len() < 24 {
        return Err(AppError::Cypher(ErrCypher::InvalidData));
    }

    let (nonce_bytes, ciphertxt) = encrypted_data.split_at(24);
    let nonce = XNonce::from_slice(nonce_bytes);

    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(nonce, ciphertxt)
        .map_err(|_| AppError::Cypher(ErrCypher::DecryptionFailed))
}

pub fn derive_key_from_password(raw_password: &str, user: &User) -> Result<[u8; 32], AppError> {
    let salt = user.get_salt()?;

    let argon2 = Argon2::default();

    let hash = argon2
        .hash_password(raw_password.as_bytes(), &salt)
        .map_err(|e| AppError::Argon2(ErrArgon2::PasswordHashError(e)))?;

    let raw_hash = hash.hash.ok_or(AppError::Cypher(ErrCypher::MissingHash))?;
    let mut key = [0u8; 32];
    key.copy_from_slice(raw_hash.as_bytes());
    Ok(key)
}
