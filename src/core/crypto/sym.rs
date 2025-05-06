use tracing::{error, info};

use crate::{
    domain::user::entities::User,
    error::{AppError, ErrArgon2, ErrEncrypt},
};
use argon2::{Argon2, password_hash::PasswordHasher};
use chacha20poly1305::{
    AeadCore, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, OsRng},
};

pub fn encrypt_data(plaintxt: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, AppError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

    let mut ciphertxt = cipher
        .encrypt(&nonce, plaintxt)
        .map_err(|_| AppError::Encrypt(ErrEncrypt::EncryptionFailed))?;

    let mut result = nonce.to_vec();
    result.append(&mut ciphertxt);
    Ok(result)
}

pub fn decrypt_data(encrypted_data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, AppError> {
    if encrypted_data.len() < 40 {
        return Err(AppError::Encrypt(ErrEncrypt::InvalidData));
    }

    let (nonce_bytes, ciphertxt) = encrypted_data.split_at(24);

    if ciphertxt.is_empty() {
        return Err(AppError::Encrypt(ErrEncrypt::InvalidData));
    }
    info!("cipher isnt empty: {:?}", ciphertxt);

    let nonce = XNonce::from_slice(nonce_bytes);
    let cipher = XChaCha20Poly1305::new(key.into());

    match cipher.decrypt(nonce, ciphertxt) {
        Ok(plaintext) => Ok(plaintext),
        Err(e) => {
            error!("Decryption failed: {:?}", e);
            Err(AppError::Encrypt(ErrEncrypt::DecryptionFailed))
        }
    }
}

pub fn derive_key_from_password(raw_password: &str, user: &User) -> Result<[u8; 32], AppError> {
    let salt = user.get_salt()?;
    info!("salt {}", salt);
    
    let argon2 = Argon2::default();

    let hash = argon2
        .hash_password(raw_password.as_bytes(), &salt)
        .map_err(|e| AppError::Argon2(ErrArgon2::PasswordHashError(e)))?;

    let raw_hash = hash
        .hash
        .ok_or(AppError::Encrypt(ErrEncrypt::MissingHash))?;
    let mut key = [0u8; 32];
    key.copy_from_slice(raw_hash.as_bytes());
    Ok(key)
}
