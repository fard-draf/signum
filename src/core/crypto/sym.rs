use tracing::{error, info};
use zeroize::Zeroize;

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
    info!("DECRPT_DATA: cipher: {:?}", ciphertxt);

    let nonce = XNonce::from_slice(nonce_bytes);
    let cipher = XChaCha20Poly1305::new(key.into());

    match cipher.decrypt(nonce, ciphertxt) {
        Ok(plaintext) => {
            info!("DECRPT_DATA: OK");
            Ok(plaintext)
        }
        Err(e) => {
            info!("DECRPT_DATA: decryption failed");
            error!("DECRPT_DATA: decryption failed: {:?}", e);
            Err(AppError::Encrypt(ErrEncrypt::DecryptionFailed))
        }
    }
}

pub fn derive_key_from_password(temp_pw: &mut str, user: &User) -> Result<[u8; 32], AppError> {
    let salt = user.get_salt()?;
    info!("DERIVE_FROM_K: salt {}", salt);
    info!("DERIVE_FROM_K: temp_pw {}", temp_pw);

    let argon2 = Argon2::default();

    let hash = argon2
        .hash_password(temp_pw.as_bytes(), &salt)
        .map_err(|e| AppError::Argon2(ErrArgon2::PasswordHashError(e)))?;
    let raw_hash = hash
        .hash
        .ok_or(AppError::Encrypt(ErrEncrypt::MissingHash))?;
    let mut key = [0u8; 32];
    key.copy_from_slice(raw_hash.as_bytes());
    info!("DERIVE_FROM_K: key {:?}", key);
    Ok(key)
}
