use tracing::{debug, error};
use zeroize::Zeroize;

use crate::{
    domain::user::entities::User,
    error::{AppError, ErrArgon2, ErrEncrypt},
};
use argon2::{Algorithm, Argon2, ParamsBuilder, Version, password_hash::PasswordHasher};
use chacha20poly1305::{
    AeadCore, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, OsRng, Payload},
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
    let nonce = XNonce::from_slice(nonce_bytes);
    let cipher = XChaCha20Poly1305::new(key.into());

    match cipher.decrypt(nonce, ciphertxt) {
        Ok(plaintext) => Ok(plaintext),
        Err(e) => {
            debug!(
                "DECRPT_DATA: decryption failed (likely integrity/AAD mismatch): {:?}",
                e
            );
            Err(AppError::Encrypt(ErrEncrypt::DecryptionFailed))
        }
    }
}

pub const PAYLOAD_VERSION: u8 = 1;

pub fn encrypt_with_aad(plaintext: &[u8], key: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>, AppError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let aad_len = (aad.len() as u16).to_be_bytes();

    let mut versioned_aad = Vec::with_capacity(1 + 2 + aad.len());
    versioned_aad.push(PAYLOAD_VERSION);
    versioned_aad.extend_from_slice(&aad_len);
    versioned_aad.extend_from_slice(aad);

    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &versioned_aad,
            },
        )
        .map_err(|_| AppError::Encrypt(ErrEncrypt::EncryptionFailed))?;

    let mut out = Vec::with_capacity(1 + 2 + aad.len() + nonce.len() + ciphertext.len());
    out.extend_from_slice(&versioned_aad);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn decrypt_with_aad(
    encrypted: &[u8],
    key: &[u8; 32],
    expected_aad: Option<&[u8]>,
) -> Result<Vec<u8>, AppError> {
    if encrypted.len() < 1 + 2 + 24 + 16 {
        return Err(AppError::Encrypt(ErrEncrypt::InvalidData));
    }
    let version = encrypted[0];
    if version != PAYLOAD_VERSION {
        return Err(AppError::Encrypt(ErrEncrypt::InvalidData));
    }
    let aad_len_bytes = &encrypted[1..3];
    let aad_len = u16::from_be_bytes([aad_len_bytes[0], aad_len_bytes[1]]) as usize;
    if encrypted.len() < 1 + 2 + aad_len + 24 + 16 {
        return Err(AppError::Encrypt(ErrEncrypt::InvalidData));
    }
    let aad = &encrypted[3..3 + aad_len];
    if let Some(expected) = expected_aad {
        if expected != aad {
            return Err(AppError::Encrypt(ErrEncrypt::InvalidData));
        }
    }
    let offset = 3 + aad_len;
    let (nonce_bytes, ciphertxt) = encrypted[offset..].split_at(24);
    let nonce = XNonce::from_slice(nonce_bytes);
    let cipher = XChaCha20Poly1305::new(key.into());

    let mut versioned_aad = Vec::with_capacity(1 + 2 + aad.len());
    versioned_aad.push(version);
    versioned_aad.extend_from_slice(&(aad.len() as u16).to_be_bytes());
    versioned_aad.extend_from_slice(aad);

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertxt,
                aad: &versioned_aad,
            },
        )
        .map_err(|_| AppError::Encrypt(ErrEncrypt::DecryptionFailed))
}

pub fn derive_key_from_password(temp_pw: &mut str, user: &User) -> Result<[u8; 32], AppError> {
    let salt = user.get_salt()?;

    let argon2 = hardened_argon2()?;

    let hash = argon2
        .hash_password(temp_pw.as_bytes(), &salt)
        .map_err(|e| AppError::Argon2(ErrArgon2::PasswordHashError(e)))?;
    temp_pw.zeroize();
    let raw_hash = hash
        .hash
        .ok_or(AppError::Encrypt(ErrEncrypt::MissingHash))?;
    let mut key = [0u8; 32];
    key.copy_from_slice(raw_hash.as_bytes());
    Ok(key)
}

fn hardened_argon2() -> Result<Argon2<'static>, AppError> {
    let (m_cost, t_cost, p_cost) = kdf_params_from_env();
    let params = ParamsBuilder::new()
        .m_cost(m_cost)
        .t_cost(t_cost)
        .p_cost(p_cost)
        .output_len(32)
        .build()
        .map_err(|e| AppError::Argon2(ErrArgon2::ArgErr(e)))?;

    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

fn kdf_params_from_env() -> (u32, u32, u32) {
    let m_cost = std::env::var("SIGNUM_KDF_MIB")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .map(|mib| mib.saturating_mul(1024))
        .unwrap_or(64 * 1024);
    let t_cost = std::env::var("SIGNUM_KDF_TIME")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(3);
    let p_cost = std::env::var("SIGNUM_KDF_PAR")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(1);
    (m_cost, t_cost, p_cost)
}

pub fn authenticate_aad(key: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>, AppError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let tag = cipher
        .encrypt(&nonce, Payload { msg: &[], aad })
        .map_err(|_| AppError::Encrypt(ErrEncrypt::EncryptionFailed))?;

    let mut res = nonce.to_vec();
    res.extend_from_slice(&tag);
    Ok(res)
}

pub fn verify_aad(key: &[u8; 32], aad: &[u8], tag: &[u8]) -> Result<(), AppError> {
    if tag.len() < 40 {
        return Err(AppError::Encrypt(ErrEncrypt::InvalidData));
    }
    let (nonce_bytes, mac) = tag.split_at(24);
    let nonce = XNonce::from_slice(nonce_bytes);
    let cipher = XChaCha20Poly1305::new(key.into());

    cipher
        .decrypt(nonce, Payload { msg: mac, aad })
        .map_err(|_| AppError::Encrypt(ErrEncrypt::DecryptionFailed))?;
    Ok(())
}
