use borsh::{BorshDeserialize, BorshSerialize, to_vec};
use std::fs;
use zeroize::{self, Zeroize};

use crate::{
    core::crypto::sym::{decrypt_data, derive_key_from_password, encrypt_data},
    domain::user::{entities::User, file_path::UserFilePath},
    error::{AppError, ErrCypher},
};

pub fn save_user(user: &User, key: &mut [u8; 32], path: &UserFilePath) -> Result<(), AppError> {
    let data = to_vec(user).map_err(|_| AppError::Cypher(ErrCypher::BorshError))?;
    let encrypted = encrypt_data(&data, key)?;
    let result =
        fs::write(&path.path, encrypted).map_err(|_| AppError::Cypher(ErrCypher::WriteError));
    key.zeroize();
    result
}

pub fn load_user(key: &[u8; 32], path: &UserFilePath) -> Result<User, AppError> {
    let mut encrypted = fs::read(&path.path).map_err(|_| AppError::Cypher(ErrCypher::ReadError))?;
    let mut decrypted = decrypt_data(&encrypted, key)?;
    let user = User::try_from_slice(&decrypted)
        .map_err(|_| AppError::Cypher(ErrCypher::DecryptionFailed))?;
    encrypted.zeroize();
    decrypted.zeroize();
    Ok(user)
}
