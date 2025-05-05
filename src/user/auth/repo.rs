use borsh::{BorshDeserialize, BorshSerialize, to_vec};
use std::fs;
use zeroize::{self, Zeroize};

use crate::{
    core::crypto::sym::{decrypt_data, derive_key_from_password, encrypt_data},
    error::{AppError, ErrCypher, ErrPath},
    user::domain::{User, UserFilePath},
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto::sym::derive_key_from_password;
    use crate::user::domain::{User, UserFilePath, UserName, UserPassword};
    use argon2::password_hash::SaltString;

    #[test]
    fn test_save_and_load_user_securely() {
        let password = "S3cur3P@ssw0rd!2024";
        let salt = SaltString::from_b64("w7dVt97tCz9S2cXqP+6s2Q").unwrap();

        let user = User {
            name: UserName::new("alice").unwrap(),
            password: UserPassword::from_raw(password).unwrap(),
            file_path: UserFilePath::new("test_user_dsp07hhi.borsh.enc".to_string()).unwrap(),
            cypher_salt: salt.to_string(),
        };

        let mut key = derive_key_from_password(password, &user).expect("Key derivation failed");

        save_user(&user, &mut key, &user.file_path).expect("Failed to save user");

        let bad_password = "S3cur3P@ssw0rd!2025";
        let key = derive_key_from_password(password, &user).expect("Key derivation failed");
        let loaded = load_user(&key, &user.file_path).expect("Failed to load user");

        assert_eq!(user.name, loaded.name);
        assert_eq!(user.password, loaded.password);

        let bad_key = derive_key_from_password(bad_password, &user).expect("Key derivation failed");
        let cant_loaded = load_user(&bad_key, &user.file_path);

        assert!(cant_loaded.is_err());

        std::fs::remove_file(&user.file_path.path).unwrap();
    }
}
