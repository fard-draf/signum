use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};

use crate::error::{AppError, ErrArgon2};

use crate::user::domain::UserPassword;

pub fn hash_password(plain: &str) -> Result<UserPassword, AppError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(plain.as_bytes(), &salt)
        .map_err(|e| AppError::Argon2(ErrArgon2::PasswordHashError(e)))?
        .to_string();
    Ok(UserPassword { password: hash })
}

pub fn verify_password(hash: &UserPassword, plain: &str) -> Result<(), AppError> {
    let parsed_hash = UserPassword::parse_to_hash(hash)?;
    Argon2::default()
        .verify_password(plain.as_bytes(), &parsed_hash)
        .map_err(|e| AppError::Argon2(ErrArgon2::Unauthorized))
}
