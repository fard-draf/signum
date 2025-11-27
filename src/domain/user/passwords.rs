use argon2::{
    Algorithm, Argon2, ParamsBuilder, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use borsh::{BorshDeserialize, BorshSerialize};
use rand_core::OsRng;
use zeroize::{self, Zeroize};

use crate::error::{AppError, ErrArgon2, ErrPassword};

#[derive(PartialEq, Eq, PartialOrd, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct UserPassword {
    hashed: String,
}

impl Zeroize for UserPassword {
    fn zeroize(&mut self) {
        self.hashed.zeroize();
    }
}

impl UserPassword {
    pub fn from_raw(raw: &str) -> Result<Self, AppError> {
        let mut pw = raw.trim().to_string();
        if pw.len() < 10 {
            return Err(AppError::Password(ErrPassword::PasswordTooShort));
        }

        if pw.len() > 30 {
            return Err(AppError::Password(ErrPassword::PasswordTooLong));
        }

        if !pw.chars().any(|c| c.is_lowercase())
            || !pw.chars().any(|c| c.is_uppercase())
            || !pw.chars().any(|c| c.is_numeric())
        {
            return Err(AppError::Password(ErrPassword::PasswordTooWeak));
        }

        let digit_count = pw.chars().filter(|c| c.is_ascii_digit()).count();
        if digit_count < 4 {
            return Err(AppError::Password(ErrPassword::NotEnoughtDigits));
        }

        let special_count = pw.chars().filter(|c| !c.is_alphanumeric()).count();
        if special_count < 1 {
            return Err(AppError::Password(ErrPassword::MissingSpecialCharacters));
        }

        let salt = SaltString::generate(&mut OsRng);
        let argon2 = hardened_argon2()?;
        let hash = argon2
            .hash_password(pw.as_bytes(), &salt)
            .map_err(|e| AppError::Argon2(ErrArgon2::PasswordHashError(e)))?
            .to_string();

        pw.zeroize();
        let valid_pw = UserPassword {
            hashed: hash.to_owned(),
        };
        Ok(valid_pw)
    }

    pub fn verify_password(hash: &UserPassword, plain: &str) -> Result<(), AppError> {
        let parsed_hash = UserPassword::parse_to_hash(hash)?;
        let argon2 = hardened_argon2()?;
        argon2
            .verify_password(plain.as_bytes(), &parsed_hash)
            .map_err(|_| AppError::Argon2(ErrArgon2::UnableToVerifyPassword))?;
        Ok(())
    }

    pub fn parse_to_hash(&self) -> Result<PasswordHash<'_>, AppError> {
        PasswordHash::new(&self.hashed)
            .map_err(|e| AppError::Argon2(ErrArgon2::PasswordHashError(e)))
    }
}

impl Drop for UserPassword {
    fn drop(&mut self) {
        self.hashed.zeroize();
    }
}

fn hardened_argon2() -> Result<Argon2<'static>, AppError> {
    let (m_cost, t_cost, p_cost) = kdf_params_from_env();
    let params = ParamsBuilder::new()
        .m_cost(m_cost)
        .t_cost(t_cost)
        .p_cost(p_cost)
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
