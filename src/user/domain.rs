use std::fmt::{Debug, Display};

use argon2::{
    Argon2, PasswordHash,
    password_hash::SaltString,
    password_hash::{PasswordHasher, PasswordVerifier},
};
use borsh::{BorshDeserialize, BorshSerialize};
use rand_core::OsRng;
use zeroize::{self, Zeroize};

use crate::error::{AppError, ErrArgon2, ErrCypher, ErrPassword, ErrPath, ErrUser};

impl Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "user_name: {}", self.name)
    }
}
#[derive(PartialEq, Eq, PartialOrd, BorshSerialize, BorshDeserialize)]
pub struct User {
    pub name: UserName,
    pub password: UserPassword,
    pub cypher_salt: String,
    pub file_path: UserFilePath,
}

impl User {
    pub fn new(
        name: UserName,
        cypher_salt: String,
        password: UserPassword,
        file_path: UserFilePath,
    ) -> Self {
        Self {
            name,
            cypher_salt,
            password,
            file_path,
        }
    }

    pub fn get_salt(&self) -> Result<SaltString, AppError> {
        SaltString::from_b64(&self.cypher_salt)
            .map_err(|_| AppError::Cypher(ErrCypher::InvalidSalt))
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, BorshSerialize, BorshDeserialize, Debug)]
pub struct UserName {
    pub name: String,
}

impl UserName {
    pub fn new(raw_name: &str) -> Result<Self, AppError> {
        let cleaned_name = raw_name.trim().to_lowercase();
        if cleaned_name.len() <= 2 {
            return Err(AppError::User(ErrUser::InvalidNameTooShort));
        }
        if cleaned_name.len() >= 17 {
            return Err(AppError::User(ErrUser::InvalidNameTooLong));
        }
        if !cleaned_name.chars().all(|c| c.is_ascii_alphabetic()) {
            return Err(AppError::User(ErrUser::InvalidCharacters));
        }

        Ok(Self { name: cleaned_name })
    }

    pub fn verify_username(&self, raw_name: &mut str) -> Result<(), AppError> {
        let cleaned_name = raw_name.trim().to_lowercase();
        if cleaned_name == self.name {
            raw_name.zeroize();
            Ok(())
        } else {
            raw_name.zeroize();
            Err(AppError::User(ErrUser::UserNotFound))
        }
    }
}

impl Display for UserName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

#[derive(PartialEq, Eq, PartialOrd, BorshSerialize, BorshDeserialize, Debug)]
pub struct UserPassword {
    hashed: String,
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
        let argon2 = Argon2::default();
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
        Argon2::default()
            .verify_password(plain.as_bytes(), &parsed_hash)
            .map_err(|_| AppError::Argon2(ErrArgon2::UnableToVerifyPassword))
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

#[derive(PartialEq, Eq, PartialOrd, Ord, BorshSerialize, BorshDeserialize)]
pub struct UserFilePath {
    pub path: String,
}

impl UserFilePath {
    pub fn new(path: String) -> Result<Self, AppError> {
        const FORBIDDEN: &[char] = &['\0', '|', ';', '>', '<'];
        let path = path.trim().to_string();
        if path.chars().any(|c| c.is_whitespace()) || path.chars().any(|c| FORBIDDEN.contains(&c)) {
            return Err(AppError::Path(ErrPath::ForbiddenCharacters));
        }

        Ok(UserFilePath { path })
    }
}
