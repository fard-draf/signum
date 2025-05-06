use argon2::password_hash::SaltString;
use borsh::{BorshDeserialize, BorshSerialize};
use std::fmt::{Debug, Display};
use zeroize::{self, Zeroize};

use crate::{
    domain::user::{file_path::UserFilePath, passwords::UserPassword},
    error::{AppError, ErrEncrypt, ErrUser},
};

#[derive(BorshSerialize, BorshDeserialize)]
pub struct UserMetadata {
    pub name: UserName,
    pub user_salt: String,
}

impl Zeroize for UserMetadata {
    fn zeroize(&mut self) {
        self.user_salt.zeroize();
        self.name.zeroize();
    }
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct UserSecureData {
    pub password: UserPassword,
    pub file_path: UserFilePath,
}

impl Zeroize for UserSecureData {
    fn zeroize(&mut self) {
        self.password.zeroize();
        self.file_path.zeroize();
    }
}

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

    pub fn get_metadata(&self) -> UserMetadata {
        UserMetadata {
            name: self.name.clone(),
            user_salt: self.cypher_salt.clone(),
        }
    }

    pub fn get_secure_data(&self) -> UserSecureData {
        UserSecureData {
            password: self.password.clone(),
            file_path: self.file_path.clone(),
        }
    }

    pub fn get_salt(&self) -> Result<SaltString, AppError> {
        SaltString::from_b64(&self.cypher_salt)
            .map_err(|_| AppError::Encrypt(ErrEncrypt::InvalidSalt))
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, BorshSerialize, BorshDeserialize, Debug)]
pub struct UserName {
    pub name: String,
}

impl Zeroize for UserName {
    fn zeroize(&mut self) {
        self.name.zeroize();
    }
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
