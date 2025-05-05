use argon2::password_hash::SaltString;
use borsh::{BorshDeserialize, BorshSerialize};
use std::fmt::{Debug, Display};
use zeroize::{self, Zeroize};

use crate::{
    domain::user::{file_path::UserFilePath, passwords::UserPassword},
    error::{AppError, ErrCypher, ErrUser},
};
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
