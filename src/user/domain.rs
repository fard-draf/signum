use std::fmt::Debug;

use argon2::PasswordHash;
use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::VerifyingKey;

use crate::error::{AppError, ErrArgon2, ErrPassword, ErrPath, ErrUser};

impl Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "user_name: {:?}, id: {:?}", self.name, self.pubkey)
    }
}
#[derive(BorshSerialize, BorshDeserialize)]
pub struct User {
    pub name: UserName,
    pub pubkey: UserPubKey,
    pub password: UserPassword,
    pub file_path: UserFilePath,
}

impl User {
    pub fn new(
        name: UserName,
        pubkey: UserPubKey,
        password: UserPassword,
        file_path: UserFilePath,
    ) -> Self {
        Self {
            name,
            pubkey,
            password,
            file_path,
        }
    }
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct UserName {
    pub name: String,
}

impl UserName {
    pub fn new(name: &str) -> Result<Self, AppError> {
        let cleaned_name = name.trim().to_lowercase();
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
}
#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct UserPubKey {
    pub vk: [u8; 32],
}

impl UserPubKey {
    pub fn from_key(vk: &VerifyingKey) -> Self {
        Self { vk: vk.to_bytes() }
    }
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct UserPassword {
    pub password: String,
}

impl UserPassword {
    pub fn new(input: &str) -> Result<Self, AppError> {
        let password = input.trim().to_string();
        if password.len() < 10 {
            return Err(AppError::Password(ErrPassword::PasswordTooShort));
        }

        if password.len() > 30 {
            return Err(AppError::Password(ErrPassword::PasswordTooLong));
        }

        let digit_count = password.chars().filter(|c| c.is_ascii_digit()).count();
        if digit_count < 4 {
            return Err(AppError::Password(ErrPassword::NotEnoughtDigits));
        }

        let special_char = password.chars().filter(|c| !c.is_alphanumeric()).count();
        if special_char < 1 {
            return Err(AppError::Password(ErrPassword::MissingSpecialCharacters));
        }

        if !password.chars().any(|c| c.is_lowercase())
            || !password.chars().any(|c| c.is_uppercase())
            || !password.chars().any(|c| c.is_numeric())
        {
            return Err(AppError::Password(ErrPassword::PasswordTooWeak));
        }

        Ok(Self { password })
    }

    pub fn parse_to_hash(&self) -> Result<PasswordHash<'_>, AppError> {
        PasswordHash::new(&self.password)
            .map_err(|e| AppError::Argon2(ErrArgon2::PasswordHashError(e)))
    }
}

#[derive(BorshSerialize, BorshDeserialize)]
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
