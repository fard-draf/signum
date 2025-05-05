use borsh::{BorshDeserialize, BorshSerialize};
use std::path::PathBuf;

use crate::{
    domain::{ports::config::AppConfig, user::entities::UserName},
    error::{AppError, ErrPath},
};
#[derive(PartialEq, Eq, PartialOrd, Ord, BorshSerialize, BorshDeserialize)]
pub struct UserFilePath {
    pub path: String,
}

impl UserFilePath {
    pub fn new(path: String) -> Result<Self, AppError> {
        const FORBIDDEN: &[char] = &[
            '\0', '|', ';', '>', '<', '/', '\\', ':', '*', '?', '"', '\'',
        ];
        let path = path.trim().to_string();
        if path.is_empty() {
            return Err(AppError::Path(ErrPath::EmptyFilename));
        }
        if path.chars().any(|c| c.is_whitespace()) || path.chars().any(|c| FORBIDDEN.contains(&c)) {
            return Err(AppError::Path(ErrPath::ForbiddenCharacters));
        }

        Ok(UserFilePath { path })
    }

    pub fn from_config(config: &AppConfig, user_name: &UserName) -> Result<Self, AppError> {
        let path = config
            .get_user_data_path(user_name)
            .to_string_lossy()
            .into_owned();

        Ok(UserFilePath { path })
    }

    pub fn validate(&self, config: &AppConfig) -> Result<(), AppError> {
        let path = PathBuf::from(&self.path);

        // if let Some(parent) = path.parent() {
        //     if !parent.exists() {
        //         fs::
        //     }
        // }
        Ok(())
    }
}
