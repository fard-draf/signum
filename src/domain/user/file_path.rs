use borsh::{BorshDeserialize, BorshSerialize};
use log::info;
use std::path::Path;
use zeroize::Zeroize;

use crate::{
    domain::{
        ports::{config::AppConfig, fs::FileSystem},
        user::entities::UserName,
    },
    error::{AppError, ErrPath},
};
#[derive(PartialEq, Eq, PartialOrd, Ord, BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct UserFilePath {
    pub path: String,
}

impl Zeroize for UserFilePath {
    fn zeroize(&mut self) {
        self.path.zeroize();
    }
}

impl UserFilePath {
    pub fn from_filename(file_name: String) -> Result<Self, AppError> {
        const FORBIDDEN: &[char] = &[
            '\0', '|', ';', '>', '<', '\\', ':', '/', '*', '?', '"', '\'',
        ];
        let file_name = file_name.trim().to_string();
        if file_name.is_empty() {
            return Err(AppError::Path(ErrPath::EmptyFilename));
        }
        if file_name.chars().any(|c| c.is_whitespace())
            || file_name.chars().any(|c| FORBIDDEN.contains(&c))
        {
            return Err(AppError::Path(ErrPath::ForbiddenCharacters));
        }

        Ok(UserFilePath { path: file_name })
    }

    pub fn from_path(path: String) -> Result<Self, AppError> {
        const FORBIDDEN: &[char] = &['\0', '|', ';', '>', '<', '\\', ':', '*', '?', '"'];
        let path = path.trim().to_string();
        if path.is_empty() {
            return Err(AppError::Path(ErrPath::EmptyPath));
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

    pub fn validate<F: FileSystem>(&self, config: &AppConfig, fs: &F) -> Result<(), AppError> {
        let base_dir = config.base_directory.to_string_lossy().into_owned();
        info!("VALIDATE: base_dir: {}", base_dir);
        if fs.file_exists(&self.path) {
            match fs.canonicalize_path(&self.path) {
                Ok(canonical_path) => {
                    if !fs.is_path_in_directory(&canonical_path, &base_dir)? {
                        info!("VALIDATE: canonical path: {}", canonical_path);
                        return Err(AppError::Path(ErrPath::PathTraversal));
                    }
                }
                Err(_) => return Err(AppError::Path(ErrPath::InvalidPath)),
            }
        } else if let Some(parent) = Path::new(&self.path).parent() {
            let parent_str = parent.to_string_lossy().into_owned();
            if fs.file_exists(&parent_str) {
                match fs.canonicalize_path(&parent_str) {
                    Ok(canonical_parent) => {
                        if !fs.is_path_in_directory(&canonical_parent, &base_dir)? {
                            return Err(AppError::Path(ErrPath::PathTraversal));
                        }
                    }
                    Err(_) => return Err(AppError::Path(ErrPath::InvalidPath)),
                }
            } else {
                fs.create_directory(&parent_str)?;
            }
        }

        Ok(())
    }
}
