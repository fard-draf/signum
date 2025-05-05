use crate::{
    core::crypto::sym::{decrypt_data, encrypt_data},
    domain::{
        ports::{config::AppConfig, fs::FileSystem, repository::UserRepository},
        user::{
            entities::{User, UserMetadata, UserName, UserSecureData},
            file_path::UserFilePath,
        },
    },
    error::{AppError, ErrCypher, ErrUser},
};

use borsh;
use zeroize::{self, Zeroize};

pub struct UserFileRepository<F: FileSystem> {
    fs: F,
    config: AppConfig,
}

impl<F: FileSystem> UserFileRepository<F> {
    pub fn new(fs: F, config: AppConfig) -> Self {
        Self { fs, config }
    }
}

impl<F: FileSystem> UserRepository for UserFileRepository<F> {
    fn save(&self, user: &User, key: &[u8; 32]) -> Result<(), AppError> {
        user.file_path.validate(&self.config, &self.fs)?;

        let metadata_path = format!("{}.meta", user.file_path.path);
        let secure_path = user.file_path.path.clone();

        let metadata = user.get_metadata();
        let metadata_bytes =
            borsh::to_vec(&metadata).map_err(|_| AppError::Cypher(ErrCypher::BorshError))?;
        self.fs.write_file(&metadata_path, &metadata_bytes)?;

        let secure_data = user.get_secure_data();
        let secure_bytes =
            borsh::to_vec(&secure_data).map_err(|_| AppError::Cypher(ErrCypher::BorshError))?;
        let encrypted = encrypt_data(&secure_bytes, key)?;
        self.fs.write_file(&secure_path, &encrypted)?;

        Ok(())
    }

    fn load(&self, username: &UserName, key: &[u8; 32]) -> Result<User, AppError> {
        let base_path = self
            .config
            .get_user_data_path(username)
            .to_string_lossy()
            .into_owned();
        let metadata_path = format!("{}.meta", base_path);
        let secure_path = base_path;

        if !self.fs.file_exists(&metadata_path) {
            return Err(AppError::User(ErrUser::UserNotFound));
        }

        let metadata_bytes = self.fs.read_file(&metadata_path)?;
        let metadata: UserMetadata = borsh::BorshDeserialize::try_from_slice(&metadata_bytes)
            .map_err(|_| AppError::Cypher(ErrCypher::BorshError))?;

        if !self.fs.file_exists(&secure_path) {
            return Err(AppError::Cypher(ErrCypher::InvalidData));
        }

        let mut encrypted = self.fs.read_file(&secure_path)?;
        let mut decrypted = decrypt_data(&encrypted, key)?;

        let secure_data: UserSecureData = borsh::BorshDeserialize::try_from_slice(&decrypted)
            .map_err(|_| AppError::Cypher(ErrCypher::DecryptionFailed))?;

        encrypted.zeroize();
        decrypted.zeroize();

        let file_path = UserFilePath::new(secure_path)?;

        Ok(User {
            name: metadata.name,
            cypher_salt: metadata.cypher_salt,
            password: secure_data.password,
            file_path,
        })
    }

    fn exists(&self, username: &UserName) -> Result<bool, AppError> {
        let base_path = self
            .config
            .get_user_data_path(username)
            .to_string_lossy()
            .into_owned();
        let metadata_path = format!("{}.meta", base_path);

        Ok(self.fs.file_exists(&metadata_path))
    }
}
