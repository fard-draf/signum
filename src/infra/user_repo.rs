use crate::{
    core::crypto::sym::{decrypt_data, encrypt_data},
    domain::{
        ports::{config::AppConfig, fs::FileSystem, repository::UserRepository},
        user::{
            entities::{User, UserMetadata, UserName, UserSecureData},
            file_path::UserFilePath,
        },
    },
    error::{AppError, ErrEncrypt, ErrUser},
};

use borsh;
use log::info;
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
        info!("USR_RPO_SAVE: entrence");
        user.file_path.validate(&self.config, &self.fs)?;
        info!("USR_RPO_SAVE: saving file: {:?}", user.file_path);
        {
            let mut metadata_path = format!("{}.meta", user.file_path.path);
            let mut metadata = user.get_metadata();
            let mut metadata_bytes =
                borsh::to_vec(&metadata).map_err(|_| AppError::Encrypt(ErrEncrypt::BorshError))?;
            metadata.zeroize();
            self.fs.write_file(&metadata_path, &metadata_bytes)?;
            metadata_bytes.zeroize();
            metadata_path.zeroize();
        }

        {
            let mut secure_path = user.file_path.path.clone();
            let mut secure_data = user.get_secure_data();
            let mut secure_bytes = borsh::to_vec(&secure_data)
                .map_err(|_| AppError::Encrypt(ErrEncrypt::BorshError))?;
            let encrypted = encrypt_data(&secure_bytes, key)?;
            self.fs.write_file(&secure_path, &encrypted)?;
            secure_path.zeroize();
            secure_data.zeroize();
            secure_bytes.zeroize();
        }

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

        let mut metadata_bytes = self.fs.read_file(&metadata_path)?;
        let metadata: UserMetadata = borsh::BorshDeserialize::try_from_slice(&metadata_bytes)
            .map_err(|_| AppError::Encrypt(ErrEncrypt::BorshError))?;
        metadata_bytes.zeroize();

        if !self.fs.file_exists(&secure_path) {
            return Err(AppError::Encrypt(ErrEncrypt::InvalidData));
        }

        let mut encrypted = self.fs.read_file(&secure_path)?;
        let mut decrypted = decrypt_data(&encrypted, key)?;
        encrypted.zeroize();

        let mut secure_data: UserSecureData =
            borsh::BorshDeserialize::try_from_slice(&decrypted)
                .map_err(|_| AppError::Encrypt(ErrEncrypt::DecryptionFailed))?;
        decrypted.zeroize();

        let file_path = UserFilePath::from_filename(secure_path)?;

        let user = User {
            name: metadata.name,
            user_salt: metadata.user_salt,
            password: secure_data.password,
            file_path,
        };
        secure_data.file_path.zeroize();

        Ok(user)
    }

    fn exists(&self, username: &UserName) -> Result<bool, AppError> {
        let mut base_path = self
            .config
            .get_user_data_path(username)
            .to_string_lossy()
            .into_owned();
        let metadata_path = format!("{}.meta", base_path);
        base_path.zeroize();

        Ok(self.fs.file_exists(&metadata_path))
    }
}
