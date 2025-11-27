use crate::{
    core::crypto::sym::{authenticate_aad, decrypt_data, encrypt_data, verify_aad},
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

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
pub(crate) struct StoredMetadata {
    pub metadata: UserMetadata,
    pub auth_tag: Vec<u8>,
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
            let metadata_path = format!("{}.meta", user.file_path.path);
            let metadata = user.get_metadata();
            let metadata_bytes =
                borsh::to_vec(&metadata).map_err(|_| AppError::Encrypt(ErrEncrypt::BorshError))?;
            let auth_tag = authenticate_aad(key, &metadata_bytes)?;
            let stored = StoredMetadata { metadata, auth_tag };
            let stored_bytes =
                borsh::to_vec(&stored).map_err(|_| AppError::Encrypt(ErrEncrypt::BorshError))?;
            self.fs.write_file(&metadata_path, &stored_bytes)?;
        }

        {
            let secure_path = user.file_path.path.clone();
            let mut secure_data = user.get_secure_data();
            let mut secure_bytes = borsh::to_vec(&secure_data)
                .map_err(|_| AppError::Encrypt(ErrEncrypt::BorshError))?;
            let encrypted = encrypt_data(&secure_bytes, key)?;
            self.fs.write_file(&secure_path, &encrypted)?;
            secure_bytes.zeroize();
            secure_data.zeroize();
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

        info!("USR_RPO_LOAD: secure_path: {}", secure_path);
        if !self.fs.file_exists(&metadata_path) {
            return Err(AppError::User(ErrUser::UserNotFound));
        }

        let mut stored_bytes = self.fs.read_file(&metadata_path)?;
        let mut stored: StoredMetadata = borsh::BorshDeserialize::try_from_slice(&stored_bytes)
            .map_err(|_| AppError::Encrypt(ErrEncrypt::BorshError))?;
        stored_bytes.zeroize();
        let metadata = stored.metadata;

        if !self.fs.file_exists(&secure_path) {
            return Err(AppError::Encrypt(ErrEncrypt::InvalidData));
        }
        let mut encrypted = self.fs.read_file(&secure_path)?;
        let mut decrypted = decrypt_data(&encrypted, key)?;
        encrypted.zeroize();

        let mut metadata_bytes =
            borsh::to_vec(&metadata).map_err(|_| AppError::Encrypt(ErrEncrypt::BorshError))?;
        verify_aad(key, &metadata_bytes, &stored.auth_tag)?;
        metadata_bytes.zeroize();
        stored.auth_tag.zeroize();

        let secure_data: UserSecureData = borsh::BorshDeserialize::try_from_slice(&decrypted)
            .map_err(|_| AppError::Encrypt(ErrEncrypt::DecryptionFailed))?;
        decrypted.zeroize();

        let file_path = UserFilePath::from_path(secure_path)?;
        info!("USR_RPO_LOAD: file_path: {:?}", file_path);
        let user = User {
            name: metadata.name,
            user_salt: metadata.user_salt,
            password: secure_data.password,
            file_path,
        };
        Ok(user)
    }

    fn exists(&self, username: &UserName) -> Result<bool, AppError> {
        let mut base_path = self
            .config
            .get_user_data_path(username)
            .to_string_lossy()
            .into_owned();
        info!("USR_RPO_EXIST: base_path: {}", base_path);
        let metadata_path = format!("{}.meta", base_path);
        info!("USR_RPO_EXIST: metadata_path: {}", metadata_path);
        base_path.zeroize();

        Ok(self.fs.file_exists(&metadata_path))
    }
}
