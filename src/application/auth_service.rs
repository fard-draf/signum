use crate::{
    core::crypto::sym::derive_key_from_password,
    domain::{
        ports::{config::AppConfig, fs::FileSystem, repository::UserRepository},
        user::{
            entities::{User, UserMetadata, UserName},
            file_path::UserFilePath,
            passwords::UserPassword,
        },
    },
    error::{AppError, ErrEncrypt, ErrUser},
};

use argon2::password_hash::SaltString;
use rand_core::OsRng;
use zeroize::Zeroize;

pub struct AuthService<R: UserRepository, F: FileSystem> {
    repository: R,
    fs: F,
    config: AppConfig,
}

impl<R: UserRepository, F: FileSystem> AuthService<R, F> {
    pub fn new(repository: R, fs: F, config: AppConfig) -> Self {
        Self {
            repository,
            fs,
            config,
        }
    }

    pub fn register(
        &self,
        username: &str,
        raw_pw: &mut str,
        path: &mut str,
    ) -> Result<User, AppError> {
        let name = UserName::new(username)?;

        if self.repository.exists(&name)? {
            return Err(AppError::User(ErrUser::AlreadyExist));
        }

        let password = UserPassword::from_raw(raw_pw)?;
        let salt = SaltString::generate(&mut OsRng);
        let file_path = UserFilePath::new(path.to_string())?;

        let user = User::new(name, salt.to_string(), password, file_path);

        let mut key = derive_key_from_password(raw_pw, &user)?;
        self.repository.save(&user, &key)?;

        key.zeroize();
        raw_pw.zeroize();
        path.zeroize();

        Ok(user)
    }

    pub fn login(&self, raw_username: &str, raw_password: &str) -> Result<User, AppError> {
        let name = UserName::new(raw_username)?;

        if !self.repository.exists(&name)? {
            return Err(AppError::User(ErrUser::UserNotFound));
        }

        let base_path = format!(
            "{}.meta",
            self.config.get_user_data_path(&name).to_string_lossy()
        );
        let metadata_bytes = self.fs.read_file(&base_path)?;
        let metadata: UserMetadata = borsh::BorshDeserialize::try_from_slice(&metadata_bytes)
            .map_err(|_| AppError::Encrypt(ErrEncrypt::BorshError))?;

        let dummy_password = UserPassword::from_raw("dummy")?; // Juste pour la structure
        let dummy_file_path = UserFilePath::new("dummy".to_string())?;

        let temp_user = User {
            name: metadata.name.clone(),
            cypher_salt: metadata.user_salt,
            password: dummy_password,
            file_path: dummy_file_path,
        };

        let key = derive_key_from_password(raw_password, &temp_user)?;

        let user = self.repository.load(&name, &key)?;

        Ok(user)
    }
}
