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
use ed25519_dalek::SigningKey;
use log::info;
use rand_core::OsRng;
use zeroize::Zeroize;

use super::key_service::{self, KeyService};

pub struct AuthService<R: UserRepository, F: FileSystem> {
    repository: R,
    fs: F,
    config: AppConfig,
    key_service: KeyService<F>,
}

impl<R: UserRepository, F: FileSystem> AuthService<R, F> {
    pub fn new(repository: R, fs: F, config: AppConfig, key_service: KeyService<F>) -> Self {
        Self {
            repository,
            fs,
            config,
            key_service,
        }
    }

    pub fn register(
        &self,
        username: &str,
        raw_pw: &mut str,
        path: &mut str,
    ) -> Result<(User, SigningKey), AppError> {
        let name = UserName::new(username)?;

        if self.repository.exists(&name)? {
            return Err(AppError::User(ErrUser::AlreadyExist));
        }
        info!("REG: repository exist");
        let password = UserPassword::from_raw(raw_pw)?;
        let salt = SaltString::generate(&mut OsRng);
        let file_path = UserFilePath::from_filename(path.to_string())?;

        info!("REG: password: {:?}", password);
        info!("REG: raw password: {:?}", raw_pw);
        info!("REG: file path: {:?}", file_path);
        info!("REG: salt: {}", salt);
        let user = User::new(name, salt.to_string(), password, file_path);
        info!("REG: user created {:?}", user);
        // saving user
        let mut key = derive_key_from_password(raw_pw, &user)?;
        self.repository.save(&user, &key)?;
        info!("REG: key derived {:?}", key);

        let mut generate_pw = String::new();
        raw_pw.clone_into(&mut generate_pw);
        generate_pw.zeroize();
        // generate and save first encrypted keys - sk & vk
        self.key_service
            .generate_user_keys(&user, &mut generate_pw)?;

        let mut signing_pw = String::new();
        raw_pw.clone_into(&mut signing_pw);
        signing_pw.zeroize();

        // load the private key to return it
        let signing_key = self.key_service.load_signing_key(&user, &mut signing_pw)?;

        key.zeroize();
        raw_pw.zeroize();
        path.zeroize();

        Ok((user, signing_key))
    }

    pub fn login(
        &self,
        raw_username: &str,
        raw_pw: &mut str,
    ) -> Result<(User, SigningKey), AppError> {
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

        let dummy_password = UserPassword::from_raw("@kenath0n1818")?;
        let dummy_file_path = UserFilePath::from_filename("/isnt/real".to_string())?;

        let temp_user = User {
            name: metadata.name.clone(),
            user_salt: metadata.user_salt,
            password: dummy_password,
            file_path: dummy_file_path,
        };

        let key = derive_key_from_password(raw_pw, &temp_user)?;

        // load the complete user
        let user = self.repository.load(&name, &key)?;

        // load private key (sk)
        let signing_key = self.key_service.load_signing_key(&user, raw_pw)?;

        // verify if user gets keys, if not, generate it
        if !self.key_service.has_keys(&user)? {
            self.key_service.generate_user_keys(&user, raw_pw)?;
            // reload the vk
            let signing_key = self.key_service.load_signing_key(&user, raw_pw)?;
            return Ok((user, signing_key));
        }
        raw_pw.zeroize();

        Ok((user, signing_key))
    }
}
