use crate::{
    core::crypto::sym::derive_key_from_password,
    domain::{
        ports::{config::AppConfig, fs::FileSystem, repository::UserRepository},
        user::{
            entities::{User, UserName},
            file_path::UserFilePath,
            passwords::UserPassword,
        },
    },
    error::{AppError, ErrEncrypt, ErrUser},
};

use argon2::password_hash::SaltString;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use zeroize::Zeroize;

use super::key_service::KeyService;
use crate::infra::user_repo::StoredMetadata;

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
        _raw_path: &mut str,
    ) -> Result<(User, SigningKey), AppError> {
        let name = UserName::new(username)?;

        if self.repository.exists(&name)? {
            return Err(AppError::User(ErrUser::AlreadyExist));
        }
        let password = UserPassword::from_raw(raw_pw)?;
        let salt = SaltString::generate(&mut OsRng);
        let biding = self
            .config
            .base_directory
            .join("users")
            .join(&name.name)
            .join(format!("{}.sgm", name));
        let path = biding.to_string_lossy();

        let file_path = UserFilePath::from_path(path.to_string())?;

        let user = User::new(name, salt.to_string(), password, file_path);

        let mut temp_pw_0 = String::new();
        raw_pw.clone_into(&mut temp_pw_0);
        let mut key = derive_key_from_password(&mut temp_pw_0, &user)?;
        temp_pw_0.zeroize();
        self.repository.save(&user, &key)?;

        let mut temp_pw_1 = String::new();
        raw_pw.clone_into(&mut temp_pw_1);
        // generate and save first encrypted keys - sk & vk
        self.key_service.generate_user_keys(&user, &mut temp_pw_1)?;
        temp_pw_1.zeroize();

        let mut temp_pw_2 = String::new();
        raw_pw.clone_into(&mut temp_pw_2);
        // load the private key to return it
        let signing_key = self.key_service.load_signing_key(&user, &mut temp_pw_2)?;
        temp_pw_2.zeroize();

        key.zeroize();

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
        let mut metadata_bytes = self.fs.read_file(&base_path)?;
        let stored: StoredMetadata =
            borsh::BorshDeserialize::try_from_slice(&metadata_bytes)
                .map_err(|_| AppError::Encrypt(ErrEncrypt::BorshError))?;
        metadata_bytes.zeroize();
        let metadata = stored.metadata;
        let dummy_password = UserPassword::from_raw("Str0ng@P4ssw0rd12345")?;
        let dummy_file_path = UserFilePath::from_path("/isnt/real".to_string())?;

        let temp_user = User {
            name: metadata.name.clone(),
            user_salt: metadata.user_salt,
            password: dummy_password,
            file_path: dummy_file_path,
        };

        let mut temp_pw_0 = String::new();
        raw_pw.clone_into(&mut temp_pw_0);
        let mut key = derive_key_from_password(&mut temp_pw_0, &temp_user)?;
        temp_pw_0.zeroize();

        // load the complete user
        let user = self.repository.load(&name, &key)?;

        // load private key (sk)
        let mut temp_pw_for_sk = raw_pw.to_string();
        let signing_key = self
            .key_service
            .load_signing_key(&user, temp_pw_for_sk.as_mut_str())?;
        temp_pw_for_sk.zeroize();

        // verify if user gets keys, if not, generate it
        if !self.key_service.has_keys(&user)? {
            let mut temp_pw_gen = raw_pw.to_string();
            self.key_service
                .generate_user_keys(&user, temp_pw_gen.as_mut_str())?;
            temp_pw_gen.zeroize();
            // reload the vk
            let mut temp_pw_reload = raw_pw.to_string();
            let signing_key = self
                .key_service
                .load_signing_key(&user, temp_pw_reload.as_mut_str())?;
            temp_pw_reload.zeroize();
            return Ok((user, signing_key));
        }
        key.zeroize();

        Ok((user, signing_key))
    }

    pub fn load_verifying_key(&self, user: &User, raw_pw: &mut str) -> Result<VerifyingKey, AppError> {
        self.key_service.load_verifying_key(user, raw_pw)
    }
}
