use tracing::{error, info};

use crate::{
    core::{
        crypto::sym::{decrypt_data, derive_key_from_password, encrypt_data},
        keys::keypair::generate_keypair,
    },
    domain::{
        ports::{config::AppConfig, fs::FileSystem},
        user::entities::User,
    },
    error::{AppError, ErrBase64, ErrDalek, ErrEncrypt},
};

use base64::{Engine as _, engine::general_purpose};
use ed25519_dalek::{SigningKey, VerifyingKey};
use zeroize::Zeroize;

pub struct KeyService<F: FileSystem> {
    fs: F,
    config: AppConfig,
}

impl<F: FileSystem> KeyService<F> {
    pub fn new(fs: F, config: AppConfig) -> Self {
        Self { fs, config }
    }

    pub fn generate_user_keys(&self, user: &User, password: &mut str) -> Result<(), AppError> {
        let (signing_key, verifying_key) = generate_keypair();
        self.save_signing_key(user, password, &signing_key)?;
        // password.zeroize();
        self.save_verifying_key(user, &verifying_key)?;

        Ok(())
    }

    pub fn save_signing_key(
        &self,
        user: &User,
        raw_pw: &mut str,
        key: &SigningKey,
    ) -> Result<(), AppError> {
        info!("SK_SAVE: password: {}", raw_pw);

        let base_dir = self.get_keys_directory(user)?;
        let base_path = std::path::Path::new(&base_dir);
        let sk_path = base_path.join("signing_key.sk.enc");
        let sk_path_str = sk_path.to_string_lossy();

        info!("SK_SAVE: raw_pw: {}", raw_pw);
        info!("SK_SAVE: salt raw: {:?}", user.get_salt());

        let mut encryption_key = derive_key_from_password(raw_pw, user)?;
        raw_pw.zeroize();
        let mut key_bytes = key.to_bytes();
        let encrypted = encrypt_data(&key_bytes, &encryption_key)?;

        info!("SK_SAVE: salt raw: {}", user.user_salt);
        info!("SK_SAVE: salt from get_salt: {:?}", user.get_salt()?);
        info!("SK_SAVE: encryption key: {:?}", encryption_key);

        self.fs.write_file(&sk_path_str, &encrypted)?;

        key_bytes.zeroize();
        encryption_key.zeroize();

        Ok(())
    }

    pub fn save_verifying_key(&self, user: &User, key: &VerifyingKey) -> Result<(), AppError> {
        let base_dir = self.get_keys_directory(user)?;
        let base_path = std::path::Path::new(&base_dir);
        let vk_path = base_path.join("verifying_key.vk");
        let vk_path_str = vk_path.to_string_lossy();

        let encoded = general_purpose::STANDARD.encode(key.to_bytes());
        self.fs.write_file(&vk_path_str, encoded.as_bytes())?;

        Ok(())
    }

    pub fn load_signing_key(&self, user: &User, raw_pw: &mut str) -> Result<SigningKey, AppError> {
        let base_dir = self.get_keys_directory(user)?;
        let base_path = std::path::Path::new(&base_dir);
        let sk_path = base_path.join("signing_key.sk.enc");
        let sk_path_str = sk_path.to_string_lossy();

        if !self.fs.file_exists(&sk_path_str) {
            return Err(AppError::Dalek(ErrDalek::KeyNotFound));
        }
        info!("SK_LOAD: raw_pw: {}", raw_pw);
        info!("SK_LOAD: salt raw: {:?}", user.get_salt());

        let mut encryption_key = derive_key_from_password(raw_pw, user)?;
        raw_pw.zeroize();
        info!("SK_LOAD: salt raw: {}", user.user_salt);
        info!("SK_LOAD: salt from get_salt: {:?}", user.get_salt()?);
        info!("SK_LOAD: encryption key: {:?}", encryption_key);

        let encrypted = self.fs.read_file(&sk_path_str)?;
        info!("SK_LOAD: encrypted value {:?}", &encrypted);

        let mut decrypted = decrypt_data(&encrypted, &encryption_key)?;
        info!("SK_LOAD: decrypted data length: {}", decrypted.len());

        if decrypted.len() == 32 {
            let mut raw = [0u8; 32];
            raw.copy_from_slice(&decrypted[0..32]);

            let key = SigningKey::from_bytes(&raw);

            decrypted.zeroize();
            encryption_key.zeroize();
            raw.zeroize();

            Ok(key)
        } else {
            log::error!(
                "SK_LOAD: Incorret decrypted key lenght: expect 32, got {}",
                decrypted.len()
            );

            decrypted.zeroize();
            encryption_key.zeroize();

            Err(AppError::Encrypt(ErrEncrypt::InvalidKey))
        }
    }

    pub fn load_verifying_key(&self, user: &User) -> Result<VerifyingKey, AppError> {
        let base_dir = self.get_keys_directory(user)?;
        let base_path = std::path::Path::new(&base_dir);
        let vk_path = base_path.join("verifying_key.vk");
        let vk_path_str = vk_path.to_string_lossy();

        if !self.fs.file_exists(&vk_path_str) {
            return Err(AppError::Dalek(ErrDalek::KeyNotFound));
        }

        info!("VK_LOAD: verifying key file exists");

        let file_content = self.fs.read_file(&vk_path_str)?;
        let encoded = match String::from_utf8(file_content) {
            Ok(s) => s.trim().to_string(),
            Err(_) => return Err(AppError::Encrypt(ErrEncrypt::InvalidData)),
        };

        info!("VK_LOAD: base64 encoded key read: {} bytes", encoded.len());

        let bytes = match general_purpose::STANDARD.decode(encoded) {
            Ok(b) => b,
            Err(e) => {
                error!("VK_LOAD: base64 decode error: {:?}", e);
                return Err(AppError::Base64(ErrBase64::DecodeError(e)));
            }
        };

        info!("VK_LOAD: decodes key bytes: {} bytes", bytes.len());

        if bytes.len() != 32 {
            error!(
                "VK_LOAD: invalid key length: expected 32, got {}",
                bytes.len()
            );
            return Err(AppError::Encrypt(ErrEncrypt::InvalidKey));
        }

        let mut raw = [0u8; 32];
        raw.copy_from_slice(&bytes);

        match VerifyingKey::from_bytes(&raw) {
            Ok(vk) => Ok(vk),
            Err(e) => {
                error!("VK_LOAD: invalid verifying key: {:?}", e);
                Err(AppError::Dalek(ErrDalek::InvalidKey))
            }
        }
    }

    pub fn has_keys(&self, user: &User) -> Result<bool, AppError> {
        let base_dir = self.get_keys_directory(user)?;
        let base_path = std::path::Path::new(&base_dir);
        let sk_path = base_path.join("signing_key.sk.enc");
        let vk_path = base_path.join("verifying_key.vk");

        Ok(self.fs.file_exists(&sk_path.to_string_lossy())
            && self.fs.file_exists(&vk_path.to_string_lossy()))
    }

    fn get_keys_directory(&self, user: &User) -> Result<String, AppError> {
        let user_dir = self
            .config
            .base_directory
            .join("users")
            .join(user.name.name.as_str())
            .join("keys");

        let user_dir_str = user_dir.to_string_lossy().into_owned();

        if !self.fs.file_exists(&user_dir_str) {
            self.fs.create_directory(&user_dir_str)?;
        }

        Ok(user_dir_str)
    }
}
