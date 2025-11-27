use tracing::error;

use crate::{
    core::{
        crypto::sym::{
            authenticate_aad, decrypt_data, derive_key_from_password, encrypt_data, verify_aad,
        },
        keys::keypair::generate_keypair,
    },
    domain::{
        ports::{config::AppConfig, fs::FileSystem},
        user::entities::User,
    },
    error::{AppError, ErrBase64, ErrDalek, ErrEncrypt},
};

use base64::{Engine as _, engine::general_purpose};
use borsh;
use ed25519_dalek::{SigningKey, VerifyingKey};
use zeroize::Zeroize;

pub struct KeyService<F: FileSystem> {
    fs: F,
    config: AppConfig,
}

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
struct StoredVerifyingKey {
    encoded: String,
    auth_tag: Vec<u8>,
}

impl<F: FileSystem> KeyService<F> {
    pub fn new(fs: F, config: AppConfig) -> Self {
        Self { fs, config }
    }

    pub fn generate_user_keys(&self, user: &User, password: &mut str) -> Result<(), AppError> {
        let (signing_key, verifying_key) = generate_keypair();
        self.save_signing_key(user, password, &signing_key)?;
        // password.zeroize();
        self.save_verifying_key(user, password, &verifying_key)?;

        Ok(())
    }

    pub fn save_signing_key(
        &self,
        user: &User,
        raw_pw: &mut str,
        key: &SigningKey,
    ) -> Result<(), AppError> {
        let base_dir = self.get_keys_directory(user)?;
        let base_path = std::path::Path::new(&base_dir);
        let sk_path = base_path.join("signing_key.sk.enc");
        let sk_path_str = sk_path.to_string_lossy();

        let mut encryption_key = derive_key_from_password(raw_pw, user)?;
        raw_pw.zeroize();
        let mut key_bytes = key.to_bytes();
        let encrypted = encrypt_data(&key_bytes, &encryption_key)?;

        self.fs.write_file(&sk_path_str, &encrypted)?;

        key_bytes.zeroize();
        encryption_key.zeroize();

        Ok(())
    }

    pub fn save_verifying_key(
        &self,
        user: &User,
        raw_pw: &mut str,
        key: &VerifyingKey,
    ) -> Result<(), AppError> {
        let base_dir = self.get_keys_directory(user)?;
        let base_path = std::path::Path::new(&base_dir);
        let vk_path = base_path.join("verifying_key.vk");
        let vk_path_str = vk_path.to_string_lossy();

        let encoded = general_purpose::STANDARD.encode(key.to_bytes());
        let mut encryption_key = derive_key_from_password(raw_pw, user)?;
        raw_pw.zeroize();
        let auth_tag = authenticate_aad(&encryption_key, encoded.as_bytes())?;
        let stored = StoredVerifyingKey { encoded, auth_tag };
        let payload =
            borsh::to_vec(&stored).map_err(|_| AppError::Encrypt(ErrEncrypt::BorshError))?;
        self.fs.write_file(&vk_path_str, &payload)?;
        encryption_key.zeroize();

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

        let mut encryption_key = derive_key_from_password(raw_pw, user)?;
        raw_pw.zeroize();

        let encrypted = self.fs.read_file(&sk_path_str)?;

        let mut decrypted = decrypt_data(&encrypted, &encryption_key)?;

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

    pub fn load_verifying_key(
        &self,
        user: &User,
        raw_pw: &mut str,
    ) -> Result<VerifyingKey, AppError> {
        let base_dir = self.get_keys_directory(user)?;
        let base_path = std::path::Path::new(&base_dir);
        let vk_path = base_path.join("verifying_key.vk");
        let vk_path_str = vk_path.to_string_lossy();

        if !self.fs.file_exists(&vk_path_str) {
            return Err(AppError::Dalek(ErrDalek::KeyNotFound));
        }

        let mut encryption_key = derive_key_from_password(raw_pw, user)?;
        raw_pw.zeroize();

        let file_content = self.fs.read_file(&vk_path_str)?;
        let stored: StoredVerifyingKey = borsh::BorshDeserialize::try_from_slice(&file_content)
            .map_err(|_| AppError::Encrypt(ErrEncrypt::InvalidData))?;

        verify_aad(&encryption_key, stored.encoded.as_bytes(), &stored.auth_tag)?;

        let bytes = match general_purpose::STANDARD.decode(stored.encoded.trim()) {
            Ok(b) => b,
            Err(e) => {
                error!("VK_LOAD: base64 decode error: {:?}", e);
                encryption_key.zeroize();
                return Err(AppError::Base64(ErrBase64::DecodeError(e)));
            }
        };

        encryption_key.zeroize();

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
