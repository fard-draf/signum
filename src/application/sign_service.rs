use std::path::Path;

use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::{
    domain::ports::fs::FileSystem,
    error::{AppError, ErrEncrypt, ErrIO, ErrPath},
    infra::file_system::FileSystemAdapter,
};

pub struct SignService {
    fs: FileSystemAdapter,
}

impl SignService {
    pub fn new(fs: FileSystemAdapter) -> Self {
        Self { fs }
    }

    pub fn sign_file(
        &self,
        signing_key: &SigningKey,
        file_path: &str,
        output_path: Option<&str>,
    ) -> Result<(), AppError> {
        if !Path::new(file_path).exists() {
            return Err(AppError::Path(ErrPath::FileNotFound));
        }
        let content = std::fs::read(file_path).map_err(|e| AppError::IO(ErrIO::IoError(e)))?;
        let signature = signing_key.sign(&content);
        let signature_b64 = general_purpose::STANDARD.encode(signature.to_bytes());
        let output = output_path
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("{}.sig", file_path));
        self.fs.write_file(&output, signature_b64.as_bytes())?;
        Ok(())
    }

    pub fn verify_signature(
        &self,
        file_path: &str,
        signature_path: &str,
        verifying_key: &VerifyingKey,
    ) -> Result<bool, AppError> {
        if !Path::new(file_path).exists() {
            return Err(AppError::Path(ErrPath::FileNotFound));
        }
        if !Path::new(signature_path).exists() {
            return Err(AppError::Path(ErrPath::FileNotFound));
        }
        let content = std::fs::read(file_path).map_err(|e| AppError::IO(ErrIO::IoError(e)))?;
        let signature_b64 =
            std::fs::read_to_string(signature_path).map_err(|e| AppError::IO(ErrIO::IoError(e)))?;
        let signature_bytes = general_purpose::STANDARD
            .decode(signature_b64.trim())
            .map_err(|_| AppError::Encrypt(ErrEncrypt::InvalidData))?;
        if signature_bytes.len() != 64 {
            return Err(AppError::Encrypt(ErrEncrypt::InvalidData));
        }
        let mut sig_raw = [0u8; 64];
        sig_raw.copy_from_slice(&signature_bytes);
        let signature = Signature::from_bytes(&sig_raw);
        match verifying_key.verify(&content, &signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}
