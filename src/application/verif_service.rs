use ed25519_dalek::VerifyingKey;

use crate::{application::sign_service::SignService, error::AppError};

pub struct VerifService {
    signer: SignService,
}

impl VerifService {
    pub fn new(signer: SignService) -> Self {
        Self { signer }
    }

    pub fn verify_file(
        &self,
        file_path: &str,
        signature_path: &str,
        verifying_key: &VerifyingKey,
    ) -> Result<bool, AppError> {
        self.signer
            .verify_signature(file_path, signature_path, verifying_key)
    }
}
