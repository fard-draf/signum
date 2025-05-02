use crate::error::AppError;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

pub fn verify_signature(
    verifying_key: &VerifyingKey,
    message: &[u8],
    signature: &Signature,
) -> Result<(), AppError> {
    verifying_key
        .verify(message, signature)
        .map_err(AppError::from)
}
