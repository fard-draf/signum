use ed25519_dalek::{Signature, Signer, SigningKey};

pub fn sign_data(signing_key: &SigningKey, message: &[u8]) -> Signature {
    signing_key.sign(message)
}
