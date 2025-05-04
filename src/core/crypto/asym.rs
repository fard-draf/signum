use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

pub fn sign_data(data: &[u8], key: &SigningKey) -> Signature {
    key.sign(data)
}

pub fn verify_signature(data: &[u8], sig: &Signature, pubkey: &VerifyingKey) -> bool {
    pubkey.verify(data, sig).is_ok()
}
