use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;

pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifing_key = signing_key.verifying_key();
    (signing_key, verifing_key)
}
