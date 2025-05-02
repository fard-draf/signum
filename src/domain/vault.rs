use chrono::{DateTime, Local};
use sodiumoxide::crypto::sign::ed25519;

pub struct PrivateKey(ed25519::SecretKey);

impl PrivateKey {
    pub fn generate() -> (Self, PublicKey) {
        let (pk, sk) = ed25519::gen_keypair();
        (Self(sk), PublicKey(pk))
    }

    pub fn sign(&self, data: &[u8]) -> ed25519::Signature {
        ed25519::sign_detached(data, &self.0)
    }
}
pub struct PublicKey(ed25519::PublicKey);

impl PublicKey {
    pub fn verify(&self, data: &[u8], sig: &ed25519::Signature) -> bool {
        ed25519::verify_detached(sig, data, &self.0)
    }
}

pub struct DateMadeVault {
    date: DateTime<Local>,
}
pub struct Vault {
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
    pub crated_at: DateMadeVault,
}
