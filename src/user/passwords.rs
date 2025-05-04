use rand::RngCore;
use rand_core::OsRng;

fn generate_random_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    OsRng.try_fill_bytes(&mut salt);
    salt
}
