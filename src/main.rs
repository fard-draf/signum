use signum::{
    crypto::{
        keys_ed25519::generate_keypair,
        keysfiles::{load_signing_key_from_file, save_signing_key_to_file},
        signer::sign_data,
        verifier::verify_signature,
        *,
    },
    error::AppError,
};
use std::io;

fn main() -> Result<(), AppError> {
    let key = generate_keypair();
    let key2 = generate_keypair();
    let saving_key = save_signing_key_to_file(&key.0, "save_file.txt")?;

    let load_key = load_signing_key_from_file("save_file.txt")?;
    let text = "The old pot is almost broken";
    let signed_text = sign_data(&key.0, text.as_bytes());
    let is_verify = verify_signature(&key.1, text.as_bytes(), &signed_text).is_ok();
    println!("{:?}", is_verify);
    Ok(())
}
