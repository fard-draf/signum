use signum::{
    cli::build::{self, run_interactive},
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
    run_interactive();
    Ok(())
}
