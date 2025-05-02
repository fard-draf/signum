use crate::{
    cli::state::AppContext,
    crypto::{
        keys_ed25519,
        keysfiles::{load_signing_key_from_file, save_signing_key_to_file},
        signer::{self, sign_data},
        verifier,
    },
    error::AppError,
};
use inquire::{Select, Text};

pub fn interactive_generate_key() -> Result<Option<String>, AppError> {
    let path = Text::new("Where do you want to save the private key?")
        .prompt()
        .map_err(|e| AppError::InquireError(e))?;
    let (sk, vk) = keys_ed25519::generate_keypair();
    if save_signing_key_to_file(&sk, &path).is_ok() {
        println!("Keys saved!");
        Ok(Some(path))
    } else {
        return Err(AppError::InvalidPath);
    }
}
