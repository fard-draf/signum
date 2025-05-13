use crate::error::{AppError, ErrInquire};
use inquire::{Confirm, Password, Select, Text};

pub fn main_menu() -> Result<String, AppError> {
    let options = vec![
        "Inscription".to_string(),
        "Connexion".to_string(),
        "Quitter".to_string(),
    ];

    Select::new("Choisissez une option:", options)
        .prompt()
        .map_err(|e| AppError::Inquire(ErrInquire::InquireError(e)))
}

pub fn action_menu() -> Result<String, AppError> {
    let options = vec![
        "Signer un fichier".to_string(),
        "Vérifier une signature".to_string(),
        "Chiffrer un fichier".to_string(),
        "Déchiffrer un fichier".to_string(),
        "Déconnexion".to_string(),
    ];

    Select::new("Que souhaitez-vous faire?", options)
        .prompt()
        .map_err(|e| AppError::Inquire(ErrInquire::InquireError(e)))
}

pub fn secure_password_prompt(message: &str, help: &str) -> Result<String, AppError> {
    Password::new(message)
        .with_help_message(help)
        .with_display_mode(inquire::PasswordDisplayMode::Masked)
        .prompt()
        .map_err(|e| AppError::Inquire(ErrInquire::InquireError(e)))
}

pub fn file_prompt(message: &str) -> Result<String, AppError> {
    Text::new(message)
        .with_help_message("Entrez le chemin complet vers le fichier")
        .prompt()
        .map_err(|e| AppError::Inquire(ErrInquire::InquireError(e)))
}

pub fn output_file_prompt() -> Result<Option<String>, AppError> {
    let use_custom = Confirm::new("Voulez-vous spécifier un chemin de sortie personnalisé?")
        .with_default(false)
        .prompt()
        .map_err(|e| AppError::Inquire(ErrInquire::InquireError(e)))?;

    if use_custom {
        let path = Text::new("Chemin du fichier de sortie:")
            .prompt()
            .map_err(|e| AppError::Inquire(ErrInquire::InquireError(e)))?;

        Ok(Some(path))
    } else {
        Ok(None)
    }
}

pub fn confirm_action(message: &str) -> Result<bool, AppError> {
    Confirm::new(message)
        .with_default(false)
        .prompt()
        .map_err(|e| AppError::Inquire(ErrInquire::InquireError(e)))
}
