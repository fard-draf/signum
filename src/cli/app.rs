// src/cli/app.rs
use crate::{
    application::{
        auth_service::AuthService, crypt_service::CryptService, key_service::KeyService,
    },
    domain::{ports::config::AppConfig, user::entities::User},
    error::AppError,
    infra::{file_system::FileSystemAdapter, user_repo::UserFileRepository},
};
use ed25519_dalek::SigningKey;
use inquire::Text;
use std::path::Path;
use zeroize::Zeroize;

pub struct SignumCli {
    auth_service: AuthService<UserFileRepository<FileSystemAdapter>, FileSystemAdapter>,
    crypt_service: CryptService,
}

impl SignumCli {
    pub fn new() -> Result<Self, AppError> {
        // Choix du mode (OFFICE/NOMADE) au premier lancement, puis configuration initiale
        let mode = crate::cli::mode::resolve_mode()?;
        crate::cli::mode::apply_mode_environment(mode)?;

        let config = AppConfig::new(None)?;
        let fs_adapter = FileSystemAdapter::new();
        let user_repository = UserFileRepository::new(fs_adapter.clone(), config.clone());
        let key_service = KeyService::new(fs_adapter.clone(), config.clone());
        let auth_service =
            AuthService::new(user_repository, fs_adapter.clone(), config, key_service);
        let crypt_service = CryptService::new(fs_adapter);

        Ok(Self {
            auth_service,
            crypt_service,
        })
    }

    pub fn run(&self) -> Result<(), AppError> {
        // Interface principale du CLI
        println!("=== Signum CLI ===");
        println!("Une application moderne pour signer, vérifier et chiffrer des fichiers");

        loop {
            let selection = crate::cli::ui::main_menu()?;
            match selection.as_str() {
                "Inscription" => self.register()?,
                "Connexion" => self.login()?,
                "Quitter" => {
                    println!("Au revoir!");
                    break;
                }
                _ => println!("Option non reconnue"),
            }
        }

        Ok(())
    }

    fn register(&self) -> Result<(), AppError> {
        println!("\n=== Inscription ===");

        let username = Text::new("Nom d'utilisateur:")
            .with_help_message("Minimum 3 caractères, lettres uniquement")
            .prompt()
            .map_err(|e| AppError::Inquire(crate::error::ErrInquire::InquireError(e)))?;

        let mut password = crate::cli::ui::secure_password_prompt(
            "Mot de passe:",
            "Minimum 10 caractères, avec majuscules, minuscules, chiffres et caractères spéciaux",
        )?;

        // Créer un chemin par défaut basé sur le nom d'utilisateur
        let config = AppConfig::new(None)?;
        let default_path = config
            .base_directory
            .join("users")
            .join(&username)
            .join(format!("{}.sgm", username));
        let mut path = default_path.to_string_lossy().into_owned();

        match self
            .auth_service
            .register(&username, &mut password, &mut path)
        {
            Ok((user, _)) => {
                println!("\n✅ Inscription réussie pour: {}", user.name);
            }
            Err(e) => {
                println!("\n❌ Erreur lors de l'inscription: {:?}", e);
            }
        }

        password.zeroize();

        Ok(())
    }

    fn login(&self) -> Result<(), AppError> {
        println!("\n=== Connexion ===");

        let username = Text::new("Nom d'utilisateur:")
            .prompt()
            .map_err(|e| AppError::Inquire(crate::error::ErrInquire::InquireError(e)))?;

        let mut password =
            crate::cli::ui::secure_password_prompt("Mot de passe:", "Entrez votre mot de passe")?;

        match self.auth_service.login(&username, &mut password) {
            Ok((user, signing_key)) => {
                println!("\n✅ Connexion réussie pour: {}", user.name);
                // Après connexion réussie, afficher le menu des actions disponibles
                self.action_menu(&user, signing_key, &mut password)?;
            }
            Err(e) => {
                println!("\n❌ Erreur lors de la connexion: {:?}", e);
            }
        }

        password.zeroize();

        Ok(())
    }

    fn action_menu(
        &self,
        user: &User,
        signing_key: SigningKey,
        password: &mut String,
    ) -> Result<(), AppError> {
        let mut continue_session = true;

        while continue_session {
            let selection = crate::cli::ui::action_menu()?;

            match selection.as_str() {
                "Signer un fichier" => {
                    self.sign_file_action(user, &signing_key)?;
                }
                "Vérifier une signature" => {
                    self.verify_signature_action(user, password)?;
                }
                "Chiffrer un fichier" => {
                    self.with_password(password, |pw| self.encrypt_file_action(user, pw))?;
                }
                "Déchiffrer un fichier" => {
                    self.with_password(password, |pw| self.decrypt_file_action(user, pw))?;
                }
                "Chiffrer un répertoire" => {
                    self.with_password(password, |pw| self.encrypt_dir_action(user, pw))?;
                }
                "Déchiffrer un répertoire" => {
                    self.with_password(password, |pw| self.decrypt_dir_action(user, pw))?;
                }
                "Déconnexion" => {
                    println!("Vous êtes déconnecté");
                    continue_session = false;
                }
                _ => println!("Option non reconnue"),
            }
        }

        Ok(())
    }

    fn sign_file_action(&self, _user: &User, signing_key: &SigningKey) -> Result<(), AppError> {
        println!("\n=== Signer un fichier ===");

        // Demander le chemin du fichier à signer
        let file_path = crate::cli::ui::file_prompt("Chemin du fichier à signer:")?;

        // Vérifier si le fichier existe
        if !Path::new(&file_path).exists() {
            println!("❌ Le fichier n'existe pas");
            return Ok(());
        }

        // Demander le chemin de sortie
        let output_path = crate::cli::ui::output_file_prompt()?;

        // Appeler la fonction de signature
        match crate::cli::commands::sign_file(signing_key, &file_path, output_path.as_deref()) {
            Ok(_) => {}
            Err(e) => println!("❌ Erreur lors de la signature: {:?}", e),
        }

        Ok(())
    }

    fn verify_signature_action(&self, user: &User, password: &mut String) -> Result<(), AppError> {
        println!("\n=== Vérifier une signature ===");

        // Demander le chemin du fichier original
        let file_path = crate::cli::ui::file_prompt("Chemin du fichier original:")?;

        // Demander le chemin du fichier de signature
        let signature_path = crate::cli::ui::file_prompt("Chemin du fichier de signature:")?;

        // Charger la clé de vérification de l'utilisateur
        let mut temp_pw = String::new();
        password.clone_into(&mut temp_pw);
        let verifying_key = match self.auth_service.load_verifying_key(user, &mut temp_pw) {
            Ok(vk) => vk,
            Err(e) => {
                println!(
                    "❌ Erreur lors du chargement de la clé de vérification: {:?}",
                    e
                );
                return Ok(());
            }
        };
        temp_pw.zeroize();

        // Appeler la fonction de vérification
        match crate::cli::commands::verify_signature(&file_path, &signature_path, &verifying_key) {
            Ok(_) => {}
            Err(e) => println!("❌ Erreur lors de la vérification: {:?}", e),
        }

        Ok(())
    }

    fn encrypt_file_action(&self, user: &User, password: &mut String) -> Result<(), AppError> {
        println!("\n=== Chiffrer un fichier ===");

        // Demander le chemin du fichier à chiffrer
        let file_path = crate::cli::ui::file_prompt("Chemin du fichier à chiffrer:")?;

        // Vérifier si le fichier existe
        if !Path::new(&file_path).exists() {
            println!("❌ Le fichier n'existe pas");
            return Ok(());
        }

        // Demander le chemin de sortie
        let output_path = crate::cli::ui::output_file_prompt()?;

        // Appeler la fonction de chiffrement
        match self
            .crypt_service
            .encrypt_file(user, password, &file_path, output_path.as_deref())
        {
            Ok(path) => println!(
                "✅ Fichier chiffré: {}. Synchronisation terminée, vous pouvez retirer la clé.",
                path.to_string_lossy()
            ),
            Err(e) => println!("❌ Erreur lors du chiffrement: {:?}", e),
        }

        Ok(())
    }

    fn decrypt_file_action(&self, user: &User, password: &mut String) -> Result<(), AppError> {
        println!("\n=== Déchiffrer un fichier ===");

        // Demander le chemin du fichier à déchiffrer
        let file_path = crate::cli::ui::file_prompt("Chemin du fichier à déchiffrer:")?;

        // Vérifier si le fichier existe
        if !Path::new(&file_path).exists() {
            println!("❌ Le fichier n'existe pas");
            return Ok(());
        }

        // Demander le chemin de sortie
        let output_path = crate::cli::ui::output_file_prompt()?;

        // Appeler la fonction de déchiffrement
        match self
            .crypt_service
            .decrypt_file(user, password, &file_path, output_path.as_deref())
        {
            Ok(_) => {}
            Err(e) => println!("❌ Erreur lors du déchiffrement: {:?}", e),
        }

        Ok(())
    }

    fn encrypt_dir_action(&self, user: &User, password: &mut String) -> Result<(), AppError> {
        println!("\n=== Chiffrer un répertoire ===");
        let dir_path = crate::cli::ui::file_prompt("Chemin du répertoire à chiffrer:")?;
        let output_path = crate::cli::ui::output_file_prompt()?;

        match self.crypt_service.encrypt_directory(
            user,
            password,
            &dir_path,
            output_path.as_deref(),
        ) {
            Ok(path) => {
                println!("✅ Répertoire chiffré dans: {}", path.to_string_lossy());
                println!(
                    "ℹ️  Synchronisation terminée. Vous pouvez retirer la clé en toute sécurité."
                );
            }
            Err(e) => println!("❌ Erreur lors du chiffrement du répertoire: {:?}", e),
        }
        Ok(())
    }

    fn decrypt_dir_action(&self, user: &User, password: &mut String) -> Result<(), AppError> {
        println!("\n=== Déchiffrer un répertoire ===");
        let dir_path = crate::cli::ui::file_prompt("Chemin du répertoire chiffré:")?;
        let output_path = crate::cli::ui::output_file_prompt()?;

        match self.crypt_service.decrypt_directory(
            user,
            password,
            &dir_path,
            output_path.as_deref(),
        ) {
            Ok(path) => println!("✅ Répertoire déchiffré dans: {}", path.to_string_lossy()),
            Err(e) => println!("❌ Erreur lors du déchiffrement du répertoire: {:?}", e),
        }
        Ok(())
    }

    fn with_password<F>(&self, password: &str, mut f: F) -> Result<(), AppError>
    where
        F: FnMut(&mut String) -> Result<(), AppError>,
    {
        let mut temp = password.to_string();
        let res = f(&mut temp);
        temp.zeroize();
        res
    }
}
