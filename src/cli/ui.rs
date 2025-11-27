use crate::error::{AppError, ErrInquire, ErrPath};
use inquire::{Confirm, Password, Select, Text};
use std::{
    env, fmt, fs,
    path::{Path, PathBuf},
};

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
        "Chiffrer un répertoire".to_string(),
        "Déchiffrer un répertoire".to_string(),
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
    path_navigator(message)
}

pub fn output_file_prompt() -> Result<Option<String>, AppError> {
    let use_custom = Confirm::new(
        "Voulez-vous spécifier un chemin de sortie personnalisé? (par défaut, l'original est remplacé)",
    )
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

#[derive(Clone)]
struct NavItem {
    label: String,
    value: NavValue,
}

#[derive(Clone)]
enum NavValue {
    SelectCurrent(PathBuf),
    Parent(PathBuf),
    Dir(PathBuf),
    File(PathBuf),
    ManualEntry,
}

impl fmt::Display for NavItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label)
    }
}

fn path_navigator(message: &str) -> Result<String, AppError> {
    let mut current = env::current_dir().map_err(|_| AppError::Path(ErrPath::DirectoryNotFound))?;

    loop {
        let options = build_nav_items(&current)?;
        let prompt = format!(
            "{msg}\nRépertoire actuel: {dir}",
            msg = message,
            dir = current.display()
        );

        let choice = Select::new(&prompt, options)
            .with_help_message(
                "Flèches: naviguer • Entrée: ouvrir/sélectionner • \"Entrer un chemin\" pour saisir manuellement",
            )
            .prompt()
            .map_err(|e| AppError::Inquire(ErrInquire::InquireError(e)))?;

        match choice.value {
            NavValue::SelectCurrent(path) => {
                return Ok(path.to_string_lossy().into_owned());
            }
            NavValue::Parent(path) => {
                current = path;
            }
            NavValue::Dir(path) => {
                current = path;
            }
            NavValue::File(path) => {
                return Ok(path.to_string_lossy().into_owned());
            }
            NavValue::ManualEntry => {
                let manual = Text::new("Entrez un chemin (fichier ou répertoire):")
                    .prompt()
                    .map_err(|e| AppError::Inquire(ErrInquire::InquireError(e)))?;
                return Ok(manual);
            }
        }
    }
}

fn build_nav_items(current: &Path) -> Result<Vec<NavItem>, AppError> {
    let mut dirs = vec![];
    let mut files = vec![];

    for entry in fs::read_dir(current).map_err(|_| AppError::Path(ErrPath::InvalidPath))? {
        let entry = entry.map_err(|_| AppError::Path(ErrPath::InvalidPath))?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();

        let file_type = entry
            .file_type()
            .map_err(|_| AppError::Path(ErrPath::InvalidPath))?;

        if file_type.is_dir() {
            dirs.push((name, path));
        } else {
            files.push((name, path));
        }
    }

    dirs.sort_by(|a, b| a.0.to_lowercase().cmp(&b.0.to_lowercase()));
    files.sort_by(|a, b| a.0.to_lowercase().cmp(&b.0.to_lowercase()));

    let mut options = Vec::new();
    options.push(NavItem {
        label: "[Sélectionner ce répertoire]".to_string(),
        value: NavValue::SelectCurrent(current.to_path_buf()),
    });

    if let Some(parent) = current.parent() {
        options.push(NavItem {
            label: "[..] Revenir en arrière".to_string(),
            value: NavValue::Parent(parent.to_path_buf()),
        });
    }

    for (name, path) in dirs {
        options.push(NavItem {
            label: format!("[D] {}", name),
            value: NavValue::Dir(path),
        });
    }

    for (name, path) in files {
        options.push(NavItem {
            label: format!("    {}", name),
            value: NavValue::File(path),
        });
    }

    options.push(NavItem {
        label: "Entrer un chemin manuellement".to_string(),
        value: NavValue::ManualEntry,
    });

    Ok(options)
}
