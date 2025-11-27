use inquire::Select;
use std::{env, fs, path::PathBuf};

use crate::error::{AppError, ErrPath};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunMode {
    Office,
    Nomade,
}

impl RunMode {
    fn as_str(&self) -> &'static str {
        match self {
            RunMode::Office => "OFFICE",
            RunMode::Nomade => "NOMADE",
        }
    }

    fn from_str(raw: &str) -> Option<Self> {
        match raw.to_ascii_uppercase().as_str() {
            "OFFICE" => Some(RunMode::Office),
            "NOMADE" => Some(RunMode::Nomade),
            _ => None,
        }
    }
}

/// Resolve run mode from config, prompting the user on first launch.
pub fn resolve_mode() -> Result<RunMode, AppError> {
    let config_path = config_path()?;

    if let Some(mode) = load_mode(&config_path) {
        return Ok(mode);
    }

    let mode = prompt_mode()?;
    persist_mode(&config_path, mode)?;
    Ok(mode)
}

/// Ensure environment variables reflect the chosen mode before building AppConfig.
pub fn apply_mode_environment(mode: RunMode) -> Result<(), AppError> {
    match mode {
        RunMode::Office => unsafe {
            env::remove_var("SIGNUM_PORTABLE");
            env::remove_var("SIGNUM_DATA_DIR");
        },
        RunMode::Nomade => {
            let exe_dir = current_exe_dir()?;
            let data_dir = exe_dir.join("signum-data");
            unsafe {
                env::set_var("SIGNUM_PORTABLE", "1");
                if env::var_os("SIGNUM_DATA_DIR").is_none() {
                    env::set_var("SIGNUM_DATA_DIR", &data_dir);
                }
            }
        }
    }
    Ok(())
}

fn prompt_mode() -> Result<RunMode, AppError> {
    let choice = Select::new(
        "Choisissez le mode de fonctionnement (définitif, stocké dans le fichier de configuration) :",
        vec!["OFFICE", "NOMADE"],
    )
    .prompt()
    .map_err(|e| AppError::Inquire(crate::error::ErrInquire::InquireError(e)))?;

    RunMode::from_str(&choice).ok_or(AppError::Path(ErrPath::InvalidPath))
}

fn persist_mode(path: &PathBuf, mode: RunMode) -> Result<(), AppError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| AppError::Path(ErrPath::DirectoryCreationFailed))?;
    }
    let content = format!("mode={}\n", mode.as_str());
    fs::write(path, content).map_err(|_| AppError::Path(ErrPath::WriteError))
}

fn load_mode(path: &PathBuf) -> Option<RunMode> {
    if let Ok(content) = fs::read_to_string(path) {
        for line in content.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("mode=") {
                if let Some(mode) = RunMode::from_str(rest.trim()) {
                    return Some(mode);
                }
            }
        }
    }
    None
}

fn config_path() -> Result<PathBuf, AppError> {
    if let Some(custom) = env::var_os("SIGNUM_CONFIG_PATH") {
        return Ok(PathBuf::from(custom));
    }

    let exe_dir = current_exe_dir()?;
    if let Some(parent) = exe_dir.parent() {
        return Ok(parent.join("signum.conf"));
    }
    Ok(exe_dir.join("signum.conf"))
}

fn current_exe_dir() -> Result<PathBuf, AppError> {
    let exe = env::current_exe().map_err(|_| AppError::Path(ErrPath::DirectoryNotFound))?;
    exe.parent()
        .map(|p| p.to_path_buf())
        .ok_or(AppError::Path(ErrPath::DirectoryNotFound))
}
