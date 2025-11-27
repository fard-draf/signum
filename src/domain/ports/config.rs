use std::env;
use std::fs;
use std::path::PathBuf;

use crate::domain::user::entities::UserName;
use crate::error::{AppError, ErrPath};

#[derive(Clone)]
pub struct AppConfig {
    pub base_directory: PathBuf,
    pub app_name: String,
}

impl AppConfig {
    pub fn new(custom_base_dir: Option<PathBuf>) -> Result<Self, AppError> {
        let app_name = "Signum".to_string();

        let base_directory = match custom_base_dir {
            Some(dir) => dir,
            None => {
                if let Some(portable_dir) = Self::get_portable_base_directory()? {
                    portable_dir
                } else {
                    Self::get_default_base_directory()?
                }
            }
        };

        let app_dir = base_directory.join(&app_name);
        if !app_dir.exists() {
            fs::create_dir_all(&app_dir)
                .map_err(|_| AppError::Path(ErrPath::DirectoryCreationFailed))?;
        }

        Ok(Self {
            base_directory: app_dir,
            app_name,
        })
    }

    fn get_portable_base_directory() -> Result<Option<PathBuf>, AppError> {
        if let Some(portable_dir) = env::var_os("SIGNUM_DATA_DIR") {
            return Ok(Some(PathBuf::from(portable_dir)));
        }

        if let Some(flag) = env::var_os("SIGNUM_PORTABLE") {
            if flag != "0" && flag != "false" {
                let exe_dir = env::current_exe()
                    .map_err(|_| AppError::Path(ErrPath::DirectoryNotFound))?;
                if let Some(parent) = exe_dir.parent() {
                    return Ok(Some(parent.join("signum-data")));
                }
                return Err(AppError::Path(ErrPath::DirectoryNotFound));
            }
        }

        Ok(None)
    }

    fn get_default_base_directory() -> Result<PathBuf, AppError> {
        let base_dir = if cfg!(target_os = "windows") {
            if let Some(app_data) = env::var_os("LOCALAPPDATA") {
                PathBuf::from(app_data)
            } else {
                return Err(AppError::Path(ErrPath::DirectoryNotFound));
            }
        } else if cfg!(target_os = "macos") {
            if let Some(home) = env::var_os("HOME") {
                let mut path = PathBuf::from(home);
                path.push("Library");
                path.push("Application Support");
                path
            } else {
                return Err(AppError::Path(ErrPath::DirectoryNotFound));
            }
        } else if let Some(xdg_data) = env::var_os("XDG_DATA_HOME") {
            PathBuf::from(xdg_data)
        } else if let Some(home) = env::var_os("HOME") {
            let mut path = PathBuf::from(home);
            path.push(".local");
            path.push("share");
            path
        } else {
            return Err(AppError::Path(ErrPath::DirectoryNotFound));
        };

        Ok(base_dir)
    }

    pub fn get_user_data_path(&self, username: &UserName) -> PathBuf {
        self.base_directory
            .join("users")
            .join(username.name.as_str())
            .join(format!("{}.sgm", username.name))
    }
}
