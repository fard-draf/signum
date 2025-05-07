use crate::domain::ports::fs::FileSystem;
use crate::error::{AppError, ErrPath};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone)]
pub struct FileSystemAdapter;

impl FileSystemAdapter {
    pub fn new() -> Self {
        FileSystemAdapter
    }
}

impl Default for FileSystemAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl FileSystem for FileSystemAdapter {
    fn read_file(&self, path: &str) -> Result<Vec<u8>, AppError> {
        fs::read(path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => AppError::Path(ErrPath::InvalidPath),
            std::io::ErrorKind::PermissionDenied => AppError::Path(ErrPath::AccessDenied),
            _ => AppError::Path(ErrPath::ReadError),
        })
    }

    fn write_file(&self, path: &str, data: &[u8]) -> Result<(), AppError> {
        if let Some(parent) = Path::new(path).parent() {
            if !parent.exists() {
                self.create_directory(&parent.to_string_lossy())?;
            }
        }

        fs::write(path, data).map_err(|_| AppError::Path(ErrPath::WriteError))
    }

    fn file_exists(&self, path: &str) -> bool {
        Path::new(path).exists()
    }

    fn is_path_in_directory(&self, path: &str, base_dir: &str) -> Result<bool, AppError> {
        let path = PathBuf::from(path);
        let base_dir = PathBuf::from(base_dir);

        match (path.canonicalize(), base_dir.canonicalize()) {
            (Ok(path), Ok(base)) => Ok(path.starts_with(base)),
            _ => Ok(false),
        }
    }

    fn create_directory(&self, path: &str) -> Result<(), AppError> {
        fs::create_dir_all(path).map_err(|_| AppError::Path(ErrPath::DirectoryCreationFailed))
    }

    fn canonicalize_path(&self, path: &str) -> Result<String, AppError> {
        let path_buf = PathBuf::from(path);
        match path_buf.canonicalize() {
            Ok(canonical_path) => Ok(canonical_path.to_string_lossy().into_owned()),
            Err(_) => Err(AppError::Path(ErrPath::InvalidPath)),
        }
    }
}
