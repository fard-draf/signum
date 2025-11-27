use crate::domain::ports::fs::FileSystem;
use crate::error::{AppError, ErrPath};
use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
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

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|_| AppError::Path(ErrPath::WriteError))?;

        file.write_all(data)
            .map_err(|_| AppError::Path(ErrPath::WriteError))?;
        let _ = file.sync_all();

        if let Some(parent) = Path::new(path).parent() {
            let _ = fs::File::open(parent).and_then(|f| f.sync_all());
        }

        #[cfg(unix)]
        {
            let perms = fs::Permissions::from_mode(0o600);
            let _ = fs::set_permissions(path, perms);
        }
        Ok(())
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
        fs::create_dir_all(path).map_err(|_| AppError::Path(ErrPath::DirectoryCreationFailed))?;
        #[cfg(unix)]
        {
            let perms = fs::Permissions::from_mode(0o700);
            let _ = fs::set_permissions(path, perms);
        }
        Ok(())
    }

    fn canonicalize_path(&self, path: &str) -> Result<String, AppError> {
        let path_buf = PathBuf::from(path);
        match path_buf.canonicalize() {
            Ok(canonical_path) => Ok(canonical_path.to_string_lossy().into_owned()),
            Err(_) => Err(AppError::Path(ErrPath::InvalidPath)),
        }
    }
}
