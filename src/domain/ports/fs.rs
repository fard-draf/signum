use crate::error::AppError;

pub trait FileSystem {
    fn read_file(&self, path: &str) -> Result<Vec<u8>, AppError>;
    fn write_file(&self, path: &str, data: &[u8]) -> Result<(), AppError>;
    fn file_exists(&self, path: &str) -> bool;
    fn is_path_in_directory(&self, path: &str, base_dir: &str) -> Result<bool, AppError>;
    fn create_directory(&self, path: &str) -> Result<(), AppError>;
    fn canonicalize_path(&self, path: &str) -> Result<String, AppError>;
}
