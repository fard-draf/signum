use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use crate::{
    core::crypto::sym::{decrypt_with_aad, derive_key_from_password, encrypt_with_aad},
    domain::{ports::fs::FileSystem, user::entities::User},
    error::{AppError, ErrEncrypt, ErrPath},
    infra::file_system::FileSystemAdapter,
};

pub struct CryptService {
    fs: FileSystemAdapter,
}

impl CryptService {
    pub fn new(fs: FileSystemAdapter) -> Self {
        Self { fs }
    }

    pub fn encrypt_file(
        &self,
        user: &User,
        raw_pw: &mut str,
        input_path: &str,
        output_path: Option<&str>,
    ) -> Result<PathBuf, AppError> {
        let plaintext = self.fs.read_file(input_path)?;
        let mut temp_pw = raw_pw.to_string();
        let mut key = derive_key_from_password(temp_pw.as_mut_str(), user)?;
        temp_pw.zeroize();

        let replace_original = output_path.is_none();
        let output = output_path
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(input_path));
        let aad = canonical_label(&output.to_string_lossy())?;
        let sealed = encrypt_with_aad(&plaintext, &key, aad.as_bytes())?;
        key.zeroize();
        if let Some(parent) = output.parent() {
            if !parent.exists() {
                self.fs.create_directory(&parent.to_string_lossy())?;
            }
        }
        self.fs.write_file(&output.to_string_lossy(), &sealed)?;
        if replace_original && output != PathBuf::from(input_path) {
            let _ = fs::remove_file(input_path);
        }
        Ok(output)
    }

    pub fn decrypt_file(
        &self,
        user: &User,
        raw_pw: &mut str,
        encrypted_path: &str,
        output_path: Option<&str>,
    ) -> Result<PathBuf, AppError> {
        let ciphertext = self.fs.read_file(encrypted_path)?;
        let mut temp_pw = raw_pw.to_string();
        let mut key = derive_key_from_password(temp_pw.as_mut_str(), user)?;
        temp_pw.zeroize();

        let replace_original = output_path.is_none();
        let output = output_path
            .map(PathBuf::from)
            .unwrap_or_else(|| default_decrypted_path(encrypted_path));
        let expected_aad = canonical_label(encrypted_path)?;
        let plaintext = decrypt_with_aad(&ciphertext, &key, Some(expected_aad.as_bytes()))?;
        key.zeroize();

        if let Some(parent) = output.parent() {
            if !parent.exists() {
                self.fs.create_directory(&parent.to_string_lossy())?;
            }
        }
        self.fs.write_file(&output.to_string_lossy(), &plaintext)?;
        if replace_original && output != PathBuf::from(encrypted_path) {
            let _ = fs::remove_file(encrypted_path);
        }
        Ok(output)
    }

    pub fn encrypt_directory(
        &self,
        user: &User,
        raw_pw: &mut str,
        input_dir: &str,
        output_dir: Option<&str>,
    ) -> Result<PathBuf, AppError> {
        let input_root = PathBuf::from(input_dir);
        if !input_root.is_dir() {
            return Err(AppError::Path(ErrPath::DirectoryNotFound));
        }
        let replace_original = output_dir.is_none();
        let (mut output_root, final_destination) = if let Some(custom) = output_dir {
            let path = PathBuf::from(custom);
            if path.exists() {
                fs::remove_dir_all(&path)
                    .map_err(|_| AppError::Path(ErrPath::WriteError))?;
            }
            self.fs.create_directory(&path.to_string_lossy())?;
            (path, None)
        } else {
            let temp = default_enc_temp_dir(&input_root)?;
            if temp.exists() {
                fs::remove_dir_all(&temp)
                    .map_err(|_| AppError::Path(ErrPath::WriteError))?;
            }
            self.fs.create_directory(&temp.to_string_lossy())?;
            (temp.clone(), Some(input_root.clone()))
        };

        let mut temp_pw = raw_pw.to_string();
        let mut key = derive_key_from_password(temp_pw.as_mut_str(), user)?;
        temp_pw.zeroize();

        for entry in walk_files(&input_root)? {
            let rel = entry
                .strip_prefix(&input_root)
                .map_err(|_| AppError::Path(ErrPath::InvalidPath))?;
            let aad = rel.to_string_lossy();
            let data = fs::read(&entry).map_err(|_| AppError::Path(ErrPath::ReadError))?;
            let sealed = encrypt_with_aad(&data, &key, aad.as_bytes())?;

            let dest = add_enc_suffix(&output_root.join(rel))?;
            if let Some(parent) = dest.parent() {
                if !parent.exists() {
                    self.fs.create_directory(&parent.to_string_lossy())?;
                }
            }
            self.fs.write_file(&dest.to_string_lossy(), &sealed)?;
        }

        key.zeroize();
        if replace_original {
            fs::remove_dir_all(&input_root)
                .map_err(|_| AppError::Path(ErrPath::WriteError))?;
            if let Some(dest) = final_destination {
                fs::rename(&output_root, &dest)
                    .map_err(|_| AppError::Path(ErrPath::WriteError))?;
                output_root = dest;
            }
        }
        Ok(output_root)
    }

    pub fn decrypt_directory(
        &self,
        user: &User,
        raw_pw: &mut str,
        enc_dir: &str,
        output_dir: Option<&str>,
    ) -> Result<PathBuf, AppError> {
        let enc_root = PathBuf::from(enc_dir);
        if !enc_root.is_dir() {
            return Err(AppError::Path(ErrPath::DirectoryNotFound));
        }
        let replace_original = output_dir.is_none();
        let (mut output_root, final_destination) = if let Some(custom) = output_dir {
            let path = PathBuf::from(custom);
            if path.exists() {
                fs::remove_dir_all(&path)
                    .map_err(|_| AppError::Path(ErrPath::WriteError))?;
            }
            self.fs.create_directory(&path.to_string_lossy())?;
            (path, None)
        } else {
            let temp = default_dec_temp_dir(&enc_root)?;
            if temp.exists() {
                fs::remove_dir_all(&temp)
                    .map_err(|_| AppError::Path(ErrPath::WriteError))?;
            }
            self.fs.create_directory(&temp.to_string_lossy())?;
            (temp.clone(), Some(resolve_dec_destination(&enc_root)?))
        };

        let mut temp_pw = raw_pw.to_string();
        let mut key = derive_key_from_password(temp_pw.as_mut_str(), user)?;
        temp_pw.zeroize();

        for entry in walk_files(&enc_root)? {
            let name = entry.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if !name.ends_with(".enc") {
                continue;
            }
            let rel_enc = entry
                .strip_prefix(&enc_root)
                .map_err(|_| AppError::Path(ErrPath::InvalidPath))?;

            let rel_plain = strip_enc_suffix(rel_enc)?;
            let aad = rel_plain.to_string_lossy();
            let data = fs::read(&entry).map_err(|_| AppError::Path(ErrPath::ReadError))?;
            let plain = decrypt_with_aad(&data, &key, Some(aad.as_bytes()))?;

            let dest = output_root.join(rel_plain);
            if let Some(parent) = dest.parent() {
                if !parent.exists() {
                    self.fs.create_directory(&parent.to_string_lossy())?;
                }
            }
            self.fs.write_file(&dest.to_string_lossy(), &plain)?;
        }

        key.zeroize();
        if replace_original {
            fs::remove_dir_all(&enc_root)
                .map_err(|_| AppError::Path(ErrPath::WriteError))?;
            if let Some(dest) = final_destination {
                fs::rename(&output_root, &dest)
                    .map_err(|_| AppError::Path(ErrPath::WriteError))?;
                output_root = dest;
            }
        }
        Ok(output_root)
    }
}

fn walk_files(root: &Path) -> Result<Vec<PathBuf>, AppError> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let entries = fs::read_dir(&path).map_err(|_| AppError::Path(ErrPath::ReadError))?;
        for entry in entries {
            let entry = entry.map_err(|_| AppError::Path(ErrPath::ReadError))?;
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                files.push(p);
            }
        }
    }
    Ok(files)
}

fn default_decrypted_path(cipher_path: &str) -> PathBuf {
    if cipher_path.ends_with(".enc") {
        let trimmed = cipher_path.trim_end_matches(".enc");
        PathBuf::from(trimmed)
    } else {
        PathBuf::from(cipher_path)
    }
}

fn canonical_label(path: &str) -> Result<String, AppError> {
    match fs::canonicalize(path) {
        Ok(p) => p
            .to_str()
            .map(|s| s.to_string())
            .ok_or(AppError::Path(ErrPath::InvalidPath)),
        Err(_) => {
            let base = env::current_dir().map_err(|_| AppError::Path(ErrPath::InvalidPath))?;
            let joined = base.join(path);
            joined
                .to_str()
                .map(|s| s.to_string())
                .ok_or(AppError::Path(ErrPath::InvalidPath))
        }
    }
}

fn strip_enc_suffix(path: &Path) -> Result<PathBuf, AppError> {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or(AppError::Path(ErrPath::InvalidPath))?;
    let stripped = name
        .strip_suffix(".enc")
        .ok_or(AppError::Encrypt(ErrEncrypt::InvalidData))?;
    let mut new_path = path.to_path_buf();
    new_path.set_file_name(stripped);
    Ok(new_path)
}

fn add_enc_suffix(path: &Path) -> Result<PathBuf, AppError> {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or(AppError::Path(ErrPath::InvalidPath))?;
    let mut new_path = path.to_path_buf();
    new_path.set_file_name(format!("{}.enc", name));
    Ok(new_path)
}

fn default_enc_temp_dir(input_root: &Path) -> Result<PathBuf, AppError> {
    let name = input_root
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or(AppError::Path(ErrPath::InvalidPath))?;
    Ok(input_root
        .parent()
        .map(|p| p.join(format!("{}-enc-tmp", name)))
        .unwrap_or_else(|| PathBuf::from(format!("{}-enc-tmp", name))))
}

fn default_dec_temp_dir(enc_root: &Path) -> Result<PathBuf, AppError> {
    let name = enc_root
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or(AppError::Path(ErrPath::InvalidPath))?;
    let clean_name = name.strip_suffix(".enc").unwrap_or(name);
    Ok(enc_root
        .parent()
        .map(|p| p.join(format!("{}-dec-tmp", clean_name)))
        .unwrap_or_else(|| PathBuf::from(format!("{}-dec-tmp", clean_name))))
}

fn resolve_dec_destination(enc_root: &Path) -> Result<PathBuf, AppError> {
    let name = enc_root
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or(AppError::Path(ErrPath::InvalidPath))?;
    let clean_name = name.strip_suffix(".enc").unwrap_or(name);
    Ok(enc_root
        .parent()
        .map(|p| p.join(clean_name))
        .unwrap_or_else(|| PathBuf::from(clean_name)))
}
