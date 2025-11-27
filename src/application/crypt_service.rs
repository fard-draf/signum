use rand::RngCore;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Component, Path, PathBuf};
use std::time::Instant;
use zeroize::Zeroize;

use crate::{
    core::crypto::sym::{decrypt_with_aad, derive_key_from_password, encrypt_with_aad},
    domain::{ports::fs::FileSystem, user::entities::User},
    error::{AppError, ErrEncrypt, ErrPath},
    infra::file_system::FileSystemAdapter,
};

pub struct CryptService {
    fs: FileSystemAdapter,
    wipe_enabled: bool,
}

impl CryptService {
    pub fn new(fs: FileSystemAdapter) -> Self {
        Self {
            fs,
            wipe_enabled: is_wipe_enabled(),
        }
    }

    pub fn encrypt_file(
        &self,
        user: &User,
        raw_pw: &mut str,
        input_path: &str,
        output_path: Option<&str>,
    ) -> Result<PathBuf, AppError> {
        if input_path.ends_with(".enc") {
            return Err(AppError::Encrypt(ErrEncrypt::AlreadyEncrypted));
        }
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
            self.best_effort_wipe_file(Path::new(input_path));
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
            self.best_effort_wipe_file(Path::new(encrypted_path));
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
        let stats = compute_dir_stats(&input_root, false)?;
        if stats.enc_count > 0 && stats.non_enc_count == 0 {
            return Err(AppError::Encrypt(ErrEncrypt::AlreadyEncrypted));
        }
        let in_place = output_dir.is_none();
        let (mut output_root, final_destination): (PathBuf, Option<PathBuf>) =
            if let Some(custom) = output_dir {
                let path = PathBuf::from(custom);
                if path.exists() {
                    self.best_effort_wipe_dir(&path);
                    fs::remove_dir_all(&path).map_err(|_| AppError::Path(ErrPath::WriteError))?;
                }
                self.fs.create_directory(&path.to_string_lossy())?;
                (path, None)
            } else {
                (input_root.clone(), None)
            };

        let mut temp_pw = raw_pw.to_string();
        let mut key = derive_key_from_password(temp_pw.as_mut_str(), user)?;
        temp_pw.zeroize();

        let total_bytes = stats.total_bytes.max(1);
        let start = Instant::now();
        let mut processed: u64 = 0;

        for entry in walk_files(&input_root)? {
            if entry
                .file_name()
                .and_then(|s| s.to_str())
                .map(|n| n.ends_with(".enc"))
                .unwrap_or(false)
            {
                continue;
            }
            let rel = entry
                .strip_prefix(&input_root)
                .map_err(|_| AppError::Path(ErrPath::InvalidPath))?;
            let aad = portable_tail_label(rel, 1)?;
            let data = match fs::read(&entry) {
                Ok(d) => d,
                Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                    // Skip unreadable system/hidden files instead of aborting the whole directory
                    continue;
                }
                Err(_) => return Err(AppError::Path(ErrPath::ReadError)),
            };
            let sealed = encrypt_with_aad(&data, &key, aad.as_bytes())?;

            let dest = add_enc_suffix(&output_root.join(rel))?;
            if let Some(parent) = dest.parent() {
                if !parent.exists() {
                    self.fs.create_directory(&parent.to_string_lossy())?;
                }
            }
            self.fs.write_file(&dest.to_string_lossy(), &sealed)?;
            if in_place {
                self.best_effort_wipe_file(&entry);
                let _ = fs::remove_file(&entry);
            }
            processed = processed.saturating_add(data.len() as u64);
            self.print_progress(processed, total_bytes, start.elapsed(), "Chiffrement");
        }

        key.zeroize();
        if let Some(dest) = final_destination {
            self.best_effort_wipe_dir(&input_root);
            fs::remove_dir_all(&input_root).map_err(|_| AppError::Path(ErrPath::WriteError))?;
            fs::rename(&output_root, &dest).map_err(|_| AppError::Path(ErrPath::WriteError))?;
            self.sync_dir(dest.parent());
            output_root = dest;
        }
        self.sync_dir(Some(&output_root));
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
        let stats = compute_dir_stats(&enc_root, true)?;
        if stats.enc_count == 0 {
            return Err(AppError::Encrypt(ErrEncrypt::InvalidData));
        }
        let in_place = output_dir.is_none();
        let (mut output_root, final_destination): (PathBuf, Option<PathBuf>) =
            if let Some(custom) = output_dir {
                let path = PathBuf::from(custom);
                if path.exists() {
                    self.best_effort_wipe_dir(&path);
                    fs::remove_dir_all(&path).map_err(|_| AppError::Path(ErrPath::WriteError))?;
                }
                self.fs.create_directory(&path.to_string_lossy())?;
                (path, None)
            } else {
                (enc_root.clone(), None)
            };

        let mut temp_pw = raw_pw.to_string();
        let mut key = derive_key_from_password(temp_pw.as_mut_str(), user)?;
        temp_pw.zeroize();

        let total_bytes = stats.total_bytes.max(1);
        let start = Instant::now();
        let mut processed: u64 = 0;

        for entry in walk_files(&enc_root)? {
            let name = entry.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if !name.ends_with(".enc") {
                continue;
            }
            let rel_enc = entry
                .strip_prefix(&enc_root)
                .map_err(|_| AppError::Path(ErrPath::InvalidPath))?;

            let rel_plain = strip_enc_suffix(rel_enc)?;
            let aad = portable_tail_label(&rel_plain, 1)?;
            let data = fs::read(&entry).map_err(|_| AppError::Path(ErrPath::ReadError))?;
            let plain = decrypt_with_aad(&data, &key, Some(aad.as_bytes()))?;

            let dest = output_root.join(rel_plain);
            if let Some(parent) = dest.parent() {
                if !parent.exists() {
                    self.fs.create_directory(&parent.to_string_lossy())?;
                }
            }
            self.fs.write_file(&dest.to_string_lossy(), &plain)?;
            if in_place {
                self.best_effort_wipe_file(&entry);
                let _ = fs::remove_file(&entry);
            }
            processed = processed.saturating_add(data.len() as u64);
            self.print_progress(processed, total_bytes, start.elapsed(), "Déchiffrement");
        }

        key.zeroize();
        if let Some(dest) = final_destination {
            self.best_effort_wipe_dir(&enc_root);
            fs::remove_dir_all(&enc_root).map_err(|_| AppError::Path(ErrPath::WriteError))?;
            fs::rename(&output_root, &dest).map_err(|_| AppError::Path(ErrPath::WriteError))?;
            self.sync_dir(dest.parent());
            output_root = dest;
        }
        self.sync_dir(Some(&output_root));
        Ok(output_root)
    }
}

fn walk_files(root: &Path) -> Result<Vec<PathBuf>, AppError> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let entries = match fs::read_dir(&path) {
            Ok(e) => e,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => continue,
            Err(_) => return Err(AppError::Path(ErrPath::ReadError)),
        };
        for entry in entries.flatten() {
            let p = entry.path();
            match entry.file_type() {
                Ok(ft) if ft.is_dir() => stack.push(p),
                Ok(_) => files.push(p),
                Err(e) if e.kind() == ErrorKind::PermissionDenied => continue,
                Err(_) => return Err(AppError::Path(ErrPath::ReadError)),
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
    // Bind to the file name only (no parent outside the USB scope), portable separators.
    portable_tail_label(Path::new(path), 1)
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

fn portable_components(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|c| match c {
            Component::Normal(os) => Some(os.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect()
}

fn portable_tail_label(path: &Path, count: usize) -> Result<String, AppError> {
    let comps = portable_components(path);
    if comps.is_empty() {
        return Err(AppError::Path(ErrPath::InvalidPath));
    }
    let effective = count.max(1);
    let mut tail = comps
        .iter()
        .rev()
        .take(effective)
        .cloned()
        .collect::<Vec<_>>();
    tail.reverse();
    Ok(tail.join("/"))
}

fn portable_rel_label(path: &Path) -> Result<String, AppError> {
    let comps = portable_components(path);
    if comps.is_empty() {
        return Err(AppError::Path(ErrPath::InvalidPath));
    }
    Ok(comps.join("/"))
}

#[derive(Default)]
struct DirStats {
    total_bytes: u64,
    enc_count: usize,
    non_enc_count: usize,
}

fn compute_dir_stats(root: &Path, decrypt: bool) -> Result<DirStats, AppError> {
    let mut stats = DirStats::default();
    for entry in walk_files(root)? {
        let name = entry.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let is_enc = name.ends_with(".enc");
        let meta = fs::metadata(&entry).map_err(|_| AppError::Path(ErrPath::ReadError))?;
        if decrypt {
            if is_enc {
                stats.enc_count += 1;
                stats.total_bytes = stats.total_bytes.saturating_add(meta.len());
            } else {
                stats.non_enc_count += 1;
            }
        } else if is_enc {
            stats.enc_count += 1;
        } else {
            stats.non_enc_count += 1;
            stats.total_bytes = stats.total_bytes.saturating_add(meta.len());
        }
    }
    Ok(stats)
}

fn is_wipe_enabled() -> bool {
    match env::var("SIGNUM_WIPE") {
        Ok(v)
            if matches!(
                v.as_str(),
                "0" | "false" | "FALSE" | "off" | "OFF" | "no" | "NO"
            ) =>
        {
            false
        }
        _ => true, // enabled by default; explicit opt-out only
    }
}

impl CryptService {
    fn sync_dir(&self, dir: Option<&Path>) {
        if let Some(d) = dir {
            let _ = fs::File::open(d).and_then(|f| f.sync_all());
            if let Some(parent) = d.parent() {
                let _ = fs::File::open(parent).and_then(|f| f.sync_all());
            }
        }
    }

    fn print_progress(
        &self,
        processed: u64,
        total: u64,
        elapsed: std::time::Duration,
        label: &str,
    ) {
        if total == 0 {
            return;
        }
        let percent = (processed as f64 / total as f64 * 100.0).min(100.0);
        let secs = elapsed.as_secs_f64().max(0.001);
        let eta = if processed > 0 {
            let rate = processed as f64 / secs;
            let remaining = (total.saturating_sub(processed)) as f64 / rate;
            remaining
        } else {
            0.0
        };
        println!(
            "[{}] Progression: {:>5.1}% | Temps restant estimé: ~{:.1}s",
            label, percent, eta
        );
    }

    fn best_effort_wipe_file(&self, path: &Path) {
        if !self.wipe_enabled {
            return;
        }
        if let Ok(meta) = fs::metadata(path) {
            if meta.is_file() {
                let len = meta.len();
                if let Ok(mut file) = OpenOptions::new().write(true).open(path) {
                    let mut rng = rand::thread_rng();
                    let mut buf = [0u8; 8192];
                    let mut remaining = len;
                    while remaining > 0 {
                        let chunk = remaining.min(buf.len() as u64) as usize;
                        rng.fill_bytes(&mut buf[..chunk]);
                        if file.write_all(&buf[..chunk]).is_err() {
                            break;
                        }
                        remaining -= chunk as u64;
                    }
                    let _ = file.sync_all();
                }
            }
        }
    }

    fn best_effort_wipe_dir(&self, path: &Path) {
        if !self.wipe_enabled {
            return;
        }
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    self.best_effort_wipe_dir(&p);
                } else {
                    self.best_effort_wipe_file(&p);
                }
            }
        }
    }
}
