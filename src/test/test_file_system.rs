#[cfg(test)]
mod tests {
    use crate::infra::file_system::FileSystemAdapter;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[cfg(unix)]
    #[test]
    fn writes_with_strict_permissions() {
        let fs = FileSystemAdapter::new();
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let file_path = tmpdir.path().join("secret_dir").join("secret.txt");

        fs.write_file(&file_path.to_string_lossy(), b"secret")
            .expect("write should succeed");

        let meta = fs::metadata(&file_path).expect("metadata");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "file mode should be 600");

        let dir_meta = fs::metadata(file_path.parent().unwrap()).expect("dir metadata");
        let dir_mode = dir_meta.permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "dir mode should be 700");
    }
}
