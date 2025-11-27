#[cfg(test)]
mod tests {
    use argon2::password_hash::SaltString;
    use rand::RngCore;
    use rand_core::OsRng;
    use std::fs;

    use crate::{
        application::crypt_service::CryptService,
        domain::user::{
            entities::{User, UserName},
            file_path::UserFilePath,
            passwords::UserPassword,
        },
        infra::file_system::FileSystemAdapter,
    };

    fn create_user() -> (User, String) {
        let password = "Str0ng@P4ssw0rd1234".to_string();
        let salt = SaltString::generate(&mut OsRng);
        let user = User {
            name: UserName::new("cryptuser").unwrap(),
            password: UserPassword::from_raw(&password).unwrap(),
            file_path: UserFilePath::from_filename("dummy.sgm".to_string()).unwrap(),
            user_salt: salt.to_string(),
        };
        (user, password)
    }

    #[test]
    fn encrypt_decrypt_file_with_aad() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let file_path = tmp.path().join("secret.txt");
        fs::write(&file_path, b"super secret").unwrap();

        let (user, mut password) = create_user();
        let service = CryptService::new(FileSystemAdapter::new());

        let enc_path = service
            .encrypt_file(&user, &mut password, &file_path.to_string_lossy(), None)
            .expect("encryption should work");
        assert_eq!(enc_path, file_path);
        let encrypted_bytes = fs::read(&enc_path).unwrap();
        assert_ne!(encrypted_bytes, b"super secret");

        // Copier le chiffré avant déchiffrement pour tester l'AAD
        let moved_path = tmp.path().join("moved.enc");
        std::fs::copy(&enc_path, &moved_path).unwrap();

        let dec_path = service
            .decrypt_file(&user, &mut password, &enc_path.to_string_lossy(), None)
            .expect("decryption should work");
        let content = fs::read_to_string(&dec_path).unwrap();
        assert_eq!(content, "super secret");

        // Déplacer ou renommer le fichier chiffré doit casser le déchiffrement (AAD lié au chemin)
        let moved_res =
            service.decrypt_file(&user, &mut password, &moved_path.to_string_lossy(), None);
        assert!(
            moved_res.is_err(),
            "decryption after move must fail (path binding)"
        );
    }

    #[test]
    fn encrypt_decrypt_directory_roundtrip() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let dir = tmp.path().join("docs");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("a.txt"), b"alpha").unwrap();
        fs::write(dir.join("nested.bin"), b"bravo").unwrap();

        let (user, mut password) = create_user();
        let service = CryptService::new(FileSystemAdapter::new());

        let enc_dir = service
            .encrypt_directory(&user, &mut password, &dir.to_string_lossy(), None)
            .expect("encrypt dir");
        assert!(enc_dir.is_dir());
        assert_eq!(enc_dir, dir);
        assert!(enc_dir.join("a.txt.enc").exists());
        assert!(!enc_dir.join("a.txt").exists());

        let dec_dir = service
            .decrypt_directory(&user, &mut password, &enc_dir.to_string_lossy(), None)
            .expect("decrypt dir");
        assert!(dec_dir.is_dir());
        assert_eq!(dec_dir, dir);

        let alpha = fs::read_to_string(dec_dir.join("a.txt")).unwrap();
        let bravo = fs::read_to_string(dec_dir.join("nested.bin")).unwrap();
        assert_eq!(alpha, "alpha");
        assert_eq!(bravo, "bravo");
    }

    #[test]
    fn encrypt_large_file() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let file_path = tmp.path().join("big.bin");
        let mut data = vec![0u8; 512 * 1024];
        rand::thread_rng().fill_bytes(&mut data);
        fs::write(&file_path, &data).unwrap();

        let (user, mut password) = create_user();
        let service = CryptService::new(FileSystemAdapter::new());

        let enc = service
            .encrypt_file(&user, &mut password, &file_path.to_string_lossy(), None)
            .expect("encrypt large");
        let dec = service
            .decrypt_file(&user, &mut password, &enc.to_string_lossy(), None)
            .expect("decrypt large");
        let decoded = fs::read(&dec).unwrap();
        assert_eq!(decoded, data);
    }
}
