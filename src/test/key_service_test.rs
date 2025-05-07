// src/test/key_service_test.rs

#[cfg(test)]
mod tests {
    use log::info;
    use std::path::PathBuf;
    use zeroize::Zeroize;

    use crate::{
        application::key_service::KeyService,
        core::{
            crypto::sym::{decrypt_data, encrypt_data},
            keys::keypair::generate_keypair,
        },
        domain::{
            ports::config::AppConfig,
            user::{
                entities::{User, UserName},
                file_path::UserFilePath,
                passwords::UserPassword,
            },
        },
        error::AppError,
        infra::file_system::FileSystemAdapter,
    };
    use argon2::password_hash::SaltString;
    use ed25519_dalek::{SigningKey, Verifier, VerifyingKey, ed25519::signature::SignerMut};
    use rand_core::OsRng;

    // Crée un répertoire temporaire pour les tests
    fn setup_test_config() -> Result<AppConfig, AppError> {
        let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");
        let custom_base_dir = Some(PathBuf::from(temp_dir.path()));
        AppConfig::new(custom_base_dir)
    }

    // debug
    fn init() {
        let _ = tracing_subscriber::fmt::try_init();
    }
    // Crée un utilisateur de test
    fn create_test_user() -> (User, String) {
        let password = "Str0ng@P4ssw0rd1234";
        let salt = SaltString::generate(&mut OsRng);

        let user = User {
            name: UserName::new("testuser").unwrap(),
            password: UserPassword::from_raw(password).unwrap(),
            file_path: UserFilePath::from_filename("test_keys.sgm".to_string()).unwrap(),
            user_salt: salt.to_string(),
        };

        (user, password.to_string())
    }

    #[test]
    fn test_key_service_initialization() {
        let config = setup_test_config().expect("Failed to setup test config");
        let fs = FileSystemAdapter::new();

        let key_service = KeyService::new(fs, config);
        assert!(true, "KeyService initialized successfully");
    }

    #[test]
    fn test_generate_and_save_user_keys() {
        let config = setup_test_config().expect("Failed to setup test config");
        let fs = FileSystemAdapter::new();
        let key_service = KeyService::new(fs, config);

        let (user, mut password) = create_test_user();

        // Générer des clés
        let result = key_service.generate_user_keys(&user, &mut password);
        assert!(
            result.is_ok(),
            "Failed to generate user keys: {:?}",
            result.err()
        );

        // Vérifier si les clés existent
        let has_keys = key_service
            .has_keys(&user)
            .expect("Failed to check if user has keys");
        assert!(has_keys, "User should have keys after generation");
    }

    #[test]
    fn test_save_and_load_signing_key() {
        init();
        let config = setup_test_config().expect("Failed to setup test config");
        let fs = FileSystemAdapter::new();
        let key_service = KeyService::new(fs, config);

        let (user, _) = create_test_user();
        let mut password = "Str0ng@P4ssw0rd1234".to_string();

        // Générer une clé de signature
        let (original_key, _) = generate_keypair();
        info!("TEST: original key test {:?}", original_key);
        // Sauvegarder la clé
        let save_result = key_service.save_signing_key(&user, &mut password, &original_key);
        assert!(
            save_result.is_ok(),
            "Failed to save signing key: {:?}",
            save_result.err()
        );

        let mut password = "Str0ng@P4ssw0rd1234".to_string();

        // Charger la clé
        let loaded_key = key_service.load_signing_key(&user, &mut password);
        assert!(
            loaded_key.is_ok(),
            "Failed to load signing key: {:?}",
            loaded_key.err()
        );

        // Vérifier que les clés sont identiques
        let loaded_key = loaded_key.unwrap();
        info!("TEST: loaded_key: {:?}", loaded_key);
        assert_eq!(
            original_key.to_bytes(),
            loaded_key.to_bytes(),
            "Loaded key should match original key"
        );

        // Tester avec un mauvais mot de passe
        let mut wrong_password = "Wr0ng@P4ssw0rd5678".to_string();
        let result = key_service.load_signing_key(&user, &mut wrong_password);
        assert!(result.is_err(), "Loading with wrong password should fail");
    }

    #[test]
    fn test_save_and_load_verifying_key() {
        let config = setup_test_config().expect("Failed to setup test config");
        let fs = FileSystemAdapter::new();
        let key_service = KeyService::new(fs, config);

        let (user, _) = create_test_user();

        // Générer une paire de clés
        let (_, original_vk) = generate_keypair();

        // Sauvegarder la clé de vérification
        let save_result = key_service.save_verifying_key(&user, &original_vk);
        assert!(
            save_result.is_ok(),
            "Failed to save verifying key: {:?}",
            save_result.err()
        );
        let mut password = "Str0ng@P4ssw0rd1234".to_string();

        // Charger la clé de vérification
        let loaded_vk = key_service.load_verifying_key(&user);
        assert!(
            loaded_vk.is_ok(),
            "Failed to load verifying key: {:?}",
            loaded_vk.err()
        );

        // Vérifier que les clés sont identiques
        let loaded_vk = loaded_vk.unwrap();
        assert_eq!(
            original_vk.to_bytes(),
            loaded_vk.to_bytes(),
            "Loaded verifying key should match original key"
        );
    }

    #[test]
    fn test_complete_key_workflow() {
        let config = setup_test_config().expect("Failed to setup test config");
        let fs = FileSystemAdapter::new();
        let key_service = KeyService::new(fs, config.clone());

        let (user, mut password) = create_test_user();

        // 1. Générer des clés pour l'utilisateur
        let gen_result = key_service.generate_user_keys(&user, &mut password);
        assert!(
            gen_result.is_ok(),
            "Failed to generate user keys: {:?}",
            gen_result.err()
        );
        let mut password = "Str0ng@P4ssw0rd1234".to_string();

        // 2. Charger les clés
        let sk = key_service.load_signing_key(&user, &mut password);
        let vk = key_service.load_verifying_key(&user);

        assert!(sk.is_ok(), "Failed to load signing key: {:?}", sk.err());
        assert!(vk.is_ok(), "Failed to load verifying key: {:?}", vk.err());

        let mut sk = sk.unwrap();
        let vk = vk.unwrap();

        // 3. Tester la signature et la vérification
        let message = b"Test message for Signum key service";
        let signature = sk.sign(message);

        // 4. Vérifier la signature
        let verify_result = vk.verify(message, &signature);
        assert!(
            verify_result.is_ok(),
            "Signature verification failed: {:?}",
            verify_result.err()
        );

        // 5. Vérifier avec un message modifié
        let modified_message = b"Modified test message for Signum key service";
        let verify_modified = vk.verify(modified_message, &signature);
        assert!(
            verify_modified.is_err(),
            "Verification with modified message should fail"
        );
    }

    #[test]
    fn test_key_isolation_between_users() {
        let config = setup_test_config().expect("Failed to setup test config");
        let fs = FileSystemAdapter::new();
        let key_service = KeyService::new(fs, config.clone());

        // Créer deux utilisateurs
        let (user1, mut password1) = create_test_user();

        let mut user2 = user1.clone();
        user2.name = UserName::new("otheruser").unwrap();
        let mut password2 = password1.clone();

        // Générer des clés pour les deux utilisateurs
        key_service
            .generate_user_keys(&user1, &mut password1)
            .expect("Failed to generate keys for user1");
        key_service
            .generate_user_keys(&user2, &mut password2)
            .expect("Failed to generate keys for user2");

        let mut password1 = "Str0ng@P4ssw0rd1234".to_string();
        let mut password2 = password1.clone();

        // Charger les clés des deux utilisateurs
        let sk1 = key_service
            .load_signing_key(&user1, &mut password1)
            .expect("Failed to load user1 signing key");
        let sk2 = key_service
            .load_signing_key(&user2, &mut password2)
            .expect("Failed to load user2 signing key");

        // Vérifier que les clés sont différentes
        assert_ne!(
            sk1.to_bytes(),
            sk2.to_bytes(),
            "Different users should have different keys"
        );
        let mut password2 = "D1ff3r3nt@P4ssw0rd5678".to_string(); // Mot de passe réellement différent
        let cross_load: Result<SigningKey, AppError> =
            key_service.load_signing_key(&user1, &mut password2);
        assert!(
            cross_load.is_err(),
            "Loading user1's key with user2's password should fail"
        );
    }

    #[test]
    fn test_encryption_decryption() {
        // Créer une clé de test
        let key = [42u8; 32]; // Clé simple pour le test

        // Données à chiffrer (taille d'une clé Ed25519)
        let original_data = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];

        // Chiffrer les données
        let encrypted = encrypt_data(&original_data, &key).expect("Encryption failed");
        println!("Encrypted data length: {}", encrypted.len());

        // Déchiffrer les données
        let decrypted = decrypt_data(&encrypted, &key).expect("Decryption failed");
        println!("Decrypted data length: {}", decrypted.len());

        // Vérifier que les données déchiffrées correspondent aux originales
        assert_eq!(decrypted.len(), original_data.len());
        assert_eq!(decrypted, original_data);
    }
}
