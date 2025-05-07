// Fichier src/test/auth_service_test.rs
#[cfg(test)]
mod tests {
    use ed25519_dalek::ed25519::signature::SignerMut;
    use log::info;
    use std::path::PathBuf;
    use zeroize::Zeroize;

    use crate::{
        application::{auth_service::AuthService, key_service::KeyService},
        domain::{ports::config::AppConfig, user::file_path::UserFilePath},
        error::AppError,
        infra::{file_system::FileSystemAdapter, user_repo::UserFileRepository},
        tracing::init_logging,
    };

    fn init() {
        let _ = init_logging();
    }

    fn setup_test_env() -> (
        AuthService<UserFileRepository<FileSystemAdapter>, FileSystemAdapter>,
        PathBuf,
    ) {
        let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");
        let temp_path = temp_dir.path().to_owned();
        let custom_base_dir = Some(temp_path.clone());
        let config = AppConfig::new(custom_base_dir).expect("Failed to create config");

        let fs_adapter = FileSystemAdapter::new();
        let user_repository = UserFileRepository::new(fs_adapter.clone(), config.clone());
        let key_service = KeyService::new(fs_adapter.clone(), config.clone());

        let auth_service = AuthService::new(user_repository, fs_adapter, config, key_service);
        let test_dir = temp_dir.path().join("user_data");
        std::fs::create_dir_all(&test_dir).expect("Failed to create test directory");
        (auth_service, temp_path)
    }

    #[test]
    fn test_register_user_with_keys() {
        init();
        let (auth_service, temp_path) = setup_test_env();

        let file_path = temp_path.join("workflow_test_data.sgm");
        let mut path = file_path.to_string_lossy().into_owned();

        let username = "testuser";
        let mut password = String::from("Str0ng@P4ssw0rd1234");

        // Enregistrer l'utilisateur
        let result = auth_service.register(username, &mut password, &mut path);
        assert!(
            result.is_ok(),
            "User registration failed: {:?}",
            result.err()
        );

        let (user, mut signing_key) = result.unwrap();

        assert_eq!(user.name.name, "testuser");

        let message = b"Test message for registration";
        let signature = signing_key.sign(message);
        let verify_result = signing_key
            .verifying_key()
            .verify_strict(message, &signature);
        assert!(
            verify_result.is_ok(),
            "Signature verification failed: {:?}",
            verify_result.err()
        );
    }

    #[test]
    fn test_login_with_keys() {
        init();
        let (auth_service, temp_path) = setup_test_env();

        let file_path = temp_path.join("workflow_test_data.sgm");
        let mut path = file_path.to_string_lossy().into_owned();
        // D'abord enregistrer un utilisateur
        let username = "logintest";
        let mut password = String::from("Str0ng@P4ssw0rd1234");

        let register_result = auth_service.register(username, &mut password, &mut path);
        assert!(
            register_result.is_ok(),
            "User registration failed: {:?}",
            register_result.err()
        );

        // Maintenant tenter de se connecter
        let mut password2 = String::from("Str0ng@P4ssw0rd1234");
        let login_result = auth_service.login(username, &mut password2);
        assert!(
            login_result.is_ok(),
            "User login failed: {:?}",
            login_result.err()
        );

        let (user, mut signing_key) = login_result.unwrap();

        // Vérifier que l'utilisateur est correctement chargé
        assert_eq!(user.name.name, "logintest");

        // Vérifier que la clé de signature est valide
        let message = b"Test message for login";
        let signature = signing_key.sign(message);
        let verify_result = signing_key.verify(message, &signature);
        assert!(
            verify_result.is_ok(),
            "Signature verification after login failed: {:?}",
            verify_result.err()
        );
    }

    #[test]
    fn test_login_wrong_password() {
        init();
        let (auth_service, temp_path) = setup_test_env();

        let mut path = String::from("workflow_test_data.sgm");

        let username = "wrongpwtest";
        let mut password = String::from("Str0ng@P4ssw0rd1234");

        let register_result = auth_service.register(username, &mut password, &mut path);
        assert!(
            register_result.is_ok(),
            "User registration failed: {:?}",
            register_result.err()
        );

        // Tenter de se connecter avec un mauvais mot de passe
        let mut wrong_password = String::from("Wr0ng@P4ssw0rd5678");
        let login_result = auth_service.login(username, &mut wrong_password);
        assert!(
            login_result.is_err(),
            "Login with wrong password should fail"
        );
    }

    #[test]
    fn test_complete_workflow() {
        init();

        let (auth_service, temp_base_path) = setup_test_env();

        // let file_path = temp_path_path.join("workflow_test_data.sgm");
        // let mut path = file_path.to_string_lossy().into_owned();
        // 1. Enregistrer un utilisateur
        let username = "workflowtest";
        let mut password = String::from("Str0ng@P4ssw0rd1234");

        let mut path = String::from("workflow_test_data.sgm");
        info!("TEST: path: {:?}", path);

        let (user, signing_key) = auth_service
            .register(username, &mut password, &mut path)
            .expect("User registration failed");

        let (user, mut signing_key) = auth_service
            .register(username, &mut password, &mut path)
            .expect("User registration failed");

        // 2. Signer un message
        let message = b"Important workflow test message";
        let signature = signing_key.sign(message);
        let verifying_key = signing_key.verifying_key();

        // 3. Se connecter à nouveau
        let mut password2 = String::from("Str0ng@P4ssw0rd1234");
        let (_, mut loaded_key) = auth_service
            .login(username, &mut password2)
            .expect("User login failed");

        // 4. Vérifier que la clé chargée peut vérifier la signature précédente
        let loaded_vk = loaded_key.verifying_key();
        assert_eq!(
            verifying_key.to_bytes(),
            loaded_vk.to_bytes(),
            "Verifying keys should match"
        );

        let verify_result = loaded_vk.verify_strict(message, &signature);
        assert!(
            verify_result.is_ok(),
            "Signature verification after reconnection failed"
        );

        // 5. Créer une nouvelle signature avec la clé chargée
        let new_message = b"New message after reconnection";
        let new_signature = loaded_key.sign(new_message);

        // 6. Vérifier la nouvelle signature
        let verify_new = loaded_vk.verify_strict(new_message, &new_signature);
        assert!(verify_new.is_ok(), "New signature verification failed");
    }
}
