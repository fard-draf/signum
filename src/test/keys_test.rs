#[cfg(test)]
mod tests {
    use std::{fs, path::Path};
    use zeroize::Zeroize;

    use crate::{
        core::{
            crypto::sym::{decrypt_data, derive_key_from_password, encrypt_data},
            keys::keypair::generate_keypair,
        },
        domain::user::{
            entities::{User, UserName},
            file_path::UserFilePath,
            passwords::UserPassword,
        },
        error::AppError,
    };
    use argon2::password_hash::SaltString;
    use ed25519_dalek::{SigningKey, Verifier, VerifyingKey, ed25519::signature::SignerMut};
    use rand_core::OsRng;

    // Fonction utilitaire pour créer un utilisateur de test
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

    // Fonction utilitaire pour nettoyer les fichiers de test
    fn cleanup_test_files(base_name: &str) {
        let paths = [
            format!("{}.sk.encr", base_name),
            format!("{}.vk", base_name),
        ];

        for path in paths.iter() {
            if Path::new(path).exists() {
                let _ = fs::remove_file(path);
            }
        }
    }

    // Fonction pour sauvegarder une clé de signature chiffrée
fn save_signing_key_encrypted(
    key: &SigningKey,
    path: &str,
    user: &User,
    password: &str,
) -> Result<(), AppError> {
    let mut pw = password.to_string();
    let mut encryption_key = derive_key_from_password(&mut pw, user)?;

    // Chiffrer et sauvegarder la clé
    let mut key_bytes = key.to_bytes();
    let encrypted = encrypt_data(&key_bytes, &encryption_key)?;
    fs::write(path, &encrypted).map_err(|e| AppError::IO(crate::error::ErrIO::IoError(e)))?;

        // Nettoyer les données sensibles
        key_bytes.zeroize();
        encryption_key.zeroize();

        Ok(())
    }

    // Fonction pour charger une clé de signature chiffrée
fn load_signing_key_encrypted(
    path: &str,
    user: &User,
    password: &str,
) -> Result<SigningKey, AppError> {
    let mut pw = password.to_string();
    let mut encryption_key = derive_key_from_password(&mut pw, user)?;

        // Lire et déchiffrer la clé
        let encrypted =
            fs::read(path).map_err(|e| AppError::IO(crate::error::ErrIO::IoError(e)))?;
        let mut decrypted = decrypt_data(&encrypted, &encryption_key)?;

        // Convertir en SigningKey
        let raw: [u8; 32] = decrypted
            .as_slice()
            .try_into()
            .map_err(|_| AppError::Encrypt(crate::error::ErrEncrypt::InvalidKey))?;
        let key = SigningKey::from_bytes(&raw);

        // Nettoyer les données sensibles
        decrypted.zeroize();
        encryption_key.zeroize();

        Ok(key)
    }

    // Fonction pour sauvegarder une clé de vérification
    fn save_verifying_key(key: &VerifyingKey, path: &str) -> Result<(), AppError> {
        use base64::{Engine as _, engine::general_purpose};
        let encoded = general_purpose::STANDARD.encode(key.to_bytes());
        fs::write(path, encoded).map_err(|e| AppError::IO(crate::error::ErrIO::IoError(e)))
    }

    // Fonction pour charger une clé de vérification
    fn load_verifying_key(path: &str) -> Result<VerifyingKey, AppError> {
        use base64::{Engine as _, engine::general_purpose};
        let encoded =
            fs::read_to_string(path).map_err(|e| AppError::IO(crate::error::ErrIO::IoError(e)))?;
        let bytes = general_purpose::STANDARD
            .decode(encoded.trim())
            .map_err(|e| AppError::Base64(crate::error::ErrBase64::DecodeError(e)))?;

        VerifyingKey::from_bytes(&bytes.try_into().map_err(|_| AppError::Error)?)
            .map_err(|_| AppError::Error)
    }

    #[test]
    fn test_generate_keypair() {
        // Générer une paire de clés
        let (mut sk, vk) = generate_keypair();

        // Vérifier que les clés ne sont pas nulles
        assert!(!sk.to_bytes().iter().all(|&b| b == 0));
        assert!(!vk.to_bytes().iter().all(|&b| b == 0));

        // Tester la signature et la vérification
        let message = b"Test message for signature verification";
        let signature = sk.sign(message);
        assert!(vk.verify(message, &signature).is_ok());

        // Tester avec un message modifié (la vérification devrait échouer)
        let wrong_message = b"Modified message for signature verification";
        assert!(vk.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_save_and_load_encrypted_signing_key() {
        let base_name = "test_signing_key";
        let sk_path = format!("{}.sk.enc", base_name);
        cleanup_test_files(base_name);

        // Créer un utilisateur de test
        let (user, mut password) = create_test_user();

        // Générer une clé de signature
        let original_key = SigningKey::generate(&mut OsRng);

        // Sauvegarder la clé de manière chiffrée avec les informations utilisateur
        save_signing_key_encrypted(&original_key, &sk_path, &user, &password)
            .expect("Failed to save encrypted signing key");

        // Charger la clé chiffrée en dérivant la clé d'encryption à partir des mêmes informations
        let loaded_key = load_signing_key_encrypted(&sk_path, &user, &password)
            .expect("Failed to load encrypted signing key");

        // Vérifier que les clés sont identiques
        assert_eq!(original_key.to_bytes(), loaded_key.to_bytes());

        // Tester avec un mauvais mot de passe
        let mut wrong_password = "Wr0ng@P4ssw0rd5678".to_string();
        let result = load_signing_key_encrypted(&sk_path, &user, &wrong_password);
        assert!(result.is_err(), "Loading with wrong password should fail");

        // Nettoyer
        cleanup_test_files(base_name);
    }

    #[test]
    fn test_save_and_load_verifying_key() {
        let base_name = "test_verifying_key";
        let vk_path = format!("{}.vk", base_name);
        cleanup_test_files(base_name);

        // Générer une paire de clés
        let (mut sk, original_vk) = generate_keypair();

        // Sauvegarder la clé de vérification
        save_verifying_key(&original_vk, &vk_path).expect("Failed to save verifying key");

        // Charger la clé de vérification
        let loaded_vk = load_verifying_key(&vk_path).expect("Failed to load verifying key");

        // Vérifier que les clés sont identiques
        assert_eq!(original_vk.to_bytes(), loaded_vk.to_bytes());

        // Test de signature/vérification avec la clé chargée
        let message = b"Test message for verification with loaded key";
        let signature = sk.sign(message);
        assert!(loaded_vk.verify(message, &signature).is_ok());

        // Nettoyer
        cleanup_test_files(base_name);
    }

    #[test]
    fn test_complete_signing_and_verification_workflow() {
        let base_name = "test_complete_workflow";
        let sk_path = format!("{}.sk.enc", base_name);
        let vk_path = format!("{}.vk", base_name);
        cleanup_test_files(base_name);

        // 1. Créer un utilisateur de test
        let (user, mut password) = create_test_user();

        // 2. Générer une paire de clés
        let (mut sk, vk) = generate_keypair();

        // 3. Sauvegarder les clés
        save_signing_key_encrypted(&sk, &sk_path, &user, &mut password)
            .expect("Failed to save signing key");
        save_verifying_key(&vk, &vk_path).expect("Failed to save verifying key");

        // 4. Message à signer
        let message = b"This is a test message for the complete workflow";

        // 5. Signer le message avec la clé privée originale
        let original_signature = sk.sign(message);

        // 6. Simuler une déconnexion puis reconnexion (recharger la clé privée)
        let mut loaded_sk = load_signing_key_encrypted(&sk_path, &user, &password)
            .expect("Failed to load signing key");
        let loaded_signature = loaded_sk.sign(message);

        // 7. Vérifier que les deux signatures sont identiques
        assert_eq!(original_signature.to_bytes(), loaded_signature.to_bytes());

        // 8. Charger la clé publique et vérifier la signature
        let loaded_vk = load_verifying_key(&vk_path).expect("Failed to load verifying key");
        assert!(loaded_vk.verify(message, &original_signature).is_ok());
        assert!(loaded_vk.verify(message, &loaded_signature).is_ok());

        // 9. Vérifier qu'une signature incorrecte est rejetée
        let wrong_message = b"This is a different message";
        let wrong_signature = sk.sign(wrong_message);
        assert!(loaded_vk.verify(message, &wrong_signature).is_err());

        // 10. Nettoyer
        cleanup_test_files(base_name);
    }

    #[test]
    fn test_user_specific_keys() {
        let base_name = "test_user_specific";
        let sk_path = format!("{}.sk.enc", base_name);
        cleanup_test_files(base_name);

        // Créer deux utilisateurs différents
        let (user1, mut password1) = create_test_user();

        let mut user2 = user1.clone();
        user2.name = UserName::new("otheruser").unwrap();
        // Même mot de passe mais sel différent
        user2.user_salt = SaltString::generate(&mut OsRng).to_string();
        let mut password2 = password1.clone();

        // Générer une clé de signature
        let original_key = SigningKey::generate(&mut OsRng);

        // Sauvegarder la clé avec les informations du premier utilisateur
        save_signing_key_encrypted(&original_key, &sk_path, &user1, &mut password1)
            .expect("Failed to save encrypted signing key");

        // Essayer de charger avec le second utilisateur (même mot de passe, sel différent)
        // Cela devrait échouer car la clé dérivée sera différente
        let result = load_signing_key_encrypted(&sk_path, &user2, &password2);
        assert!(
            result.is_err(),
            "Loading with different salt should fail even with same password"
        );

        // Nettoyer
        cleanup_test_files(base_name);
    }
}
