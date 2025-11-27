#[cfg(test)]
mod tests {
    use crate::core::crypto::sym::derive_key_from_password;
    use crate::domain::user::{
        entities::{User, UserName},
        file_path::UserFilePath,
        passwords::UserPassword,
    };
    use argon2::password_hash::SaltString;

    #[test]
    fn test_derive_key_from_password() {
        let password = "S3cur3P@ssw0rd!1998".to_string();
        let salt = SaltString::from_b64("w7dVt97tCz9S2cXqP+6s2Q").unwrap();

        let user = User {
            name: UserName::new("alice").unwrap(),
            password: UserPassword::from_raw(&password).unwrap(),
            file_path: UserFilePath::from_path("dummy_path".to_string()).unwrap(),
            user_salt: salt.to_string(),
        };

        let mut pw1 = password.clone();
        let mut pw2 = password.clone();
        let key1 = derive_key_from_password(&mut pw1, &user).expect("derivation failed");
        let key2 = derive_key_from_password(&mut pw2, &user).expect("derivation failed");

        assert_eq!(key1.len(), 32);
        assert_eq!(key1, key2);
        assert_ne!(key1, [0u8; 32]);
        assert!(key1.iter().any(|&b| b != 0));
    }
}
