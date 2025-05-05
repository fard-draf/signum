// #[cfg(test)]
// mod tests {
//     use crate::core::crypto::sym::derive_key_from_password;
//     use crate::domain::user::{
//         entities::{User, UserName},
//         file_path::UserFilePath,
//         passwords::UserPassword,
//     };
//     use crate::infra::user_repo::*;
//     use argon2::password_hash::SaltString;

//     #[test]
//     fn test_save_and_load_user_securely() {
//         let password = "S3cur3P@ssw0rd!2024";
//         let salt = SaltString::from_b64("w7dVt97tCz9S2cXqP+6s2Q").unwrap();

//         let user = User {
//             name: UserName::new("alice").unwrap(),
//             password: UserPassword::from_raw(password).unwrap(),
//             file_path: UserFilePath::new("test_user_dsp07hhi.borsh.enc".to_string()).unwrap(),
//             cypher_salt: salt.to_string(),
//         };

//         let mut key = derive_key_from_password(password, &user).expect("Key derivation failed");

//         save(&user, &mut key, &user.file_path).expect("Failed to save user");

//         let bad_password = "S3cur3P@ssw0rd!2025";
//         let key = derive_key_from_password(password, &user).expect("Key derivation failed");
//         let loaded = load_user(&key, &user.file_path).expect("Failed to load user");

//         assert_eq!(user.name, loaded.name);
//         assert_eq!(user.password, loaded.password);

//         let bad_key = derive_key_from_password(bad_password, &user).expect("Key derivation failed");
//         let cant_loaded = load_user(&bad_key, &user.file_path);

//         assert!(cant_loaded.is_err());

//         std::fs::remove_file(&user.file_path.path).unwrap();
//     }
// }
