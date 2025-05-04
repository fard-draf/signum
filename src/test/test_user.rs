#[cfg(test)]
mod tests {
    use crate::{
        error::{AppError, ErrPassword, ErrPath, ErrUser},
        user::domain::{User, UserFilePath, UserName, UserPassword, UserPubKey},
    };
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    #[test]
    fn test_valid_user_creation() {
        let name = UserName::new("Alice").expect("valid name");
        let password = UserPassword::new("Str0ng!Pass").expect("valid password");
        let file_path = UserFilePath::new("secure_file.txt".to_string()).expect("valid path");
        let signing_key = SigningKey::generate(&mut OsRng);
        let pubkey = UserPubKey::from_key(&signing_key.verifying_key());

        let user = User::new(name, pubkey, password, file_path);
        assert_eq!(user.name.name, "alice");
        assert_eq!(user.file_path.path, "secure_file.txt");
    }

    // USER TEST

    #[test]
    fn test_invalid_username_too_short() {
        let result = UserName::new("Al");
        assert!(matches!(
            result,
            Err(AppError::User(ErrUser::InvalidNameTooShort))
        ));
    }

    #[test]
    fn test_invalid_username_with_numbers() {
        let result = UserName::new("Alice123");
        assert!(matches!(
            result,
            Err(AppError::User(ErrUser::InvalidCharacters))
        ));
    }

    // PASSWORD TEST

    #[test]
    fn test_invalid_password_too_weak() {
        let result = UserPassword::new("passwordpassword");
        assert!(matches!(
            result,
            Err(AppError::Password(ErrPassword::PasswordTooWeak))
        ));
    }

    #[test]
    fn test_password_missing_special_char() {
        let result = UserPassword::new("StrongPassword1945");
        assert!(matches!(
            result,
            Err(AppError::Password(ErrPassword::MissingSpecialCharacters))
        ));
    }

    #[test]
    fn test_password_too_short() {
        let result = UserPassword::new("S!1a");
        assert!(matches!(
            result,
            Err(AppError::Password(ErrPassword::PasswordTooShort))
        ));
    }

    // PATH TEST

    #[test]
    fn test_invalid_file_path_with_space() {
        let result = UserFilePath::new("invalid path.txt".to_string());
        assert!(matches!(
            result,
            Err(AppError::Path(ErrPath::ForbiddenCharacters))
        ));
    }

    #[test]
    fn test_invalid_file_path_with_symbol() {
        let result = UserFilePath::new("bad>path.txt".to_string());
        assert!(matches!(
            result,
            Err(AppError::Path(ErrPath::ForbiddenCharacters))
        ));
    }
}
