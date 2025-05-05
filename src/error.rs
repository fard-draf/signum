use argon2::password_hash;
use ed25519_dalek::SignatureError as DalekSignatureError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error(transparent)]
    User(#[from] ErrUser),

    #[error(transparent)]
    Password(#[from] ErrPassword),

    #[error(transparent)]
    RandCore(#[from] ErrRandCore),

    #[error(transparent)]
    Base64(#[from] ErrBase64),

    #[error(transparent)]
    Path(#[from] ErrPath),

    #[error(transparent)]
    Cypher(#[from] ErrCypher),

    #[error(transparent)]
    IO(#[from] ErrIO),

    #[error(transparent)]
    Dalek(#[from] ErrDalek),

    #[error(transparent)]
    Inquire(#[from] ErrInquire),

    #[error(transparent)]
    Argon2(#[from] ErrArgon2),

    #[error("Unknown fatal error")]
    Error,
}

// --- sous-enums spécifiques ---

#[derive(Debug, Error)]
pub enum ErrUser {
    #[error("Username is too short")]
    InvalidNameTooShort,

    #[error("Username is too long")]
    InvalidNameTooLong,

    #[error("User already exists")]
    AlreadyExist,

    #[error("User not found")]
    UserNotFound,

    #[error("Invalid characters")]
    InvalidCharacters,
}

#[derive(Debug, Error)]
pub enum ErrPassword {
    #[error("Password is too short")]
    PasswordTooShort,

    #[error("Password is too long")]
    PasswordTooLong,

    #[error("Password is to weak")]
    PasswordTooWeak,

    #[error("Invalid characters")]
    InvalidCharacters,

    #[error("Missing special characters")]
    MissingSpecialCharacters,

    #[error("Not enought digits")]
    NotEnoughtDigits,

    #[error("Unvalid password")]
    InvalidPassword,
}

#[derive(Debug, Error)]
pub enum ErrRandCore {
    #[error("RandCore error: {0}")]
    RandCoreError(#[from] rand_core::Error),
}

#[derive(Debug, Error)]
pub enum ErrBase64 {
    #[error("Base64 decode error: {0}")]
    DecodeError(#[from] base64::DecodeError),
}

#[derive(Debug, Error)]
pub enum ErrPath {
    #[error("Invalid path")]
    InvalidPath,

    #[error("Forbidden characters")]
    ForbiddenCharacters,

    #[error("Directory not found")]
    DirectoryNotFound,

    #[error("Failed to create directory")]
    DirectoryCreationFailed,

    #[error("Path traversal detected")]
    PathTraversal,

    #[error("Empty filename")]
    EmptyFilename,

    #[error("Access denied")]
    AccessDenied,

    #[error("Read Error")]
    ReadError,

    #[error("Write Error")]
    WriteError,

    #[error("Failed to change permissions")]
    PermissionChangeFailed,

    #[error("Relative path not allowed")]
    RelativePath,

    #[error("File not found")]
    FileNotFound,
}

#[derive(Debug, Error)]
pub enum ErrCypher {
    #[error("Invalid key")]
    InvalidKey,

    #[error("Invalid key length")]
    KeyLength,

    #[error("Invalid salt")]
    InvalidSalt,

    #[error("Missing hash")]
    MissingHash,

    #[error("Borsh error")]
    BorshError,

    #[error("Write error")]
    WriteError,

    #[error("Read error")]
    ReadError,

    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Invalid data")]
    InvalidData,
}

#[derive(Debug, Error)]
pub enum ErrIO {
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

#[derive(Debug, Error)]
pub enum ErrDalek {
    #[error("Signature error: {0}")]
    Signature(#[from] DalekSignatureError),
}

#[derive(Debug, Error)]
pub enum ErrInquire {
    #[error("Inquire error: {0}")]
    InquireError(#[from] inquire::error::InquireError),
}

#[derive(Debug, Error)]
pub enum ErrArgon2 {
    #[error("Argon2 error")]
    ArgErr(argon2::Error),

    #[error("Password hash error")]
    PasswordHashError(password_hash::Error),

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Unable to verify password")]
    UnableToVerifyPassword,
}
