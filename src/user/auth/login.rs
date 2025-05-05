use crate::{
    error::{AppError, ErrArgon2, ErrCypher, ErrPassword},
    user::domain::{User, UserName, UserPassword},
};
use borsh::{self, to_vec};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305, Key, Nonce
};
use zeroize::{self, Zeroize};

pub fn create_user_name(raw_name: &mut str) -> Result<UserName, AppError> {
    let user_name = UserName::new(raw_name)?;
    raw_name.zeroize();
    Ok(user_name)
}

pub fn create_password(raw_pw: &mut str) -> Result<UserPassword, AppError> {
    let user_pw = UserPassword::from_raw(raw_pw)?;
    raw_pw.zeroize();
    Ok(user_pw)
}

