use crate::domain::user::entities::{User, UserName};
use crate::error::AppError;

pub trait UserRepository {
    fn save(&self, user: &User, key: &[u8; 32]) -> Result<(), AppError>;
    fn load(&self, username: &UserName, key: &[u8; 32]) -> Result<User, AppError>;
    fn exists(&self, username: &UserName) -> Result<bool, AppError>;
}
