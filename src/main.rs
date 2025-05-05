use signum::application::auth_service::AuthService;
use signum::domain::ports::config::AppConfig;
use signum::error::AppError;
use signum::infra::file_system::FileSystemAdapter;
use signum::infra::user_repo::UserFileRepository;

fn main() -> Result<(), AppError> {
    let config = AppConfig::new(None)?;

    let fs_adapter = FileSystemAdapter::new();

    let user_repository = UserFileRepository::new(fs_adapter.clone(), config.clone());

    let auth_service = AuthService::new(user_repository, fs_adapter, config);

    Ok(())
}
