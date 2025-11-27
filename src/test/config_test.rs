#[cfg(test)]
mod tests {
    use std::{
        env,
        fs,
        path::PathBuf,
        sync::{Mutex, OnceLock},
    };

    use crate::domain::ports::config::AppConfig;

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn lock_env<'a>() -> std::sync::MutexGuard<'a, ()> {
        ENV_LOCK.get_or_init(|| Mutex::new(())).lock().expect("lock poisoned")
    }

    #[test]
    fn uses_env_data_dir_when_set() {
        let _guard = lock_env();
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");

        unsafe {
            env::set_var("SIGNUM_DATA_DIR", temp_dir.path());
            env::remove_var("SIGNUM_PORTABLE");
        }

        let config = AppConfig::new(None).expect("Failed to build config with env dir");

        unsafe {
            env::remove_var("SIGNUM_DATA_DIR");
        }

        let expected = PathBuf::from(temp_dir.path()).join("Signum");
        assert_eq!(config.base_directory, expected);
    }

    #[test]
    fn uses_portable_dir_when_flag_enabled() {
        let _guard = lock_env();
        unsafe {
            env::remove_var("SIGNUM_DATA_DIR");
            env::set_var("SIGNUM_PORTABLE", "1");
        }

        let config = AppConfig::new(None).expect("Failed to build config with portable flag");

        unsafe {
            env::remove_var("SIGNUM_PORTABLE");
        }

        let exe_dir = env::current_exe().expect("Failed to get current exe");
        let expected = exe_dir
            .parent()
            .expect("Exe has no parent directory")
            .join("signum-data")
            .join("Signum");
        assert_eq!(config.base_directory, expected);

        let _ = fs::remove_dir_all(expected);
    }
}
