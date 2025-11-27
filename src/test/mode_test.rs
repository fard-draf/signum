#[cfg(test)]
mod tests {
    use std::{
        env,
        fs,
        path::PathBuf,
        sync::{Mutex, OnceLock},
    };

    use crate::cli::mode::{apply_mode_environment, resolve_mode, RunMode};

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn lock_env<'a>() -> std::sync::MutexGuard<'a, ()> {
        ENV_LOCK.get_or_init(|| Mutex::new(())).lock().expect("lock poisoned")
    }

    fn temp_config_path(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("signum.conf")
    }

    #[test]
    fn resolve_mode_reads_existing_config_without_prompt() {
        let _guard = lock_env();
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let config_path = temp_config_path(&temp_dir);
        fs::write(&config_path, "mode=NOMADE").expect("write config");

        unsafe {
            env::set_var("SIGNUM_CONFIG_PATH", &config_path);
        }

        let mode = resolve_mode().expect("resolve mode");
        assert_eq!(mode, RunMode::Nomade);

        unsafe {
            env::remove_var("SIGNUM_CONFIG_PATH");
            env::remove_var("SIGNUM_PORTABLE");
            env::remove_var("SIGNUM_DATA_DIR");
        }
    }

    #[test]
    fn apply_mode_environment_sets_portable_vars() {
        let _guard = lock_env();
        unsafe {
            env::remove_var("SIGNUM_PORTABLE");
            env::remove_var("SIGNUM_DATA_DIR");
        }

        apply_mode_environment(RunMode::Nomade).expect("apply env");

        assert_eq!(env::var("SIGNUM_PORTABLE").unwrap_or_default(), "1");
        assert!(env::var_os("SIGNUM_DATA_DIR").is_some());

        unsafe {
            env::remove_var("SIGNUM_PORTABLE");
            env::remove_var("SIGNUM_DATA_DIR");
        }
    }
}
