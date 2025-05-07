use ed25519_dalek::ed25519::signature::SignerMut;
use log::info;
use signum::application::auth_service::AuthService;
use signum::application::key_service::{self, KeyService};
use signum::domain::ports::config::AppConfig;
use signum::error::AppError;
use signum::infra::file_system::FileSystemAdapter;
use signum::infra::user_repo::UserFileRepository;
use signum::tracing::init_logging;
use zeroize::Zeroize;

fn main() -> Result<(), AppError> {
    init_logging();
    log::info!("(log) Serveur lancé");
    tracing::info!("(tracing) Application prête");

    // intial setup
    let config = AppConfig::new(None)?;

    let file_path = config.base_directory.join("francois.sgm");
    let mut path = file_path.to_string_lossy().into_owned();

    let fs_adapter = FileSystemAdapter::new();
    let user_repository = UserFileRepository::new(fs_adapter.clone(), config.clone());
    let key_service = KeyService::new(fs_adapter.clone(), config.clone());
    let auth_service = AuthService::new(user_repository, fs_adapter, config, key_service);

    // suscribe
    let username = "francois";
    let mut password = String::from("Monp@ssw0rd1002");

    info!("user loaded");
    // log
    let (user, mut signing_key) = auth_service.register(username, &mut password, &mut path)?;
    println!("Utilisateur inscrit : {}", user.name);
    println!("Clé de signature générée");

    println!("TEMPS 1");

    // connect user
    let mut password = String::from("Monp@ssw0rd1002");
    // let mut password = String::from("Str0ng@P4ssw0rd1234");
    let (logged_user, _loaded_key) = auth_service.login(username, &mut password)?;
    println!("Utilisateur connecté : {}", logged_user.name);
    println!("Clé de signature chargée");

    // test sign
    let message = b"J'irai a la mer demain, pas de panique";
    let signature = signing_key.sign(message);
    let verifying_key = signing_key.verifying_key();

    // verifying key
    match verifying_key.verify_strict(message, &signature) {
        Ok(_) => println!("Signature vérifiée avec succès"),
        Err(_) => println!("Échec de la vérification de signature"),
    }

    Ok(())
}
