use signum::cli::app::SignumCli;
use signum::tracing::init_logging;

fn main() {
    // Initialiser le logging
    init_logging();

    // Initialiser le CLI
    match SignumCli::new() {
        Ok(cli) => {
            if let Err(e) = cli.run() {
                eprintln!("Erreur: {:?}", e);
            }
        }
        Err(e) => {
            eprintln!("Erreur lors de l'initialisation: {:?}", e);
        }
    }
}
