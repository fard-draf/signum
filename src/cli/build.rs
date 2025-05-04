// use crate::{
//     cli::state::AppContext,
//     core::{
//         keys_ed25519,
//         keysfiles::load_signing_key_from_file,
//         signer::{self, sign_data},
//         verifier,
//     },
//     error::AppError,
// };
// use inquire::{Select, Text};

// use super::interactive::interactive_generate_key;

// pub fn run_interactive() -> Result<(), AppError> {
//     let mut ctx = AppContext {
//         signing_key_path: None,
//         verifying_key_path: None,
//     };

//     let options = vec![
//         "Generate keys",
//         // "Sign a file",
//         // "Verifying a signature",
//         // "Quit",
//     ];

//     let choice = Select::new("What do you want do to?", options).prompt();

//     match choice {
//         Ok("Generate keys") => {
//             let instance = interactive_generate_key()?;
//             ctx.signing_key_path = instance;
//             println!("{:?}", ctx.signing_key_path)
//         }

//         _ => (),
//         // Ok("Sign a file") => {
//         //     let path = Text::new("What is the path's file?")
//         //         .prompt()
//         //         .map_err(|e| AppError::InquireError(e))?;
//         //     let keys = load_signing_key_from_file(&path)?;
//         //     // sign_data(signing_key, message)
//         // }
//     }

//     Ok(())
// }
