// src/cli/commands.rs
use crate::{
    core::crypto::{
        asym::sign_data,
        sym::{decrypt_data, encrypt_data},
    },
    domain::user::entities::User,
    error::{AppError, ErrIO, ErrPath},
};
use base64::{Engine as _, engine::general_purpose};
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use log::info;
use std::{fs, path::Path};

// Fonction pour signer un fichier
pub fn sign_file(
    signing_key: &SigningKey,
    file_path: &str,
    output_path: Option<&str>,
) -> Result<(), AppError> {
    info!("Signature du fichier: {}", file_path);

    // Vérifier que le fichier existe
    if !Path::new(file_path).exists() {
        return Err(AppError::Path(ErrPath::FileNotFound));
    }

    // Lire le contenu du fichier
    let file_content = fs::read(file_path).map_err(|e| AppError::IO(ErrIO::IoError(e)))?;

    // Signer le fichier
    let signature = sign_data(&file_content, signing_key);

    // Encoder la signature en base64
    let signature_b64 = general_purpose::STANDARD.encode(signature.to_bytes());

    // Déterminer le chemin de sortie
    let output = match output_path {
        Some(path) => path.to_string(),
        None => format!("{}.sig", file_path),
    };

    // Écrire la signature dans le fichier de sortie
    fs::write(&output, signature_b64).map_err(|e| AppError::IO(ErrIO::IoError(e)))?;

    println!("✅ Signature créée et enregistrée dans: {}", output);
    Ok(())
}

// Fonction pour vérifier une signature
pub fn verify_signature(
    file_path: &str,
    signature_path: &str,
    verifying_key: &VerifyingKey,
) -> Result<bool, AppError> {
    info!("Vérification de la signature: {}", signature_path);

    // Vérifier que les fichiers existent
    if !Path::new(file_path).exists() {
        return Err(AppError::Path(ErrPath::FileNotFound));
    }
    if !Path::new(signature_path).exists() {
        return Err(AppError::Path(ErrPath::FileNotFound));
    }

    // Lire le contenu du fichier
    let file_content = fs::read(file_path).map_err(|e| AppError::IO(ErrIO::IoError(e)))?;

    // Lire la signature
    let signature_b64 =
        fs::read_to_string(signature_path).map_err(|e| AppError::IO(ErrIO::IoError(e)))?;

    // Décoder la signature base64
    let signature_bytes = general_purpose::STANDARD
        .decode(signature_b64.trim())
        .map_err(|e| AppError::Base64(crate::error::ErrBase64::DecodeError(e)))?;

    // Convertir en objet Signature
    if signature_bytes.len() != 64 {
        return Err(AppError::Encrypt(crate::error::ErrEncrypt::InvalidData));
    }

    // Corriger cette partie pour créer une Signature à partir des bytes
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&signature_bytes);
    let signature = Signature::from_bytes(&sig_bytes);

    // Vérifier la signature
    match verifying_key.verify(&file_content, &signature) {
        Ok(_) => {
            println!("✅ Signature valide!");
            Ok(true)
        }
        Err(_) => {
            println!("❌ Signature invalide!");
            Ok(false)
        }
    }
}

// Fonction pour chiffrer un fichier
pub fn encrypt_file(
    file_path: &str,
    password: &mut str,
    user: &User,
    output_path: Option<&str>,
) -> Result<(), AppError> {
    info!("Chiffrement du fichier: {}", file_path);

    // Vérifier que le fichier existe
    if !Path::new(file_path).exists() {
        return Err(AppError::Path(ErrPath::FileNotFound));
    }

    // Lire le contenu du fichier
    let file_content = fs::read(file_path).map_err(|e| AppError::IO(ErrIO::IoError(e)))?;

    // Dériver une clé à partir du mot de passe
    let encryption_key = crate::core::crypto::sym::derive_key_from_password(password, user)?;

    // Chiffrer le contenu
    let encrypted = encrypt_data(&file_content, &encryption_key)?;

    // Déterminer le chemin de sortie
    let output = match output_path {
        Some(path) => path.to_string(),
        None => format!("{}.enc", file_path),
    };

    // Écrire les données chiffrées
    fs::write(&output, encrypted).map_err(|e| AppError::IO(ErrIO::IoError(e)))?;

    println!("✅ Fichier chiffré enregistré dans: {}", output);
    Ok(())
}

// Fonction pour déchiffrer un fichier
pub fn decrypt_file(
    file_path: &str,
    password: &mut str,
    user: &User,
    output_path: Option<&str>,
) -> Result<(), AppError> {
    info!("Déchiffrement du fichier: {}", file_path);

    // Vérifier que le fichier existe
    if !Path::new(file_path).exists() {
        return Err(AppError::Path(ErrPath::FileNotFound));
    }

    // Lire le contenu du fichier chiffré
    let encrypted_content = fs::read(file_path).map_err(|e| AppError::IO(ErrIO::IoError(e)))?;

    // Dériver une clé à partir du mot de passe
    let encryption_key = crate::core::crypto::sym::derive_key_from_password(password, user)?;

    // Déchiffrer le contenu
    let decrypted = decrypt_data(&encrypted_content, &encryption_key)?;

    // Déterminer le chemin de sortie
    let default_output = if file_path.ends_with(".enc") {
        file_path[..file_path.len() - 4].to_string()
    } else {
        format!("{}.dec", file_path)
    };

    let output = match output_path {
        Some(path) => path.to_string(),
        None => default_output,
    };

    // Écrire les données déchiffrées
    fs::write(&output, decrypted).map_err(|e| AppError::IO(ErrIO::IoError(e)))?;

    println!("✅ Fichier déchiffré enregistré dans: {}", output);
    Ok(())
}
