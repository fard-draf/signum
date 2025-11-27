# Signum – Guide utilisateur (FR)

Ce guide explique, pas à pas, comment chiffrer et déchiffrer vos fichiers ou dossiers avec Signum. Aucun prérequis crypto n’est nécessaire.

## 1. Installer et lancer
- Assurez-vous d’avoir Rust/Cargo installé.
- Dans le dossier du projet : `cargo run --release`.
- Suivez le menu interactif qui s’affiche dans le terminal.
- **Mode portable (clé USB)** : au premier lancement, choisissez `OFFICE` (chemins système classiques) ou `NOMADE` (portable). Le choix est sauvegardé dans `signum.conf` à côté du binaire (surchargable via `SIGNUM_CONFIG_PATH`). En `NOMADE`, Signum force `SIGNUM_PORTABLE=1` et stocke dans `signum-data/Signum` à côté du binaire. Vous pouvez lancer directement via `run_signum.sh` (Unix/macOS) ou `Signum-portable.bat` (Windows) placés à côté du binaire, sans `./signum`. Sans ces variables, le comportement par défaut (XDG/AppData/Home) est conservé.

## 2. Créer un compte (Inscription)
1) Choisissez « Inscription ».
2) Entrez un nom d’utilisateur (lettres uniquement, 3–16 caractères).
3) Entrez un mot de passe fort (majuscules, minuscules, chiffres, caractères spéciaux). Conservez-le en lieu sûr : il protège vos clés.
4) Signum crée et chiffre vos clés ; tout est stocké sous `~/.local/share/Signum/users/<votre_nom>/` (permissions privées par défaut).

## 3. Se connecter (Connexion)
1) Choisissez « Connexion ».
2) Saisissez votre nom d’utilisateur et votre mot de passe.
3) Une fois connecté, vous accédez aux actions : signer, vérifier, chiffrer/déchiffrer un fichier ou un répertoire.

## 4. Chiffrer un fichier
1) Choisissez « Chiffrer un fichier ».
2) Entrez le chemin du fichier (ex. `/home/user/document.pdf`).
3) Par défaut, le fichier chiffré remplace l’original (in-place). Spécifiez un chemin de sortie personnalisé si vous souhaitez conserver l’original.
4) Le chiffrement est lié au chemin du fichier chiffré : si vous déplacez ou renommez le fichier chiffré, le déchiffrement échouera tant que vous ne le remettez pas au chemin d’origine.

## 5. Déchiffrer un fichier
1) Choisissez « Déchiffrer un fichier ».
2) Entrez le chemin du fichier chiffré (ex. `document.pdf.enc`).
3) Laissez le chemin de sortie vide pour obtenir `document.pdf`, ou fournissez un autre nom.
4) Le déchiffrement échoue si le mot de passe est incorrect ou si le fichier a été altéré.

## 6. Chiffrer/Déchiffrer un répertoire
1) « Chiffrer un répertoire » : entrez le chemin d’un dossier. Par défaut, le dossier est remplacé par sa version chiffrée (les fichiers deviennent `*.enc` dans le même dossier). Fournissez un chemin de sortie pour conserver l’original.
2) « Déchiffrer un répertoire » : pointez sur le dossier chiffré. Par défaut, il est remplacé par sa version déchiffrée ; vous pouvez donner un chemin de sortie pour éviter d’écraser la version chiffrée.

## 7. Signer / Vérifier
- « Signer un fichier » : fournit un `.sig` (Base64) à côté du fichier (ou à un chemin choisi).
- « Vérifier une signature » : indiquez le fichier original et son `.sig`. Signum utilise votre clé publique pour vérifier l’authenticité.

## 8. Bonnes pratiques simples
- **Mot de passe** : gardez-le secret et suffisamment long. Sans lui, vos clés privées restent inaccessibles.
- **Sauvegarde clé publique** : le fichier `verifying_key.vk` dans votre dossier utilisateur peut être copié en lieu sûr (il ne divulgue pas votre secret).
- **Déplacements** : les dossiers chiffrés (`.enc`) peuvent être déplacés en bloc. Les fichiers chiffrés individuels doivent rester au même chemin qu’au moment du chiffrement (sinon, remettez-les temporairement à ce chemin pour déchiffrer).
- **Permissions** : les fichiers Signum sont créés en privé (0700/0600). Évitez d’utiliser des machines non fiables.

---

# Signum – User Guide (EN)

This guide explains, step by step, how to encrypt and decrypt your files or folders with Signum. No crypto background needed.

## 1. Install and run
- Ensure Rust/Cargo is installed.
- In the project folder: `cargo run --release`.
- Follow the interactive menu in the terminal.
- **Portable mode (USB)**: on first launch choose `OFFICE` (standard OS paths) or `NOMADE` (portable). The choice is stored in `signum.conf` next to the binary (override via `SIGNUM_CONFIG_PATH`). In `NOMADE`, Signum forces `SIGNUM_PORTABLE=1` and stores under `signum-data/Signum` next to the binary. You can launch via `run_signum.sh` (Unix/macOS) or `Signum-portable.bat` (Windows) placed next to the binary; no `./signum` needed. Without these variables, default XDG/AppData/Home paths are used.

## 2. Create an account (Registration)
1) Choose “Inscription”.
2) Enter a username (letters only, 3–16 chars).
3) Enter a strong password (upper/lowercase, digits, special chars). Keep it safe: it protects your keys.
4) Signum creates and encrypts your keys; everything is stored under `~/.local/share/Signum/users/<your_name>/` with private permissions.

## 3. Log in (Connexion)
1) Choose “Connexion”.
2) Enter your username and password.
3) After login, you can sign, verify, encrypt/decrypt a file or a directory.

## 4. Encrypt a file
1) Choose “Encrypt a file”.
2) Enter the file path (e.g. `/home/user/document.pdf`).
3) By default the encrypted file replaces the original (in-place). Provide a custom output path if you want to keep the original.
4) Encryption binds to the ciphertext path: if you move or rename the encrypted file, decryption will fail until you put it back at its original path.

## 5. Decrypt a file
1) Choose “Déchiffrer un fichier”.
2) Enter the encrypted file path (e.g. `document.pdf.enc`).
3) Leave output empty to get `document.pdf`, or set a different name.
4) Decryption fails if the password is wrong or if the file was tampered with.

## 6. Encrypt/Decrypt a directory
1) “Encrypt a directory”: point to a folder. By default the folder is replaced by its encrypted version (files become `*.enc` in the same folder). Provide a custom output path if you need to keep the original.
2) “Decrypt a directory”: point to the encrypted folder. By default it is replaced by the decrypted version; provide a custom output path to avoid overwriting the encrypted folder.

## 7. Sign / Verify
- “Signer un fichier”: produces a `.sig` (Base64) next to the file (or at a custom path).
- “Vérifier une signature”: provide the original file and its `.sig`. Signum uses your public key to verify authenticity.

## 8. Simple best practices
- **Password**: keep it secret and long enough. Without it, your private keys remain inaccessible.
- **Backup public key**: the `verifying_key.vk` file in your user folder can be copied safely (it does not expose your secret).
- **Moving data**: encrypted directories (`.enc`) can be moved as a whole. Single encrypted files must stay at the same path they were produced at (or be put back there for decryption).
- **Permissions**: Signum creates private files (0700/0600). Avoid using untrusted machines.
