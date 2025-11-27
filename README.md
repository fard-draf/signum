# signum (work in progress)

Signum is a command-line tool written in Rust to sign, verify, and encrypt files or directories. It focuses on explicit, auditable cryptographic steps.

## Crypto choices
- Signatures: Ed25519 (ed25519-dalek)
- Symmetric encryption: XChaCha20-Poly1305 (AEAD)
- KDF: Argon2id (default params: m=64 MiB, t=3, p=1)

## Security model (local usage)
- Everything is local: no KMS/TPM/HSM. Secrets are derived from the user password + per-user salt and stored under the app data directory (e.g. `~/.local/share/Signum/users/<name>/`).
- Keys: private signing keys are encrypted with a key derived from the password+salt; public keys are stored with an AEAD tag (integrity) also derived from the password.
- Metadata: user metadata is MACed to detect tampering; encrypted payloads use AEAD with AAD binding to context.
- AAD/path binding: encrypted payloads include AAD with the canonical ciphertext path (files) or the relative path inside an encrypted directory (per entry). Moving/renaming a ciphertext breaks decryption, which is intentional to catch replay/misplacement.
- Permissions: directories 0700, files 0600 (Unix). Ensure the runtime user is the only account allowed to read the Signum data directory.

## Default KDF policy
- Argon2id m=64 MiB, t=3, p=1, output 32 bytes. Override via env: `SIGNUM_KDF_MIB` (memory in MiB), `SIGNUM_KDF_TIME` (iterations), `SIGNUM_KDF_PAR` (lanes). Increase for stronger resistance; lower for constrained devices. Migration/versioning hooks are present; tune as needed for your environment.

## Payload/versioning
- Encrypted blobs carry a version byte (currently `1`) and AAD. Future versions should bump the version and provide migration logic.

## CLI quickstart
- `cargo run --release` then use the interactive menu: register → login → sign/verify/encrypt/decrypt. Directory encryption is supported (recursively) with per-file AEAD and AAD = relative path.
- Default encryption replaces the original file or directory in place; specify a custom output path if you need to keep the clear version.

## Portable / USB usage
- On first launch Signum asks for the operating mode: `OFFICE` (default OS data dirs) or `NOMADE` (portable). The choice is persisted in `signum.conf` next to the binary (override path with `SIGNUM_CONFIG_PATH`).
- In `NOMADE`, Signum forces portable paths (envs `SIGNUM_PORTABLE=1` and `SIGNUM_DATA_DIR` next to the binary in `signum-data/Signum`).
- For double-click/standalone launch from a USB: use `run_signum.sh` (Unix/macOS) or `Signum-portable.bat` (Windows). Place them next to the compiled binary; they honour the stored mode and start Signum without `./signum`.
- Default behaviour remains unchanged (XDG/AppData/Home) when no portable env var is provided.

## Operational recommendations
- Keep logs at `info`/`warn`; decryption integrity failures are emitted at `debug` to avoid noisy logs. Use `RUST_LOG=signum=info` (or `debug` for troubleshooting).
- Back up verifying keys if you expect to rotate passwords; they are currently authenticated with a key derived from the password.
- Document to users that a wrong password will make key loading fail (by design), and that moving ciphertexts requires preserving the bound path.
