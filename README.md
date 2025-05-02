# signum - Work in progress 

Signum is a command-line tool written in Rust to sign, verify, and encrypt files in a modern and understandable way.

It relies on secure and up-to-date cryptographic primitives:

Ed25519 for digital signatures

XChaCha20-Poly1305 for symmetric encryption

Argon2id for key derivation from user passwords

## Why Signum?

Modern cryptographic tools are often either too complex (like GPG) or too limited. Signum offers a minimal, well-structured, and educational alternative that:

Makes cryptographic operations transparent and auditable

Offers an optional --explain mode that helps users understand internal steps (key usage, hash, nonce, etc.)

Includes an interactive CLI powered by inquire to guide users step by step

Signum is ideal for learners in applied cryptography and developers who want to integrate a clean and secure cryptographic core into their projects.

While still under development, Signum is designed to evolve into a trusted base for simple and explicit crypto workflows.

