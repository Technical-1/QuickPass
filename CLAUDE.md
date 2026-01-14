# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

QuickPass is a Rust-based desktop password manager with a GUI built on eframe/egui. It supports multiple encrypted vaults, password generation, and dual authentication (master password + pattern lock).

## Build Commands

```bash
cargo build              # Development build
cargo build --release    # Release build
cargo run                # Run the application
cargo test               # Run tests (currently only password module has tests)
```

## Architecture

### Core Modules

- **app.rs** - Main GUI application (`QuickPassApp` struct implementing eframe's `App` trait). Contains all UI screens: vault manager, login, initial creation, and main vault view.

- **vault.rs** - Encryption/decryption layer using AES-256-GCM. Handles:
  - `EncryptedVaultFile` - On-disk format with master hash, pattern hash, encrypted vault key (twice, once per auth method), and encrypted vault data
  - The vault key is randomly generated and encrypted under both master password and pattern for dual-unlock capability
  - `VaultData` contains entries and metadata (last accessed timestamp)

- **security.rs** - Argon2id configuration with three security levels (Low/Medium/High) affecting memory cost and iterations. Contains global salt for password hashing.

- **password.rs** - Password generation and entropy estimation. Supports configurable character sets (lowercase, uppercase, digits, symbols).

- **manager.rs** - Vault file management. Vaults stored in platform-specific data directory (`ProjectDirs::from("com", "KANFER", "QuickPass")`). Files named `encrypted_vault_{name}.json`.

### Security Model

1. **Dual Authentication**: Users can unlock vaults via master password OR a 6x6 grid pattern (8+ clicks required)
2. **Key Derivation**: Argon2id with configurable security levels (16MB/32MB/64MB memory)
3. **Encryption**: AES-256-GCM for both vault key wrapping and vault data encryption
4. **Brute-force Protection**: Vault is deleted after 3 failed login attempts
5. **Memory Safety**: Sensitive fields use `zeroize` crate for secure memory clearing on drop

### Data Flow

1. On vault creation: random 32-byte vault key generated, encrypted twice (under password and pattern), stored with Argon2 hashes
2. On login: password/pattern verified against stored hash, then used to decrypt vault key, then vault key decrypts vault data
3. Vault file is base64-encoded JSON containing all encrypted components

### UI States

The app cycles through these screens based on state:
- Vault Manager (select/create vaults)
- Initial Creation (new vault setup with security level, password, pattern)
- Login (password or pattern entry)
- Main UI (password generation, vault entries, settings)
