# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

QuickPass is a pure-Rust desktop password manager with a GUI built on eframe/egui. It supports multiple encrypted vaults, password generation, dual authentication (master password + pattern lock), TOTP 2FA, USB backup, and a Tic-Tac-Toe entropy game. All code is Rust — no JavaScript, no IPC boundary, no garbage-collected runtime touching sensitive data.

## Build Commands

```bash
cargo build              # Development build
cargo build --release    # Release build
cargo run                # Run the application
cargo test               # Run all tests (109 tests: 78 unit + 31 integration)
cargo clippy             # Run linter
```

## Architecture

### Core Modules

- **app.rs** - Main GUI application (`QuickPassApp` struct implementing eframe's `App` trait). Contains all UI screens: vault manager, login, initial creation, main vault view, settings, export/import, USB backup. Monolithic state machine with ~80 fields driving conditional rendering.

- **vault.rs** - Encryption/decryption layer using AES-256-GCM. Handles:
  - `EncryptedVaultFile` - On-disk format with master hash, pattern hash, encrypted vault key (twice, once per auth method), and encrypted vault data
  - The vault key is randomly generated and encrypted under both master password and pattern for dual-unlock capability
  - `VaultData` contains entries, metadata, and custom tags
  - TOTP generation, QR code rendering, vault-level 2FA
  - Import/export: CSV (Bitwarden, 1Password, LastPass, generic) and encrypted backup

- **security.rs** - Argon2id configuration with three security levels (Low/Medium/High) affecting memory cost and iterations. Per-vault random salts.

- **password.rs** - Password generation and entropy estimation. Supports configurable character sets (lowercase, uppercase, digits, symbols). Optional seeded generation via ChaCha20Rng for game entropy.

- **manager.rs** - Vault file management. Vaults stored in platform-specific data directory (`ProjectDirs::from("com", "KANFER", "QuickPass")`). Files named `encrypted_vault_{name}.json`. Path sanitization blocks directory traversal.

- **lockout.rs** - Brute-force protection with configurable max attempts (3-10). Exponential backoff: 15min, 30min, 60min lockouts. Vault deletion after 4th lockout period. State persists across restarts.

- **settings.rs** - Persistent app settings: clipboard clear timeout (10-120s), auto-lock timeout (60-3600s), max failed attempts (3-10). Validates and clamps values to safe ranges.

- **gamification.rs** - Tic-Tac-Toe game for entropy collection. Captures move timing, coordinates, and system time. Outputs SHA-256 hash mixed with system RNG for password generation.

- **usb_export.rs** - USB device detection via `sysinfo`. Encrypted backup export/import with SHA-256 checksum verification. Blocks system directories, validates mount points.

- **build.rs** - Windows build script for icon/manifest resources via `winres`.

### Security Model

1. **Dual Authentication**: Users can unlock vaults via master password OR a 6x6 grid pattern (12+ unique cells required)
2. **Key Derivation**: Argon2id with configurable security levels (19/47/64 MiB memory), all exceeding OWASP minimums
3. **Encryption**: AES-256-GCM for both vault key wrapping and vault data encryption
4. **Brute-force Protection**: Configurable failed attempt threshold with exponential backoff lockouts, eventual vault deletion
5. **Memory Safety**: All sensitive fields use `zeroize` crate for secure memory clearing on Drop
6. **Atomic Writes**: Temp file + rename pattern prevents vault corruption
7. **No Network**: Zero HTTP requests, zero telemetry, completely offline

### Data Flow

1. On vault creation: random 32-byte vault key generated, encrypted twice (under password and pattern), stored with Argon2 hashes
2. On login: password/pattern verified against stored hash, then used to decrypt vault key, then vault key decrypts vault data
3. Vault file is base64-encoded JSON containing all encrypted components
4. All saves use atomic write (write to temp, rename)

### UI States

The app cycles through these screens based on boolean state flags in `QuickPassApp`:
- Vault Manager (select/create/delete vaults)
- Initial Creation (security level, password, pattern, optional entropy game)
- Login (password or pattern entry, 2FA verification, lockout display)
- Main UI (entry list, password generator, settings, export/import, USB backup, tag management, 2FA setup)
