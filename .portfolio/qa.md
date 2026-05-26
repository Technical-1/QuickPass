# QuickPass - Project Q&A

## Project Overview

QuickPass is a secure, cross-platform desktop password manager I built in Rust. It provides encrypted vault storage for credentials with dual authentication options (master password or visual pattern lock), comprehensive 2FA support, and extensive import/export capabilities for migrating from other password managers.

**Problem Solved:** Users need a trustworthy, offline-first password manager that doesn't require subscription fees or cloud trust. QuickPass provides modern encryption (AES-256-GCM, Argon2id) in a standalone application that keeps all data local.

**Target Users:** Security-conscious individuals who prefer local data storage, users migrating from other password managers (Bitwarden, 1Password, LastPass), and anyone wanting a free, open-source alternative to commercial offerings.

## Key Features

### Encrypted Vault System
Each vault uses AES-256-GCM encryption with per-vault random keys. The vault key itself is encrypted under both the master password and pattern lock, enabling dual-unlock capability while maintaining security.

### Dual Authentication
Users can unlock vaults via traditional master password or a 6x6 visual pattern grid requiring minimum 12 unique cells. This provides approximately 42 bits of entropy while offering an alternative for users who prefer visual/spatial memory.

### Configurable Security Levels
Three Argon2id security tiers (Low/Medium/High) let users balance security against unlock speed. Even the "Low" setting exceeds OWASP recommendations with 19 MiB memory and 3 iterations.

### Brute-Force Protection
Progressive lockout system with exponential backoff (15min -> 30min -> 60min). After 4 lockout periods, the vault is automatically deleted to prevent persistent attacks.

### TOTP/2FA Support
Full two-factor authentication with QR code generation for authenticator app setup. Available both per-entry (for storing 2FA secrets) and vault-level (requiring 2FA to unlock).

### Password Manager Import
Automatic format detection for Bitwarden, 1Password, LastPass, and generic CSV exports. Makes migration seamless for users switching to QuickPass.

### USB Portable Backup
Export encrypted vault backups to removable drives with checksum verification. Enables secure manual sync between devices without cloud services.

### Entropy Game
A Tic-Tac-Toe mini-game that collects user interaction timing and patterns to supplement system RNG for password generation — adding user-contributed randomness.

## Technical Highlights

### Dual-Key Encryption Architecture
Two independent unlock methods (password and pattern) without storing either credential. A random 32-byte vault key is encrypted separately under both credentials and stored as two ciphertexts. Either credential can decrypt the vault key, which then decrypts the actual data. Changing one credential only requires re-encrypting the vault key (32 bytes), not the entire vault. See `src/vault.rs` for the dual-encryption layout.

### Memory-Safe Credential Handling
Passwords in memory are an attack surface. All sensitive buffers (master password, vault key, decrypted entries) use the `zeroize` crate to overwrite memory deterministically on `Drop`, even on panic paths. The pure-Rust pipeline means credentials never cross an FFI or IPC boundary into an unsafe runtime.

### Atomic File Writes
A crash mid-save could corrupt vault files — catastrophic for a password manager. Saves use a write-to-temp + atomic rename pattern, so the vault file on disk is always either the old version or the new version, never partial. Logic lives in `src/manager.rs`.

### Path-Sanitized USB Export
USB backup paths are user-controlled, so the export code (`src/usb_export.rs`) validates mount points, rejects system directories, and blocks `..` traversal before writing. Each export file also carries a SHA-256 checksum so a corrupted backup is detectable at import time.

## Engineering Decisions

### Rust + egui over Electron / Tauri / native toolkits
- **Constraint:** Password managers handle credentials that must not leak via garbage-collected runtimes or FFI buffers, and the app needs to run on Windows, macOS, and Linux from a single codebase.
- **Options:** Electron (familiar UI, JS memory model leaks secrets), Qt/GTK (system deps, inconsistent APIs), Tauri + React (web UI, IPC boundary), pure Rust + egui.
- **Choice:** Pure Rust with eframe/egui — passwords stay inside the Rust runtime end to end.
- **Why:** No FFI boundary means `zeroize` actually clears every copy of a credential. egui's immediate-mode model also keeps GUI state colocated with the underlying types, so I don't need a parallel JS state tree holding decrypted entries. (A Tauri/React variant exists as [QuickPass-v2](https://github.com/Technical-1/QuickPass-v2) for users who want the modern web UI.)

### Argon2id over bcrypt / PBKDF2
- **Constraint:** Need a KDF that resists GPU/ASIC cracking on stolen vault files.
- **Options:** bcrypt (CPU-only, dated), PBKDF2 (no memory hardness), scrypt, Argon2id.
- **Choice:** Argon2id with three configurable cost levels (Low/Medium/High).
- **Why:** Winner of the Password Hashing Competition and current OWASP recommendation. Memory-hard cost (19–64 MiB) makes GPU attacks expensive. Three tiers let the user trade unlock latency vs. attack cost.

### Dual encrypted vault key over single password-derived key
- **Constraint:** Want to support both a master password and a visual pattern as unlock methods, plus allow either to be rotated without re-encrypting the whole vault.
- **Options:** Encrypt the vault data directly under the password-derived key (simpler, but coupling), or use an intermediate random vault key.
- **Choice:** Generate a random 32-byte vault key, encrypt it twice — once under the password-derived key, once under the pattern-derived key.
- **Why:** Rotating a credential only re-encrypts the 32-byte key, not megabytes of entries. Either credential can independently unlock the vault. The two ciphertexts give no information about each other.

### Vault auto-deletion after repeated lockouts
- **Constraint:** Need to bound the lifetime of brute-force attempts against a stolen vault file without trapping a legitimate user behind an indefinite lockout.
- **Options:** Indefinite lockout, manual admin reset, or progressive lockout followed by auto-delete.
- **Choice:** Exponential backoff (15 → 30 → 60 minutes), then delete the vault file after the 4th period.
- **Why:** A real user has plenty of attempts before any data loss; an attacker burns hours per attempt and ends with an empty file rather than an encrypted target they can grind offline. There is no recovery, by design — any back door would be the weakest link.

## Frequently Asked Questions

### Q: How does the dual authentication work without compromising security?
**A:** The vault key is encrypted separately under both credentials using Argon2id-derived keys. Neither credential is stored — only their hashes for verification, plus the two encrypted vault key copies. Knowing one credential doesn't help decrypt the copy encrypted under the other.

### Q: What happens if I forget both my password and pattern?
**A:** The vault is unrecoverable by design. There's no backdoor, no master key, no recovery option. Any recovery mechanism would itself be an attack vector.

### Q: Why no browser integration or autofill?
**A:** Browser extensions significantly increase the attack surface. QuickPass focuses on secure storage and uses clipboard auto-clear (default 30s) for transferring passwords. This is a deliberate trade-off favoring security over convenience.

### Q: How does the lockout system protect against brute force?
**A:** After a configurable number of failed attempts (3–10), the vault locks with exponential backoff (15min, 30min, 60min). After the 4th lockout period, the vault file is deleted. An attacker gets a bounded number of attempts before the target disappears entirely.

### Q: Can I sync vaults between devices?
**A:** Not automatically — this is intentional to avoid cloud dependencies. The USB export feature creates encrypted backup files with SHA-256 checksums that can be manually transferred between devices.

### Q: Is there a version with a modern UI?
**A:** Yes — [QuickPass-v2](https://github.com/Technical-1/QuickPass-v2) is a Tauri v2 + React rewrite. This original version remains the pure-Rust implementation with stronger memory safety guarantees, since credentials never cross an IPC boundary into JavaScript.

### Q: Why is the macOS binary unsigned?
**A:** Apple Developer Program costs $99/year. For an open-source project that isn't monetized, I documented the unsigned-app trust steps for users instead.

### Q: What's the Tic-Tac-Toe game for?
**A:** Entropy collection. User interaction timing and move sequences feed into the password generator to supplement system RNG with user-contributed randomness. It's optional but available for users who want extra entropy.
