# QuickPass - Project Q&A

## Project Overview

QuickPass is a secure, cross-platform desktop password manager I built in Rust. It provides encrypted vault storage for credentials with dual authentication options (master password or visual pattern lock), comprehensive 2FA support, and extensive import/export capabilities for migrating from other password managers.

**Problem Solved:** Users need a trustworthy, offline-first password manager that doesn't require subscription fees or cloud trust. QuickPass provides enterprise-grade encryption (AES-256-GCM, Argon2id) in a standalone application that keeps all data local.

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
A Tic-Tac-Toe mini-game that collects user interaction timing and patterns to supplement system RNG for password generation - adding user-contributed randomness.

## Technical Highlights

### Challenge: Dual-Key Encryption Architecture
I needed to support two independent unlock methods (password and pattern) without storing the password or pattern. My solution: generate a random vault key, encrypt it separately under both credentials, and store both encrypted copies. Either credential can decrypt the vault key, which then decrypts the actual data.

### Challenge: Memory-Safe Credential Handling
Passwords in memory are attack vectors. I used the `zeroize` crate to ensure all sensitive data (master password, vault key, decrypted entries) is securely cleared when no longer needed, preventing memory scraping attacks.

### Challenge: Atomic File Operations
A crash during save could corrupt vault files. I implemented atomic writes using temporary files and rename operations - the vault file is always in a valid state, either old or new, never partial.

### Innovative Approach: Visual Pattern Lock
The 6x6 pattern grid provides 36 possible cells. With minimum 12 cells required, this creates meaningful entropy while being more memorable than random characters for some users.

### Comprehensive Test Coverage
Over 100 unit and integration tests covering encryption round-trips, CSV parsing edge cases, security level validation, lockout progression, and more.

## Frequently Asked Questions

### Q: Why build another password manager when established options exist?
**A:** Commercial password managers require trust in their cloud infrastructure and ongoing subscriptions. I wanted a verifiably secure, local-only solution I could audit myself. Open-sourcing it lets others do the same.

### Q: How does the dual authentication work without compromising security?
**A:** The vault key is encrypted separately under both credentials using Argon2id-derived keys. Neither credential is stored - only their hashes for verification and the encrypted vault keys. Knowing one credential doesn't help decrypt the copy encrypted under the other.

### Q: Why Argon2id instead of bcrypt or PBKDF2?
**A:** Argon2id won the Password Hashing Competition specifically for its resistance to GPU and ASIC attacks through memory-hardness. It's the current OWASP recommendation for password hashing.

### Q: What happens if I forget both my password and pattern?
**A:** The vault is unrecoverable by design. There's no backdoor, no master key, no recovery option. This is intentional - any recovery mechanism would be an attack vector.

### Q: Why no browser integration or autofill?
**A:** Browser extensions increase attack surface significantly. QuickPass focuses on secure storage; users copy passwords manually. This is a deliberate tradeoff favoring security over convenience.

### Q: How does the lockout system protect against brute force?
**A:** After configurable failed attempts (3-10), the vault locks with exponential backoff (15min, 30min, 60min). After the 4th lockout period, the vault is deleted. An attacker gets limited attempts before losing access entirely.

### Q: Can I sync vaults between devices?
**A:** Not automatically - this is intentional to avoid cloud dependencies. USB export creates encrypted backup files that can be manually transferred. I may add local network sync in future versions.

### Q: Why is the macOS binary unsigned?
**A:** Apple Developer Program costs $99/year. For an open-source project, I've documented how to allow unsigned apps in macOS security settings instead.

### Q: How do I verify the security of this implementation?
**A:** The codebase is open source with clear module separation. Critical security code is isolated in `security.rs` and `vault.rs` for easy auditing. I've documented all cryptographic choices and their rationale.

### Q: What's the Tic-Tac-Toe game for?
**A:** It's an entropy collection mechanism. User interaction timing and move sequences feed into password generation, supplementing system randomness. It's optional but adds user-contributed entropy for those who want it.
