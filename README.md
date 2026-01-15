# QuickPass

A secure, cross-platform desktop password manager built in Rust with eframe/egui.

## Features

- **Encrypted Vaults**: AES-256-GCM encryption with per-vault random keys
- **Dual Authentication**: Unlock via master password OR visual pattern lock (6x6 grid)
- **Configurable Security**: Three Argon2id security levels (Low/Medium/High)
- **Password Generation**: Customizable length, character sets, and real-time entropy estimation
- **2FA/TOTP Support**: Generate TOTP codes for entries and enable vault-level 2FA with QR codes
- **Import/Export**: Support for Bitwarden, 1Password, LastPass CSV imports and encrypted backups
- **Auto-Lock**: Configurable inactivity timeout with clipboard auto-clear
- **Brute-Force Protection**: Progressive lockouts with exponential backoff
- **Tags & Search**: Organize entries with custom tags and filter by website/username

## Security Model

### Key Derivation
- **Argon2id** with configurable memory cost:
  - Low: 19 MiB, 3 iterations
  - Medium: 47 MiB, 3 iterations
  - High: 64 MiB, 4 iterations
- Per-vault random salts
- All levels exceed OWASP minimum recommendations

### Encryption
- **AES-256-GCM** authenticated encryption for vault data
- Random 32-byte vault key encrypted under both master password and pattern
- Secure memory clearing via `zeroize` crate
- Atomic file writes to prevent corruption

### Lockout System
- Configurable failed attempt threshold (3-10 attempts)
- Exponential backoff: 15min → 30min → 60min lockouts
- Vault deletion after 4th lockout period
- Lockout state persists across app restarts

### Password Requirements
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- Pattern lock requires minimum 12 unique cells

## Installation

### Pre-built Binaries

Download the latest release for your platform from [GitHub Releases](https://github.com/Technical-1/QuickPass/releases):

| Platform | File | Notes |
|----------|------|-------|
| Windows | `QuickPass-Windows.exe` | Double-click to run |
| Linux | `QuickPass-Linux` | Run `chmod +x QuickPass-Linux` first |
| macOS | `QuickPass-macOS` | See macOS notes below |

#### macOS First Run

macOS may block unsigned applications. To run QuickPass:

1. **Right-click** the binary and select **"Open"**, OR
2. Go to **System Preferences > Security & Privacy > General** and click **"Allow Anyway"**

#### Linux Dependencies

On some Linux distributions, you may need GTK libraries:

```bash
# Ubuntu/Debian
sudo apt install libgtk-3-0

# Fedora
sudo dnf install gtk3
```

### Build from Source

```bash
# Clone the repository
git clone https://github.com/Technical-1/QuickPass.git
cd QuickPass

# Build release version
cargo build --release

# Run the application
./target/release/QuickPass
```

## Usage

### Creating a Vault

1. Launch QuickPass
2. Enter a vault name and click "Create"
3. Choose security level (Low/Medium/High)
4. Set master password (must meet strength requirements)
5. Create pattern lock (minimum 12 unique cells on 6x6 grid)

### Managing Passwords

- **Add Entry**: Fill website, username, generate or enter password, select tags
- **Generate Password**: Configure length and character sets, click "Generate"
- **Edit Entry**: Click "Edit" on any entry to modify
- **Copy to Clipboard**: Click "Copy" - automatically clears after timeout (default 30s)

### Two-Factor Authentication

- **Per-Entry TOTP**: Add TOTP secrets to individual entries
- **Vault-Level 2FA**: Enable in Settings to require TOTP code on vault unlock
- **QR Codes**: Scan generated QR codes with your authenticator app

### Import/Export

- **Import CSV**: Supports Bitwarden, 1Password, LastPass, and generic CSV formats (auto-detected)
- **Import Encrypted Backup**: Restore from previously exported encrypted backup
- **Export CSV**: Export entries to CSV format
- **Export Encrypted Backup**: Create encrypted backup file

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+L` | Lock vault |
| `Ctrl+G` | Generate password |
| `Escape` | Cancel current action |

## Data Storage

Vault files are stored in platform-specific directories:

| Platform | Location |
|----------|----------|
| macOS | `~/Library/Application Support/com.KANFER.QuickPass/` |
| Linux | `~/.local/share/QuickPass/` |
| Windows | `C:\Users\<User>\AppData\Roaming\KANFER\QuickPass\` |

Files:
- `encrypted_vault_{name}.json` - Encrypted vault data
- `{name}.lockout.json` - Lockout state (auto-deleted on successful login)
- `settings.json` - Application settings

## Development

```bash
cargo build              # Development build
cargo build --release    # Release build
cargo test               # Run all tests (100+ tests)
cargo run                # Run the application
cargo clippy             # Run linter
```

### Testing

QuickPass has comprehensive test coverage:

```bash
cargo test                          # Run all tests
cargo test --lib                    # Library tests only
cargo test --test integration_tests # Integration tests only
cargo test -- --nocapture           # Show println! output
cargo test password_tests::         # Run specific module tests
```

**Test Categories:**
- **Unit Tests** (~70 tests): Password generation, entropy calculation, encryption/decryption, validation
- **Integration Tests** (~30 tests): Full workflows, import/export, security features

### Quality Checks

Before submitting PRs, ensure:

```bash
cargo clippy -- -D warnings   # No linter warnings
cargo test                    # All tests pass
cargo build --release         # Release builds successfully
```

## CI/CD Pipeline

QuickPass uses GitHub Actions for automated builds and releases.

### Automated Release Workflow

The CI/CD pipeline automatically:
1. Builds binaries for Windows, Linux, and macOS
2. Runs all tests
3. Creates GitHub Releases with downloadable artifacts

### Triggering a Release

Push a semantic version tag to trigger a release:

```bash
git tag v1.2.0
git push origin v1.2.0
```

### Build Matrix

| Platform | Runner | Binary Size |
|----------|--------|-------------|
| Windows | `windows-latest` | ~8 MB |
| Linux | `ubuntu-latest` | ~6 MB |
| macOS | `macos-latest` | ~7 MB |

### Workflow File

The workflow is defined in `.github/workflows/build.yml` and includes:
- Parallel builds across all platforms
- Artifact upload to GitHub Actions
- Automatic release creation with all binaries

### Project Structure

```
src/
├── main.rs       # Application entry point
├── app.rs        # GUI application and state management
├── vault.rs      # Encryption/decryption and vault operations
├── security.rs   # Argon2id configuration and key derivation
├── password.rs   # Password generation and entropy estimation
├── manager.rs    # Vault file management and sanitization
├── lockout.rs    # Brute-force protection system
└── settings.rs   # Application configuration
```

## Architecture

### Data Flow

1. **Vault Creation**: Random 32-byte vault key generated, encrypted twice (under password and pattern), stored with Argon2 hashes
2. **Login**: Password/pattern verified against stored hash, then used to decrypt vault key
3. **Vault Access**: Vault key decrypts vault data for reading/writing entries
4. **Save**: Entries encrypted with vault key, written atomically to disk

### Vault File Format

```json
{
  "salt": "<base64 per-vault random salt>",
  "master_hash": "<argon2id hash of password>",
  "pattern_hash": "<argon2id hash of pattern>",
  "encrypted_key_pw": "<vault key encrypted under password>",
  "encrypted_key_pt": "<vault key encrypted under pattern>",
  "vault_ciphertext": "<AES-256-GCM encrypted vault data>",
  "security_level": "Medium",
  "totp_secret_encrypted": "<optional vault-level 2FA secret>"
}
```

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit pull requests.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
