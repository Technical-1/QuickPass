# QuickPass Technology Stack

## Core Technology

### Language & Framework

| Component | Technology | Version |
|-----------|------------|---------|
| Language | Rust | 2021 Edition |
| GUI Framework | eframe/egui | 0.31.1 |
| Build System | Cargo | Standard |

I chose Rust for this project because:
- **Memory safety without garbage collection**: Critical for a security application handling sensitive data
- **Zero-cost abstractions**: Performance comparable to C/C++ with safer code
- **Strong type system**: Catches many bugs at compile time
- **Excellent cryptography ecosystem**: Well-audited crates available

### Cryptographic Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `aes-gcm` | 0.10 | AES-256-GCM authenticated encryption |
| `argon2` | 0.5.3 | Memory-hard key derivation (Argon2id) |
| `rand` | 0.9.0 | Cryptographically secure random number generation |
| `sha2` | 0.10 | SHA-256 hashing for checksums |
| `zeroize` | 1.5 | Secure memory clearing |

**Why these specific libraries:**
- `aes-gcm`: Pure Rust implementation, well-audited, provides authenticated encryption
- `argon2`: Winner of the Password Hashing Competition, recommended by OWASP
- `zeroize`: Ensures sensitive data is properly cleared from memory

### GUI Stack

| Library | Version | Purpose |
|---------|---------|---------|
| `eframe` | 0.31.1 | Native application wrapper |
| `egui` | 0.31.1 | Immediate-mode GUI rendering |
| `winit` | 0.30.9 | Window creation and event handling |

I chose egui/eframe because:
- **Cross-platform**: Single codebase for Windows, macOS, and Linux
- **No system dependencies**: Self-contained rendering (wgpu backend)
- **Immediate mode**: Simplifies state management for complex UIs
- **Rust-native**: No FFI boundaries, pure Rust safety guarantees

### Supporting Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `serde` | 1.0 | Serialization framework |
| `serde_json` | 1.0 | JSON parsing/writing for vault files |
| `base64` | 0.22.1 | Base64 encoding for encrypted data |
| `chrono` | 0.4 | Date/time handling |
| `directories` | 6.0.0 | Platform-specific data directories |
| `totp-rs` | 5.6 | TOTP code generation for 2FA |
| `qrcode` | 0.14 | QR code generation for 2FA setup |
| `sysinfo` | 0.33 | USB device detection |

## Infrastructure

### Build Configuration

```toml
[package]
name = "QuickPass"
version = "0.1.0"
edition = "2021"
build = "src/build.rs"
```

The custom build script (`src/build.rs`) handles Windows-specific resources like icons.

### CI/CD Pipeline

I implemented automated builds using GitHub Actions:

```yaml
Platform Matrix:
- Windows (windows-latest)
- Linux (ubuntu-latest)
- macOS (macos-latest)
```

**Pipeline Features:**
- Triggered on semantic version tags (v*.*.*)
- Parallel builds across all platforms
- Automatic GitHub Release creation
- Artifact naming: `QuickPass-{Platform}`

**Typical Binary Sizes:**
| Platform | Size |
|----------|------|
| Windows | ~8 MB |
| Linux | ~6 MB |
| macOS | ~7 MB |

### Data Storage

**Vault Files Location:**
| Platform | Path |
|----------|------|
| macOS | `~/Library/Application Support/com.KANFER.QuickPass/` |
| Linux | `~/.local/share/QuickPass/` |
| Windows | `C:\Users\<User>\AppData\Roaming\KANFER\QuickPass\` |

**File Types:**
- `encrypted_vault_{name}.json` - Encrypted vault data
- `{name}.lockout.json` - Lockout state tracking
- `settings.json` - Application configuration

### Security Configuration

**Argon2id Parameters by Security Level:**

| Level | Memory | Iterations | Parallelism |
|-------|--------|------------|-------------|
| Low | 19 MiB | 3 | 2 |
| Medium | 47 MiB | 3 | 4 |
| High | 64 MiB | 4 | 4 |

All levels exceed OWASP minimum recommendations (19 MiB, 2 iterations).

## Development Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| `winres` | 0.1 | Windows resource compilation (build-time only) |

## Why I Made These Choices

### Rust over Electron/JavaScript
Password managers written in Electron have historically had security issues due to JavaScript's memory model. Rust's ownership system ensures sensitive data can be properly managed and cleared.

### egui over Qt/GTK
Native GUI toolkits require system dependencies and have inconsistent APIs across platforms. egui provides a consistent, dependency-free experience with acceptable performance for a utility application.

### Local Storage over Cloud
I deliberately avoided cloud sync features because:
- Reduces attack surface significantly
- No server infrastructure to maintain or trust
- Users maintain full control of their data
- USB export provides manual sync when needed
