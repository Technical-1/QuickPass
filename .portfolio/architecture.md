# QuickPass Architecture

## System Architecture Diagram

```mermaid
flowchart TB
    subgraph UI["GUI Layer (eframe/egui)"]
        VM[Vault Manager Screen]
        LS[Login Screen]
        MS[Main Screen]
        IC[Initial Creation Screen]
        SET[Settings Dialog]
    end

    subgraph APP["Application State (app.rs)"]
        QPA[QuickPassApp State]
        KB[Keyboard Shortcuts]
        AL[Auto-Lock Timer]
        CC[Clipboard Clear Timer]
    end

    subgraph CORE["Core Modules"]
        V[vault.rs<br/>Encryption/Decryption]
        S[security.rs<br/>Argon2id Config]
        P[password.rs<br/>Generation & Entropy]
        M[manager.rs<br/>File Management]
        L[lockout.rs<br/>Brute-force Protection]
        ST[settings.rs<br/>App Configuration]
    end

    subgraph FEATURES["Feature Modules"]
        G[gamification.rs<br/>Entropy Game]
        U[usb_export.rs<br/>Portable Backup]
    end

    subgraph CRYPTO["Cryptographic Layer"]
        A2[Argon2id KDF]
        AES[AES-256-GCM]
        RNG[rand RNG]
        TOTP[TOTP Generation]
    end

    subgraph STORAGE["Data Storage"]
        VF[(Vault Files<br/>encrypted_vault_*.json)]
        LF[(Lockout Files<br/>*.lockout.json)]
        SF[(Settings File<br/>settings.json)]
        USB[(USB Export Files<br/>.quickpass_*.enc)]
    end

    VM --> QPA
    LS --> QPA
    MS --> QPA
    IC --> QPA
    SET --> QPA

    QPA --> V
    QPA --> P
    QPA --> M
    QPA --> L
    QPA --> ST
    QPA --> G
    QPA --> U

    V --> AES
    V --> A2
    V --> TOTP
    S --> A2
    P --> RNG
    G --> RNG

    V --> VF
    L --> LF
    ST --> SF
    U --> USB
    M --> VF

    V --> S
    V --> M
    L --> M
```

## Data Flow Diagram

```mermaid
sequenceDiagram
    participant U as User
    participant UI as GUI
    participant APP as App State
    participant S as Security
    participant V as Vault
    participant FS as File System

    Note over U,FS: Vault Creation Flow
    U->>UI: Create new vault
    UI->>APP: Vault name + credentials
    APP->>S: Generate Argon2id params
    S->>V: Hash password & pattern
    V->>V: Generate random vault key (32 bytes)
    V->>V: Encrypt vault key twice (pw + pattern)
    V->>V: Encrypt empty vault data
    V->>FS: Write encrypted_vault_*.json

    Note over U,FS: Login Flow
    U->>UI: Enter password/pattern
    UI->>APP: Credentials
    APP->>V: Load vault file
    V->>FS: Read encrypted file
    FS->>V: Encrypted data
    V->>S: Verify with Argon2id
    S->>V: Hash match
    V->>V: Decrypt vault key
    V->>V: Decrypt vault data
    V->>APP: Decrypted entries
    APP->>UI: Show vault contents

    Note over U,FS: Save Entry Flow
    U->>UI: Add/Edit entry
    UI->>APP: Entry data
    APP->>V: Encrypt with vault key
    V->>V: AES-256-GCM encrypt
    V->>FS: Atomic write (tmp + rename)
```

## Architecture Overview

### Design Philosophy

I built QuickPass with a security-first mindset while maintaining usability. The architecture follows these key principles:

1. **Defense in Depth**: Multiple layers of security protect user data - Argon2id for key derivation, AES-256-GCM for encryption, and zeroize for secure memory clearing.

2. **Fail-Secure Design**: The lockout system progressively restricts access on failed attempts, eventually deleting vaults after too many failures to prevent brute-force attacks.

3. **Minimal Trust Surface**: All sensitive operations happen locally. No network requests, no telemetry, no cloud sync.

### Key Architectural Decisions

#### Dual Authentication System
I implemented both master password and visual pattern unlock because:
- Users can choose their preferred method based on context
- Pattern provides visual/spatial memory alternative for users who struggle with passwords
- The vault key is encrypted under both credentials, allowing either to unlock

#### Per-Vault Random Salt
Each vault gets its own cryptographically random salt rather than a global salt:
- Prevents rainbow table attacks across vaults
- Isolates vault security - compromising one vault's salt doesn't help attack others
- Follows modern cryptographic best practices

#### Vault Key Architecture
Instead of directly encrypting vault data with the password-derived key:
- A random 32-byte vault key encrypts the actual data
- This vault key is encrypted under both password and pattern
- Changing password/pattern only requires re-encrypting the vault key, not all data

#### Atomic File Writes
All vault saves use a write-to-temp-then-rename pattern:
- Prevents data corruption from interrupted writes
- Ensures vault files are always in a valid state
- Critical for a password manager where data loss is catastrophic

#### Module Separation
I separated concerns into focused modules:
- `vault.rs`: Pure encryption/decryption logic
- `security.rs`: Argon2id configuration isolated for easy auditing
- `manager.rs`: File system operations with path sanitization
- `lockout.rs`: Brute-force protection as independent module
- `app.rs`: GUI state management separate from crypto

### Security Model Summary

| Layer | Protection | Implementation |
|-------|-----------|----------------|
| Key Derivation | Memory-hard hashing | Argon2id (19-64 MiB) |
| Data Encryption | Authenticated encryption | AES-256-GCM |
| Memory Safety | Secure memory clearing | zeroize crate |
| Brute-force | Progressive lockouts | Exponential backoff |
| Path Safety | Input sanitization | Strict vault name validation |

### Limitations I Acknowledge

1. **No Browser Integration**: QuickPass is standalone - users must manually copy passwords
2. **No Sync**: Each device maintains its own vaults (USB export provides manual transfer)
3. **Platform Signing**: macOS/Windows binaries are unsigned, requiring manual trust approval
4. **Single-User Design**: No multi-user or sharing features
