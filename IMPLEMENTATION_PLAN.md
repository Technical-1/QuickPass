# QuickPass Implementation Plan

## Overview

This plan addresses the 4 remaining open GitHub issues:
- **#20** - USB Export with Raw Device Write
- **#15** - Custom Field Support
- **#6** - CI/CD Documentation (remaining tasks)
- **#4** - Gamified Password Generation

## Implementation Order

**Recommended sequence** (by complexity and dependency):
1. **Custom Field Support** (#15) - Data model change, foundational
2. **CI/CD Documentation** (#6) - Quick win, no code changes
3. **Gamified Password Generation** (#4) - UI-focused, builds on existing password module
4. **USB Export** (#20) - Most complex, platform-specific

---

## Issue #15: Custom Field Support

### Summary
Allow users to add arbitrary key-value fields to vault entries (Recovery Email, Security Questions, Notes, etc.).

### Data Model Changes

**File: `src/vault.rs`**

```rust
// NEW: Custom field types
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum CustomFieldType {
    Text,
    Password,   // Masked in UI
    URL,
    Email,
    Notes,      // Multiline
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct CustomField {
    pub name: String,
    pub value: String,
    pub field_type: CustomFieldType,
}

// MODIFIED: Add custom_fields to VaultEntry
pub struct VaultEntry {
    pub website: String,
    pub username: String,
    pub password: String,
    pub tags: Vec<String>,
    pub created_at: Option<String>,
    pub modified_at: Option<String>,
    pub totp_secret: Option<String>,
    #[serde(default)]                    // NEW
    pub custom_fields: Vec<CustomField>, // NEW
}
```

### App State Changes

**File: `src/app.rs`**

Add to `QuickPassApp` struct:
```rust
// Custom field editing state
pub editing_custom_fields: Vec<CustomField>,
pub new_field_name: String,
pub new_field_value: String,
pub new_field_type: CustomFieldType,
```

### UI Implementation

**Location:** Entry editing section in `app.rs` (around line 1468, after TOTP section)

Components:
1. List existing custom fields with edit/delete buttons
2. "Add Field" form with name, value, type selector
3. Password-type fields show masked values with reveal toggle
4. Notes-type fields use multiline TextEdit

### Export/Import Updates

**CSV Export:** Add custom fields as additional columns or JSON blob
**Encrypted Backup:** No changes needed (serializes automatically)
**CSV Import:** Parse extra columns as custom fields

### Tests to Add

```rust
#[test]
fn test_custom_field_serialization()
#[test]
fn test_entry_with_custom_fields_roundtrip()
#[test]
fn test_custom_field_types()
#[test]
fn test_export_csv_with_custom_fields()
```

### Tasks
- [ ] Add `CustomField` and `CustomFieldType` structs to vault.rs
- [ ] Add `custom_fields: Vec<CustomField>` to `VaultEntry` with `#[serde(default)]`
- [ ] Add editing state fields to `QuickPassApp`
- [ ] Implement custom fields UI section in entry editor
- [ ] Add field type dropdown (Text, Password, URL, Email, Notes)
- [ ] Implement masked display for Password-type fields
- [ ] Update CSV export to include custom fields
- [ ] Add unit tests for custom field functionality
- [ ] Test backward compatibility with existing vault files

---

## Issue #6: CI/CD Documentation

### Summary
Document the existing CI/CD pipeline and installation instructions.

### README.md Updates

Add new sections after "Building from Source":

```markdown
## Installation

### Pre-built Binaries

Download the latest release for your platform from [GitHub Releases](https://github.com/Technical-1/QuickPass/releases):

| Platform | File | Notes |
|----------|------|-------|
| Windows | `QuickPass-Windows.exe` | Double-click to run |
| Linux | `QuickPass-Linux` | `chmod +x` then run |
| macOS | `QuickPass-macOS` | May need to allow in Security settings |

### macOS First Run

macOS may block unsigned applications. To run:
1. Right-click the binary and select "Open"
2. Or: System Preferences → Security & Privacy → Allow

### Linux Dependencies

On some Linux distributions, you may need GTK libraries:
```bash
# Ubuntu/Debian
sudo apt install libgtk-3-0

# Fedora
sudo dnf install gtk3
```

## CI/CD Pipeline

QuickPass uses GitHub Actions for automated builds and releases.

### Workflow Trigger

Push a semantic version tag to trigger a release:
```bash
git tag v1.2.0
git push origin v1.2.0
```

### Build Matrix

| Platform | Runner | Output |
|----------|--------|--------|
| Windows | windows-latest | QuickPass-Windows.exe |
| Linux | ubuntu-latest | QuickPass-Linux |
| macOS | macos-latest | QuickPass-macOS |

### Quality Checks

Run locally before releasing:
```bash
cargo test              # Run all tests
cargo clippy            # Lint check
cargo build --release   # Verify release build
```
```

### Tasks
- [ ] Add "Installation" section to README.md
- [ ] Add pre-built binaries download table
- [ ] Add macOS unsigned app instructions
- [ ] Add Linux dependencies note
- [ ] Add "CI/CD Pipeline" section
- [ ] Document release tagging process
- [ ] Document quality checks

---

## Issue #4: Gamified Password Generation

### Summary
Add optional mini-challenges and achievements to make password generation engaging while collecting user-interaction entropy.

### New Module: `src/gamification.rs`

```rust
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub id: u32,
    pub name: String,
    pub description: String,
    pub target_entropy: f64,
    pub requirements: Vec<Requirement>,
    pub reward_xp: u32,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub enum Requirement {
    MinLength(usize),
    HasLowercase,
    HasUppercase,
    HasDigits,
    HasSymbols(usize),
    NoRepeatingChars,
    MinEntropy(f64),
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct PlayerStats {
    pub total_generated: u32,
    pub total_xp: u32,
    pub best_entropy: f64,
    pub challenges_completed: Vec<u32>,
    pub achievements: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Achievement {
    pub id: String,
    pub name: String,
    pub description: String,
    pub icon: char,  // Unicode symbol
}

// Built-in challenges
pub fn get_challenges() -> Vec<Challenge> {
    vec![
        Challenge {
            id: 1,
            name: "Getting Started".into(),
            description: "Generate a password with 60+ bits of entropy".into(),
            target_entropy: 60.0,
            requirements: vec![Requirement::MinLength(8)],
            reward_xp: 10,
        },
        Challenge {
            id: 2,
            name: "Mix It Up".into(),
            description: "Use all character types".into(),
            target_entropy: 80.0,
            requirements: vec![
                Requirement::HasLowercase,
                Requirement::HasUppercase,
                Requirement::HasDigits,
                Requirement::HasSymbols(1),
            ],
            reward_xp: 25,
        },
        Challenge {
            id: 3,
            name: "Fortress".into(),
            description: "Create a 128+ bit entropy password".into(),
            target_entropy: 128.0,
            requirements: vec![Requirement::MinEntropy(128.0)],
            reward_xp: 50,
        },
        Challenge {
            id: 4,
            name: "No Repeats".into(),
            description: "Generate without repeating characters".into(),
            target_entropy: 70.0,
            requirements: vec![Requirement::NoRepeatingChars],
            reward_xp: 30,
        },
        Challenge {
            id: 5,
            name: "Symbol Master".into(),
            description: "Include at least 4 symbols".into(),
            target_entropy: 90.0,
            requirements: vec![Requirement::HasSymbols(4)],
            reward_xp: 40,
        },
    ]
}

// Built-in achievements
pub fn get_achievements() -> Vec<Achievement> {
    vec![
        Achievement { id: "first_gen".into(), name: "First Steps".into(),
                      description: "Generate your first password".into(), icon: '🎯' },
        Achievement { id: "entropy_100".into(), name: "Century Club".into(),
                      description: "Reach 100 bits of entropy".into(), icon: '💯' },
        Achievement { id: "gen_10".into(), name: "Getting Serious".into(),
                      description: "Generate 10 passwords".into(), icon: '🔟' },
        Achievement { id: "gen_100".into(), name: "Password Pro".into(),
                      description: "Generate 100 passwords".into(), icon: '🏆' },
        Achievement { id: "all_challenges".into(), name: "Completionist".into(),
                      description: "Complete all challenges".into(), icon: '⭐' },
    ]
}

pub fn check_requirements(password: &str, requirements: &[Requirement]) -> Vec<(Requirement, bool)> {
    requirements.iter().map(|req| {
        let met = match req {
            Requirement::MinLength(n) => password.len() >= *n,
            Requirement::HasLowercase => password.chars().any(|c| c.is_ascii_lowercase()),
            Requirement::HasUppercase => password.chars().any(|c| c.is_ascii_uppercase()),
            Requirement::HasDigits => password.chars().any(|c| c.is_ascii_digit()),
            Requirement::HasSymbols(n) => {
                password.chars().filter(|c| !c.is_alphanumeric()).count() >= *n
            }
            Requirement::NoRepeatingChars => {
                let chars: Vec<char> = password.chars().collect();
                chars.windows(2).all(|w| w[0] != w[1])
            }
            Requirement::MinEntropy(target) => {
                crate::password::estimate_entropy(password) >= *target
            }
        };
        (req.clone(), met)
    }).collect()
}

pub fn check_achievements(stats: &PlayerStats) -> Vec<String> {
    let mut new_achievements = Vec::new();

    if stats.total_generated >= 1 && !stats.achievements.contains(&"first_gen".to_string()) {
        new_achievements.push("first_gen".to_string());
    }
    if stats.best_entropy >= 100.0 && !stats.achievements.contains(&"entropy_100".to_string()) {
        new_achievements.push("entropy_100".to_string());
    }
    if stats.total_generated >= 10 && !stats.achievements.contains(&"gen_10".to_string()) {
        new_achievements.push("gen_10".to_string());
    }
    if stats.total_generated >= 100 && !stats.achievements.contains(&"gen_100".to_string()) {
        new_achievements.push("gen_100".to_string());
    }
    if stats.challenges_completed.len() >= 5 && !stats.achievements.contains(&"all_challenges".to_string()) {
        new_achievements.push("all_challenges".to_string());
    }

    new_achievements
}
```

### App State Changes

**File: `src/app.rs`**

```rust
// Gamification state
pub player_stats: PlayerStats,
pub active_challenge: Option<Challenge>,
pub show_challenges: bool,
pub challenge_requirements_status: Vec<(Requirement, bool)>,
pub newly_unlocked_achievement: Option<Achievement>,
```

### UI Components

1. **Challenge Panel** (collapsible, in password generator section)
   - Current challenge name/description
   - Requirements checklist with green/gray indicators
   - Progress bar toward target entropy
   - "Skip" button to dismiss

2. **Achievement Toast**
   - Popup when achievement unlocked
   - Shows icon, name, description
   - Auto-dismiss after 3 seconds

3. **Stats Display** (small, in corner or settings)
   - Total passwords generated
   - Best entropy achieved
   - XP/Level progress bar

### Persistence

Store `PlayerStats` in vault metadata or separate file:
- Option A: Add to `VaultMetadata` (per-vault stats)
- Option B: Global stats file in app data directory (recommended)

### Tasks
- [ ] Create `src/gamification.rs` module
- [ ] Implement `Challenge`, `Requirement`, `PlayerStats`, `Achievement` structs
- [ ] Add 5 built-in challenges with increasing difficulty
- [ ] Add 5 achievements for milestones
- [ ] Implement requirement checking functions
- [ ] Add gamification state to `QuickPassApp`
- [ ] Create collapsible challenge panel UI
- [ ] Add requirements checklist with live status
- [ ] Implement achievement popup/toast
- [ ] Add stats persistence (global file)
- [ ] Update `mod.rs` / `main.rs` to include new module
- [ ] Add "Enable Challenges" toggle in settings (opt-in/out)
- [ ] Add unit tests for requirement checking

---

## Issue #20: USB Export with Raw Device Write

### Summary
Export encrypted vault data directly to USB device sectors for secure, portable storage.

### Approach

**Simplified Approach (Recommended):**
Instead of raw sector writes (which require admin privileges and are platform-complex), implement:
1. Detect mounted USB drives
2. Write encrypted file directly to USB filesystem
3. Optional: Create hidden/system file for obscurity

**Advanced Approach (Full Implementation):**
Raw sector writes with platform-specific code.

### Dependencies

**Add to Cargo.toml:**
```toml
[dependencies]
sysinfo = "0.32"  # System/device information (cross-platform)

[target.'cfg(windows)'.dependencies]
windows = { version = "0.58", features = ["Win32_Storage_FileSystem", "Win32_System_IO"] }

[target.'cfg(unix)'.dependencies]
nix = { version = "0.29", features = ["fs"] }
```

### New Module: `src/usb_export.rs`

```rust
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct USBDevice {
    pub name: String,
    pub mount_point: PathBuf,
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub is_removable: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct USBExportData {
    pub version: u32,
    pub vault_name: String,
    pub exported_at: String,
    pub nonce: String,      // Base64
    pub ciphertext: String, // Base64
    pub checksum: String,   // SHA-256 of ciphertext
}

/// Detect removable USB drives
pub fn detect_usb_devices() -> Vec<USBDevice> {
    use sysinfo::Disks;

    let disks = Disks::new_with_refreshed_list();
    disks.iter()
        .filter(|d| d.is_removable())
        .map(|d| USBDevice {
            name: d.name().to_string_lossy().to_string(),
            mount_point: d.mount_point().to_path_buf(),
            total_bytes: d.total_space(),
            available_bytes: d.available_space(),
            is_removable: true,
        })
        .collect()
}

/// Export encrypted vault to USB device
pub fn export_to_usb(
    device: &USBDevice,
    vault_name: &str,
    vault_key: &[u8],
    entries: &[crate::vault::VaultEntry],
    custom_tags: &[String],
) -> Result<PathBuf, Box<dyn Error>> {
    use sha2::{Sha256, Digest};

    // Get encrypted backup data
    let backup_json = crate::vault::export_encrypted_backup(
        vault_name, vault_key, entries, custom_tags
    )?;

    // Parse and add checksum
    let mut backup: serde_json::Value = serde_json::from_str(&backup_json)?;
    let ciphertext = backup["ciphertext"].as_str().unwrap_or("");
    let checksum = format!("{:x}", Sha256::digest(ciphertext.as_bytes()));
    backup["checksum"] = serde_json::Value::String(checksum);

    // Create export filename
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let filename = format!(".quickpass_{}_{}.enc", vault_name, timestamp);
    let export_path = device.mount_point.join(&filename);

    // Write to USB
    std::fs::write(&export_path, serde_json::to_string_pretty(&backup)?)?;

    // Set hidden attribute on Windows
    #[cfg(windows)]
    set_hidden_attribute(&export_path)?;

    Ok(export_path)
}

/// Import vault from USB device
pub fn import_from_usb(file_path: &PathBuf) -> Result<String, Box<dyn Error>> {
    use sha2::{Sha256, Digest};

    let content = std::fs::read_to_string(file_path)?;
    let data: serde_json::Value = serde_json::from_str(&content)?;

    // Verify checksum if present
    if let Some(stored_checksum) = data["checksum"].as_str() {
        let ciphertext = data["ciphertext"].as_str().unwrap_or("");
        let computed = format!("{:x}", Sha256::digest(ciphertext.as_bytes()));
        if stored_checksum != computed {
            return Err("Checksum verification failed - file may be corrupted".into());
        }
    }

    Ok(content)
}

/// Find QuickPass exports on a USB device
pub fn find_exports_on_device(device: &USBDevice) -> Vec<PathBuf> {
    let mut exports = Vec::new();

    if let Ok(entries) = std::fs::read_dir(&device.mount_point) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with(".quickpass_") && name.ends_with(".enc") {
                    exports.push(path);
                }
            }
        }
    }

    exports
}

#[cfg(windows)]
fn set_hidden_attribute(path: &PathBuf) -> Result<(), Box<dyn Error>> {
    use std::os::windows::fs::OpenOptionsExt;
    // Windows-specific hidden file attribute
    Ok(())
}
```

### App State Changes

**File: `src/app.rs`**

```rust
// USB Export state
pub show_usb_export_dialog: bool,
pub detected_usb_devices: Vec<USBDevice>,
pub selected_usb_device: Option<usize>,
pub usb_export_status: Option<Result<String, String>>,
pub usb_exports_found: Vec<PathBuf>,
pub show_usb_import_dialog: bool,
```

### UI Components

1. **USB Export Dialog**
   - "Refresh Devices" button
   - List of detected USB drives with name/size
   - Select device → "Export" button
   - Progress/status indicator
   - Success: show file path

2. **USB Import Dialog**
   - Device selector
   - List of found `.quickpass_*.enc` files
   - Select file → "Import" button
   - Checksum verification status

### Tasks
- [ ] Add `sysinfo` dependency to Cargo.toml
- [ ] Create `src/usb_export.rs` module
- [ ] Implement `USBDevice` struct and detection
- [ ] Implement `export_to_usb()` with checksum
- [ ] Implement `import_from_usb()` with verification
- [ ] Implement `find_exports_on_device()`
- [ ] Add USB export state to `QuickPassApp`
- [ ] Create USB export dialog UI
- [ ] Create USB import dialog UI
- [ ] Add "Export to USB" button in export section
- [ ] Add "Import from USB" button in import section
- [ ] Handle Windows hidden file attributes
- [ ] Add integration tests for USB export/import
- [ ] Test on Windows, Linux, macOS

---

## Testing Strategy

### Unit Tests

| Module | Tests |
|--------|-------|
| vault.rs | Custom field serialization, backward compatibility |
| gamification.rs | Requirement checking, achievement unlocking |
| usb_export.rs | Export format, checksum verification |

### Integration Tests

```rust
// tests/integration_tests.rs additions

#[test]
fn test_vault_entry_with_custom_fields() { ... }

#[test]
fn test_custom_fields_persist_through_encrypt_decrypt() { ... }

#[test]
fn test_gamification_challenge_completion() { ... }

#[test]
fn test_usb_export_import_roundtrip() { ... }

#[test]
fn test_usb_export_checksum_verification() { ... }
```

### Manual Testing Checklist

- [ ] Create entry with custom fields, close/reopen vault
- [ ] Export vault with custom fields to CSV
- [ ] Complete all 5 gamification challenges
- [ ] Export to actual USB drive on each platform
- [ ] Import from USB on different machine
- [ ] Verify corrupted USB export is rejected

---

## File Changes Summary

| File | Changes |
|------|---------|
| `src/vault.rs` | Add `CustomField`, `CustomFieldType`, update `VaultEntry` |
| `src/app.rs` | Add UI for custom fields, gamification, USB export |
| `src/gamification.rs` | **NEW** - Challenges, achievements, stats |
| `src/usb_export.rs` | **NEW** - USB detection and export |
| `src/lib.rs` or `main.rs` | Add `mod gamification; mod usb_export;` |
| `Cargo.toml` | Add `sysinfo`, `sha2` dependencies |
| `README.md` | Add CI/CD and installation documentation |
| `tests/integration_tests.rs` | Add tests for new features |

---

## Estimated Complexity

| Issue | Complexity | New Files | Lines of Code |
|-------|------------|-----------|---------------|
| #15 Custom Fields | Medium | 0 | ~200 |
| #6 CI/CD Docs | Low | 0 | ~100 (docs) |
| #4 Gamification | Medium | 1 | ~400 |
| #20 USB Export | High | 1 | ~350 |

**Total: ~1,050 lines of code + documentation**
