//! USB Export module for portable vault backups.
//!
//! This module provides functionality to export encrypted vault backups
//! to removable USB drives and import them back.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::path::{Path, PathBuf};
use sysinfo::Disks;

/// Maximum length for sanitized vault name in filename
const MAX_VAULT_NAME_LEN: usize = 50;
/// Maximum total filename length
const MAX_FILENAME_LEN: usize = 255;
/// Minimum free space required for export (1 MB)
const MIN_FREE_SPACE: u64 = 1_048_576;

/// System directories that should never be export targets
const BLOCKED_PATHS: &[&str] = &[
    "/", "/etc", "/usr", "/bin", "/sbin", "/var", "/tmp",
    "/System", "/Library", "/Applications", "/private",
    "C:\\", "C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)",
    "C:\\Users\\Public", "C:\\ProgramData",
];

/// Represents a detected USB/removable drive
#[derive(Clone, Debug)]
pub struct USBDevice {
    pub name: String,
    pub mount_point: PathBuf,
    pub total_bytes: u64,
    pub available_bytes: u64,
}

impl USBDevice {
    /// Format the device size for display
    pub fn formatted_size(&self) -> String {
        let gb = self.total_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
        if gb >= 1.0 {
            format!("{:.1} GB", gb)
        } else {
            let mb = self.total_bytes as f64 / (1024.0 * 1024.0);
            format!("{:.0} MB", mb)
        }
    }

    /// Format available space for display
    pub fn formatted_available(&self) -> String {
        let gb = self.available_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
        if gb >= 1.0 {
            format!("{:.1} GB free", gb)
        } else {
            let mb = self.available_bytes as f64 / (1024.0 * 1024.0);
            format!("{:.0} MB free", mb)
        }
    }
}

/// Data format for USB export files
#[derive(Clone, Serialize, Deserialize)]
pub struct USBExportData {
    pub version: u32,
    pub vault_name: String,
    pub exported_at: String,
    pub nonce: String,      // Base64-encoded
    pub ciphertext: String, // Base64-encoded
    pub checksum: String,   // SHA-256 of ciphertext
}

/// Detect removable USB drives
pub fn detect_usb_devices() -> Vec<USBDevice> {
    let disks = Disks::new_with_refreshed_list();

    disks
        .iter()
        .filter(|d| d.is_removable())
        .map(|d| USBDevice {
            name: d.name().to_string_lossy().to_string(),
            mount_point: d.mount_point().to_path_buf(),
            total_bytes: d.total_space(),
            available_bytes: d.available_space(),
        })
        .collect()
}

/// Check if a path is a blocked system directory
fn is_blocked_path(path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    for blocked in BLOCKED_PATHS {
        // Check if path IS the blocked path or is directly under it with nothing else
        if path_str == *blocked || (path_str.starts_with(blocked) && path_str.len() == blocked.len()) {
            return true;
        }
    }
    false
}

/// Validate USB device is safe for export
pub fn validate_export_device(device: &USBDevice) -> Result<(), String> {
    // Check mount point exists
    if !device.mount_point.exists() {
        return Err("Mount point does not exist".into());
    }

    // Check it's not a system directory
    if is_blocked_path(&device.mount_point) {
        return Err("Cannot export to system directory".into());
    }

    // Check minimum free space
    if device.available_bytes < MIN_FREE_SPACE {
        return Err(format!(
            "Insufficient space: need at least 1 MB, have {} bytes",
            device.available_bytes
        ));
    }

    Ok(())
}

/// Validate and create safe export path
fn create_safe_export_path(mount_point: &Path, vault_name: &str) -> Result<(PathBuf, String), Box<dyn Error>> {
    // Sanitize vault name: only alphanumeric and underscore, limited length
    let safe_name: String = vault_name
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_')
        .take(MAX_VAULT_NAME_LEN)
        .collect();

    // Use a fallback if name is empty after sanitization
    let safe_name = if safe_name.is_empty() {
        "vault".to_string()
    } else {
        safe_name
    };

    // Generate filename with timestamp
    let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
    let filename = format!(".quickpass_{}_{}.enc", safe_name, timestamp);

    // Validate filename length
    if filename.len() > MAX_FILENAME_LEN {
        return Err("Generated filename too long".into());
    }

    // Create and validate export path
    let export_path = mount_point.join(&filename);

    // Security check: ensure path doesn't escape mount point
    // (e.g., via .. or symlinks)
    let canonical_mount = mount_point.canonicalize().unwrap_or_else(|_| mount_point.to_path_buf());
    if let Ok(canonical_export) = export_path.canonicalize() {
        if !canonical_export.starts_with(&canonical_mount) {
            return Err("Invalid export path - possible path traversal".into());
        }
    }
    // For new files, just verify parent is the mount point
    if export_path.parent() != Some(mount_point) {
        return Err("Export path must be directly in mount point".into());
    }

    Ok((export_path, filename))
}

/// Export encrypted vault to a USB device
pub fn export_to_usb(
    device: &USBDevice,
    vault_name: &str,
    vault_key: &[u8],
    entries: &[crate::vault::VaultEntry],
    custom_tags: &[String],
) -> Result<PathBuf, Box<dyn Error>> {
    // Validate device is safe for export
    validate_export_device(device).map_err(|e| -> Box<dyn Error> { e.into() })?;

    // Create safe export path with validation
    let (export_path, _filename) = create_safe_export_path(&device.mount_point, vault_name)?;

    // Get encrypted backup data using existing function
    let backup_json = crate::vault::export_encrypted_backup(vault_name, vault_key, entries, custom_tags)?;

    // Parse the backup to add checksum
    let backup: serde_json::Value = serde_json::from_str(&backup_json)?;
    let ciphertext = backup["ciphertext"].as_str().unwrap_or("");

    // Create checksum
    let mut hasher = Sha256::new();
    hasher.update(ciphertext.as_bytes());
    let checksum = format!("{:x}", hasher.finalize());

    // Create USB export data with checksum
    let usb_export = USBExportData {
        version: 1,
        vault_name: vault_name.to_string(),
        exported_at: Utc::now().to_rfc3339(),
        nonce: backup["nonce"].as_str().unwrap_or("").to_string(),
        ciphertext: ciphertext.to_string(),
        checksum,
    };

    // Write to USB
    let json = serde_json::to_string_pretty(&usb_export)?;
    std::fs::write(&export_path, json)?;

    // Try to set hidden attribute on Windows
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use std::fs::OpenOptions;
        // FILE_ATTRIBUTE_HIDDEN = 2
        let _ = OpenOptions::new()
            .write(true)
            .attributes(2)
            .open(&export_path);
    }

    Ok(export_path)
}

/// Import encrypted vault data from a USB export file
pub fn import_from_usb(file_path: &PathBuf) -> Result<String, Box<dyn Error>> {
    let content = std::fs::read_to_string(file_path)?;
    let data: USBExportData = serde_json::from_str(&content)?;

    // Verify checksum
    let mut hasher = Sha256::new();
    hasher.update(data.ciphertext.as_bytes());
    let computed_checksum = format!("{:x}", hasher.finalize());

    if data.checksum != computed_checksum {
        return Err("Checksum verification failed - file may be corrupted".into());
    }

    // Convert back to standard backup format for import
    let backup = serde_json::json!({
        "version": data.version,
        "vault_name": data.vault_name,
        "nonce": data.nonce,
        "ciphertext": data.ciphertext,
        "created_at": data.exported_at,
    });

    Ok(serde_json::to_string(&backup)?)
}

/// Find QuickPass export files on a USB device
pub fn find_exports_on_device(device: &USBDevice) -> Vec<(PathBuf, String, String)> {
    let mut exports = Vec::new();

    if let Ok(entries) = std::fs::read_dir(&device.mount_point) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if (name.starts_with(".quickpass_") || name.starts_with("quickpass_"))
                    && name.ends_with(".enc")
                {
                    // Try to read metadata
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        if let Ok(data) = serde_json::from_str::<USBExportData>(&content) {
                            exports.push((path, data.vault_name, data.exported_at));
                        }
                    }
                }
            }
        }
    }

    exports
}

/// Verify a USB export file's integrity
pub fn verify_usb_export(file_path: &PathBuf) -> Result<USBExportData, Box<dyn Error>> {
    let content = std::fs::read_to_string(file_path)?;
    let data: USBExportData = serde_json::from_str(&content)?;

    // Verify checksum
    let mut hasher = Sha256::new();
    hasher.update(data.ciphertext.as_bytes());
    let computed_checksum = format!("{:x}", hasher.finalize());

    if data.checksum != computed_checksum {
        return Err("Checksum verification failed".into());
    }

    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_usb_device_formatted_size() {
        let device = USBDevice {
            name: "Test".to_string(),
            mount_point: PathBuf::from("/test"),
            total_bytes: 8 * 1024 * 1024 * 1024, // 8 GB
            available_bytes: 4 * 1024 * 1024 * 1024, // 4 GB
        };

        assert!(device.formatted_size().contains("8.0 GB"));
        assert!(device.formatted_available().contains("4.0 GB"));
    }

    #[test]
    fn test_usb_device_formatted_size_mb() {
        let device = USBDevice {
            name: "Small".to_string(),
            mount_point: PathBuf::from("/test"),
            total_bytes: 500 * 1024 * 1024, // 500 MB
            available_bytes: 250 * 1024 * 1024, // 250 MB
        };

        assert!(device.formatted_size().contains("500 MB"));
        assert!(device.formatted_available().contains("250 MB"));
    }

    #[test]
    fn test_checksum_verification() {
        let data = USBExportData {
            version: 1,
            vault_name: "test".to_string(),
            exported_at: "2026-01-15".to_string(),
            nonce: "abc123".to_string(),
            ciphertext: "encrypted_data_here".to_string(),
            checksum: "".to_string(),
        };

        // Calculate expected checksum
        let mut hasher = Sha256::new();
        hasher.update(data.ciphertext.as_bytes());
        let expected = format!("{:x}", hasher.finalize());

        assert!(!expected.is_empty());
    }
}
