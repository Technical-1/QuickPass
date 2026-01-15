use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

use crate::manager::data_dir;

/// Application settings with configurable security timeouts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    /// Clipboard clear timeout in seconds (10-120, default 30)
    pub clipboard_clear_seconds: u32,
    /// Auto-lock timeout in seconds (60-3600, default 300)
    pub auto_lock_seconds: u32,
    /// Maximum failed attempts before lockout (3-10, default 5)
    pub max_failed_attempts: u32,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            clipboard_clear_seconds: 30,
            auto_lock_seconds: 300,  // 5 minutes
            max_failed_attempts: 5,
        }
    }
}

impl AppSettings {
    /// Returns the path to the settings file
    fn settings_path() -> PathBuf {
        data_dir().join("settings.json")
    }

    /// Load settings from file, or return defaults if not found
    pub fn load() -> Self {
        let path = Self::settings_path();
        if path.exists() {
            if let Ok(data) = fs::read_to_string(&path) {
                if let Ok(settings) = serde_json::from_str(&data) {
                    return settings;
                }
            }
        }
        Self::default()
    }

    /// Save settings to file
    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let path = Self::settings_path();
        let data = serde_json::to_string_pretty(self)?;
        fs::write(path, data)?;
        Ok(())
    }

    /// Validate and clamp clipboard timeout to allowed range
    pub fn set_clipboard_timeout(&mut self, seconds: u32) {
        self.clipboard_clear_seconds = seconds.clamp(10, 120);
    }

    /// Validate and clamp auto-lock timeout to allowed range
    pub fn set_auto_lock_timeout(&mut self, seconds: u32) {
        self.auto_lock_seconds = seconds.clamp(60, 3600);
    }

    /// Validate and clamp max failed attempts to allowed range
    pub fn set_max_failed_attempts(&mut self, attempts: u32) {
        self.max_failed_attempts = attempts.clamp(3, 10);
    }

    /// Get clipboard timeout as u64 for comparison with Instant
    pub fn clipboard_timeout_u64(&self) -> u64 {
        self.clipboard_clear_seconds as u64
    }

    /// Get auto-lock timeout as u64 for comparison with Instant
    pub fn auto_lock_timeout_u64(&self) -> u64 {
        self.auto_lock_seconds as u64
    }
}

// ------------------ TESTS ------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_settings() {
        let settings = AppSettings::default();
        assert_eq!(settings.clipboard_clear_seconds, 30);
        assert_eq!(settings.auto_lock_seconds, 300);
        assert_eq!(settings.max_failed_attempts, 5);
    }

    #[test]
    fn test_clipboard_timeout_clamping() {
        let mut settings = AppSettings::default();

        // Below minimum
        settings.set_clipboard_timeout(5);
        assert_eq!(settings.clipboard_clear_seconds, 10);

        // Above maximum
        settings.set_clipboard_timeout(200);
        assert_eq!(settings.clipboard_clear_seconds, 120);

        // Within range
        settings.set_clipboard_timeout(60);
        assert_eq!(settings.clipboard_clear_seconds, 60);
    }

    #[test]
    fn test_auto_lock_timeout_clamping() {
        let mut settings = AppSettings::default();

        // Below minimum
        settings.set_auto_lock_timeout(30);
        assert_eq!(settings.auto_lock_seconds, 60);

        // Above maximum
        settings.set_auto_lock_timeout(5000);
        assert_eq!(settings.auto_lock_seconds, 3600);

        // Within range
        settings.set_auto_lock_timeout(600);
        assert_eq!(settings.auto_lock_seconds, 600);
    }

    #[test]
    fn test_max_failed_attempts_clamping() {
        let mut settings = AppSettings::default();

        // Below minimum
        settings.set_max_failed_attempts(1);
        assert_eq!(settings.max_failed_attempts, 3);

        // Above maximum
        settings.set_max_failed_attempts(20);
        assert_eq!(settings.max_failed_attempts, 10);

        // Within range
        settings.set_max_failed_attempts(7);
        assert_eq!(settings.max_failed_attempts, 7);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let settings = AppSettings {
            clipboard_clear_seconds: 45,
            auto_lock_seconds: 600,
            max_failed_attempts: 7,
        };

        let json = serde_json::to_string(&settings).unwrap();
        let restored: AppSettings = serde_json::from_str(&json).unwrap();

        assert_eq!(settings.clipboard_clear_seconds, restored.clipboard_clear_seconds);
        assert_eq!(settings.auto_lock_seconds, restored.auto_lock_seconds);
        assert_eq!(settings.max_failed_attempts, restored.max_failed_attempts);
    }

    #[test]
    fn test_u64_conversions() {
        let settings = AppSettings::default();
        assert_eq!(settings.clipboard_timeout_u64(), 30u64);
        assert_eq!(settings.auto_lock_timeout_u64(), 300u64);
    }
}
