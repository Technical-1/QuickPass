//! Vault lockout management module.
//!
//! Implements exponential backoff lockout system:
//! - First lockout: 15 minutes
//! - Second lockout: 30 minutes
//! - Third lockout: 60 minutes
//! - Fourth lockout: Vault deletion

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

use crate::manager::vault_file_path;

/// Maximum lockouts before vault deletion
const MAX_LOCKOUTS: u32 = 3;

/// Lockout state for a vault
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct VaultLockout {
    /// ISO 8601 timestamp when lockout expires (None if not locked)
    pub locked_until: Option<String>,
    /// Number of failed attempts in current lockout period
    pub failed_attempts: u32,
    /// Number of times vault has been locked out
    pub lockout_count: u32,
    /// Timestamp of last failed attempt
    pub last_attempt: Option<String>,
}

impl VaultLockout {
    /// Get the lockout file path for a vault
    pub fn lockout_file_path(vault_name: &str) -> PathBuf {
        let vault_path = vault_file_path(vault_name);
        vault_path.with_extension("lockout.json")
    }

    /// Load lockout state from file, or return default if not found
    pub fn load(vault_name: &str) -> Self {
        let path = Self::lockout_file_path(vault_name);
        if path.exists() {
            if let Ok(data) = fs::read_to_string(&path) {
                if let Ok(lockout) = serde_json::from_str(&data) {
                    return lockout;
                }
            }
        }
        Self::default()
    }

    /// Save lockout state to file
    pub fn save(&self, vault_name: &str) -> std::io::Result<()> {
        let path = Self::lockout_file_path(vault_name);
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        fs::write(path, json)
    }

    /// Delete lockout file for a vault
    pub fn delete(vault_name: &str) {
        let path = Self::lockout_file_path(vault_name);
        let _ = fs::remove_file(path);
    }

    /// Check if the vault is currently locked
    pub fn is_locked(&self) -> bool {
        if let Some(ref locked_until) = self.locked_until {
            if let Ok(lock_time) = DateTime::parse_from_rfc3339(locked_until) {
                return Utc::now() < lock_time.with_timezone(&Utc);
            }
        }
        false
    }

    /// Get remaining lockout time in seconds (0 if not locked)
    pub fn remaining_lockout_seconds(&self) -> u64 {
        if let Some(ref locked_until) = self.locked_until {
            if let Ok(lock_time) = DateTime::parse_from_rfc3339(locked_until) {
                let remaining = lock_time.with_timezone(&Utc) - Utc::now();
                if remaining.num_seconds() > 0 {
                    return remaining.num_seconds() as u64;
                }
            }
        }
        0
    }

    /// Format remaining lockout time for display
    pub fn format_remaining_time(&self) -> String {
        let secs = self.remaining_lockout_seconds();
        if secs == 0 {
            return String::new();
        }
        let mins = secs / 60;
        let secs_remainder = secs % 60;
        if mins > 0 {
            format!("{}m {}s", mins, secs_remainder)
        } else {
            format!("{}s", secs)
        }
    }

    /// Calculate lockout duration in minutes based on lockout count
    fn lockout_duration_minutes(lockout_count: u32) -> i64 {
        match lockout_count {
            0 => 15,  // First lockout: 15 minutes
            1 => 30,  // Second lockout: 30 minutes
            2 => 60,  // Third lockout: 60 minutes
            _ => 0,   // Fourth+ lockout: delete vault
        }
    }

    /// Record a failed login attempt.
    /// Returns `LockoutResult` indicating the outcome.
    ///
    /// # Arguments
    /// * `vault_name` - Name of the vault
    /// * `max_attempts` - Maximum failed attempts before lockout (from AppSettings)
    pub fn record_failure(&mut self, vault_name: &str, max_attempts: u32) -> LockoutResult {
        // If currently locked, check if lockout expired
        if self.is_locked() {
            return LockoutResult::StillLocked {
                remaining_seconds: self.remaining_lockout_seconds(),
            };
        }

        // Clear expired lockout state
        if self.locked_until.is_some() && !self.is_locked() {
            self.locked_until = None;
            // Don't reset failed_attempts - they continue from where they were
        }

        self.failed_attempts += 1;
        self.last_attempt = Some(Utc::now().to_rfc3339());

        let attempts_left = max_attempts.saturating_sub(self.failed_attempts);

        if self.failed_attempts >= max_attempts {
            self.lockout_count += 1;
            self.failed_attempts = 0;

            // Check if we've exceeded max lockouts - time to delete
            if self.lockout_count > MAX_LOCKOUTS {
                // Delete the lockout file too
                Self::delete(vault_name);
                return LockoutResult::DeleteVault;
            }

            // Apply lockout
            let lockout_mins = Self::lockout_duration_minutes(self.lockout_count - 1);
            let lock_until = Utc::now() + Duration::minutes(lockout_mins);
            self.locked_until = Some(lock_until.to_rfc3339());

            // Save state
            let _ = self.save(vault_name);

            return LockoutResult::NewLockout {
                lockout_number: self.lockout_count,
                duration_minutes: lockout_mins as u64,
                lockouts_before_deletion: MAX_LOCKOUTS + 1 - self.lockout_count,
            };
        }

        // Save state
        let _ = self.save(vault_name);

        LockoutResult::AttemptFailed { attempts_left }
    }

    /// Reset lockout state on successful login
    pub fn reset_on_success(&mut self, vault_name: &str) {
        self.failed_attempts = 0;
        self.lockout_count = 0;
        self.locked_until = None;
        self.last_attempt = None;
        // Delete the lockout file on successful login
        Self::delete(vault_name);
    }

    /// Get warning message if close to lockout
    ///
    /// # Arguments
    /// * `max_attempts` - Maximum failed attempts before lockout (from AppSettings)
    pub fn get_warning(&self, max_attempts: u32) -> Option<String> {
        let attempts_left = max_attempts.saturating_sub(self.failed_attempts);
        if attempts_left <= 2 && attempts_left > 0 {
            let lockouts_left = MAX_LOCKOUTS + 1 - self.lockout_count;
            Some(format!(
                "{} attempts left before {}",
                attempts_left,
                if lockouts_left <= 1 {
                    "vault deletion!".to_string()
                } else {
                    format!("lockout ({} lockouts before deletion)", lockouts_left)
                }
            ))
        } else {
            None
        }
    }
}

/// Result of recording a failed login attempt
#[derive(Debug, Clone)]
pub enum LockoutResult {
    /// Attempt failed but more attempts remain
    AttemptFailed { attempts_left: u32 },
    /// Vault is now locked
    NewLockout {
        lockout_number: u32,
        duration_minutes: u64,
        lockouts_before_deletion: u32,
    },
    /// Vault is still locked from previous lockout
    StillLocked { remaining_seconds: u64 },
    /// Too many lockouts - vault should be deleted
    DeleteVault,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lockout_duration_progression() {
        assert_eq!(VaultLockout::lockout_duration_minutes(0), 15);
        assert_eq!(VaultLockout::lockout_duration_minutes(1), 30);
        assert_eq!(VaultLockout::lockout_duration_minutes(2), 60);
        assert_eq!(VaultLockout::lockout_duration_minutes(3), 0);
    }

    #[test]
    fn test_default_lockout_state() {
        let lockout = VaultLockout::default();
        assert_eq!(lockout.failed_attempts, 0);
        assert_eq!(lockout.lockout_count, 0);
        assert!(lockout.locked_until.is_none());
        assert!(!lockout.is_locked());
    }

    #[test]
    fn test_format_remaining_time() {
        let mut lockout = VaultLockout::default();

        // No lockout
        assert_eq!(lockout.format_remaining_time(), "");

        // Set a lockout 5 minutes in the future
        let future = Utc::now() + Duration::minutes(5);
        lockout.locked_until = Some(future.to_rfc3339());

        let remaining = lockout.format_remaining_time();
        assert!(remaining.contains("m"));
    }
}
