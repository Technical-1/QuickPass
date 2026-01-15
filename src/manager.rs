use directories::ProjectDirs;
use std::fs;
use std::path::PathBuf;

/// Maximum vault name length
const MAX_VAULT_NAME_LENGTH: usize = 64;

/// Allowed characters in vault names (alphanumeric, space, hyphen, underscore)
const ALLOWED_CHARS: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_ ";

/// Sanitize vault name to prevent path traversal and other issues.
/// Returns Ok(sanitized_name) or Err(error_message).
pub fn sanitize_vault_name(name: &str) -> Result<String, &'static str> {
    let trimmed = name.trim();

    // Check empty
    if trimmed.is_empty() {
        return Err("Vault name cannot be empty");
    }

    // Check length
    if trimmed.len() > MAX_VAULT_NAME_LENGTH {
        return Err("Vault name too long (max 64 characters)");
    }

    // Check for path traversal attempts
    if trimmed.contains("..") || trimmed.contains('/') || trimmed.contains('\\') {
        return Err("Vault name contains invalid characters");
    }

    // Check for null bytes
    if trimmed.contains('\0') {
        return Err("Vault name contains invalid characters");
    }

    // Validate all characters
    if !trimmed.chars().all(|c| ALLOWED_CHARS.contains(c)) {
        return Err("Vault name can only contain letters, numbers, spaces, hyphens, and underscores");
    }

    // Don't allow names that start with a dot (hidden files)
    if trimmed.starts_with('.') {
        return Err("Vault name cannot start with a dot");
    }

    Ok(trimmed.to_string())
}

/// Returns the base data directory for storing QuickPass vault files.
pub fn data_dir() -> PathBuf {
    if let Some(proj_dirs) = ProjectDirs::from("com", "KANFER", "QuickPass") {
        let dir = proj_dirs.data_dir();
        let _ = fs::create_dir_all(dir);
        dir.to_path_buf()
    } else {
        PathBuf::from(".")
    }
}

/// Builds the full vault file path for a given vault name.
pub fn vault_file_path(vault_name: &str) -> PathBuf {
    data_dir().join(format!("encrypted_vault_{vault_name}.json"))
}

/// Scans the data directory to find existing vault names.
pub fn scan_vaults_in_dir() -> Vec<String> {
    let mut results = Vec::new();
    if let Ok(entries) = fs::read_dir(data_dir()) {
        for entry in entries.flatten() {
            let path = entry.path();
            let fname = path.file_name().unwrap_or_default().to_string_lossy();
            if fname.starts_with("encrypted_vault_") && fname.ends_with(".json") {
                let middle = &fname["encrypted_vault_".len()..fname.len() - ".json".len()];
                results.push(middle.to_string());
            }
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_vault_name_valid() {
        assert!(sanitize_vault_name("MyVault").is_ok());
        assert!(sanitize_vault_name("My Vault 123").is_ok());
        assert!(sanitize_vault_name("vault-name_2").is_ok());
        assert_eq!(sanitize_vault_name("  trimmed  ").unwrap(), "trimmed");
    }

    #[test]
    fn test_sanitize_vault_name_empty() {
        assert!(sanitize_vault_name("").is_err());
        assert!(sanitize_vault_name("   ").is_err());
    }

    #[test]
    fn test_sanitize_vault_name_path_traversal() {
        assert!(sanitize_vault_name("../../../etc/passwd").is_err());
        assert!(sanitize_vault_name("vault/../secret").is_err());
        assert!(sanitize_vault_name("vault/secret").is_err());
        assert!(sanitize_vault_name("vault\\secret").is_err());
    }

    #[test]
    fn test_sanitize_vault_name_special_chars() {
        assert!(sanitize_vault_name("vault<script>").is_err());
        assert!(sanitize_vault_name("vault;rm -rf").is_err());
        assert!(sanitize_vault_name("vault|cat").is_err());
        assert!(sanitize_vault_name("vault\0null").is_err());
    }

    #[test]
    fn test_sanitize_vault_name_hidden_file() {
        assert!(sanitize_vault_name(".hidden").is_err());
        assert!(sanitize_vault_name("..").is_err());
    }

    #[test]
    fn test_sanitize_vault_name_too_long() {
        let long_name = "a".repeat(65);
        assert!(sanitize_vault_name(&long_name).is_err());

        let max_name = "a".repeat(64);
        assert!(sanitize_vault_name(&max_name).is_ok());
    }
}
