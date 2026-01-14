use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::error::Error as StdError;
use std::fs;
use std::io::{Error as IoError, ErrorKind};
use std::path::Path;
use zeroize::Zeroize;

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};

use crate::manager::vault_file_path;
use crate::security::{SecurityLevel, argon2_for_level, generate_random_salt};

/// Each vault entry
#[derive(Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    pub website: String,
    pub username: String,
    pub password: String,
    pub tags: Vec<String>,
}

/// Metadata stored (encrypted) along with the vault entries
#[derive(Clone, Serialize, Deserialize)]
pub struct VaultMetadata {
    pub last_accessed: Option<String>,
    #[serde(default)]
    pub custom_tags: Vec<String>,
}

/// This struct is what's actually serialized/encrypted as the vault data.
#[derive(Clone, Serialize, Deserialize)]
pub struct VaultData {
    pub entries: Vec<VaultEntry>,
    pub metadata: VaultMetadata,
}

/// The on-disk format for the entire vault file.
#[derive(Serialize, Deserialize)]
pub struct EncryptedVaultFile {
    /// Per-vault random salt for Argon2 (base64 encoded)
    pub salt: String,

    pub master_hash: String,
    pub pattern_hash: Option<String>,

    pub encrypted_key_pw: Vec<u8>,
    pub nonce_pw: Vec<u8>,

    pub encrypted_key_pt: Option<Vec<u8>>,
    pub nonce_pt: Option<Vec<u8>>,

    pub vault_ciphertext: Vec<u8>,
    pub vault_nonce: Vec<u8>,

    // We store the chosen Argon2 security level in plaintext
    pub security_level: crate::security::SecurityLevel,

    // Plaintext field to avoid expensive decryption in Vault Manager
    pub last_accessed_plaintext: Option<String>,
}

// ----------------------------------------------------------------
// Encryption/Decryption Helpers
// ----------------------------------------------------------------

/// Encrypt arbitrary bytes with a given 256-bit vault_key, returning (nonce, ciphertext).
fn encrypt_vault_bytes(
    bytes: &[u8],
    vault_key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn StdError>> {
    let cipher_key = Key::<Aes256Gcm>::from_slice(vault_key);
    let cipher = Aes256Gcm::new(cipher_key);
    let mut rng = rand::rng();
    let mut nonce_arr = [0u8; 12];
    rng.fill_bytes(&mut nonce_arr);
    let nonce = Nonce::from_slice(&nonce_arr);
    let ciphertext = cipher
        .encrypt(nonce, bytes)
        .map_err(|e| IoError::new(ErrorKind::InvalidData, e.to_string()))?;
    Ok((nonce_arr.to_vec(), ciphertext))
}

/// Decrypt with a given 256-bit key, returning the plaintext bytes.
fn decrypt_vault_data(
    (nonce_bytes, ciphertext): (&[u8], &[u8]),
    vault_key: &[u8],
) -> Result<Vec<u8>, Box<dyn StdError>> {
    let cipher_key = Key::<Aes256Gcm>::from_slice(vault_key);
    let cipher = Aes256Gcm::new(cipher_key);
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| IoError::new(ErrorKind::InvalidData, e.to_string()))?;
    Ok(plaintext)
}

// ----------------------------------------------------------------
// Derived Key Helpers (for master password or pattern string)
// ----------------------------------------------------------------

/// Derive a 32-byte key from user input using Argon2id with the provided salt.
fn derive_key_from_input(input: &[u8], salt: &SaltString, level: SecurityLevel) -> [u8; 32] {
    let argon2 = argon2_for_level(level);
    let mut salt_buf = [0u8; 32];
    let salt_len = salt.decode_b64(&mut salt_buf).map(|s| s.len()).unwrap_or(16);
    let mut key = [0u8; 32];
    let _ = argon2.hash_password_into(input, &salt_buf[..salt_len], &mut key).ok();
    key
}

/// Encrypt some plaintext with a key derived from the user's input (password or pattern).
fn encrypt_with_derived_key(
    plaintext: &[u8],
    input: &[u8],
    salt: &SaltString,
    level: SecurityLevel,
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn StdError>> {
    let key_bytes = derive_key_from_input(input, salt, level);
    let cipher_key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(cipher_key);

    // Generate a new 12-byte nonce
    let mut rng = rand::rng();
    let mut nonce_arr = [0u8; 12];
    rng.fill_bytes(&mut nonce_arr);

    let nonce = Nonce::from_slice(&nonce_arr);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| IoError::new(ErrorKind::InvalidData, e.to_string()))?;

    let mut kb = key_bytes;
    kb.zeroize();
    Ok((ciphertext, nonce_arr.to_vec()))
}

/// Decrypt ciphertext with a key derived from user input (password or pattern).
fn decrypt_with_derived_key(
    ciphertext: &[u8],
    nonce_bytes: &[u8],
    input: &[u8],
    salt: &SaltString,
    level: SecurityLevel,
) -> Result<Vec<u8>, Box<dyn StdError>> {
    let key_bytes = derive_key_from_input(input, salt, level);
    let cipher_key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(cipher_key);

    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| IoError::new(ErrorKind::InvalidData, e.to_string()))?;

    let mut kb = key_bytes;
    kb.zeroize();

    Ok(plaintext)
}

// ----------------------------------------------------------------
// File read/write (with atomic writes)
// ----------------------------------------------------------------

/// Writes vault file atomically: write to temp file, then rename.
fn write_encrypted_vault_file(
    path: impl AsRef<Path>,
    file_data: &EncryptedVaultFile,
) -> Result<(), Box<dyn StdError>> {
    let path = path.as_ref();
    let temp_path = path.with_extension("tmp");

    let json = serde_json::to_string_pretty(file_data)
        .map_err(|e| IoError::new(ErrorKind::InvalidData, e.to_string()))?;
    let encoded = URL_SAFE_NO_PAD.encode(json);

    // Write to temporary file first
    fs::write(&temp_path, &encoded)?;

    // Atomic rename (on most filesystems)
    fs::rename(&temp_path, path)?;

    Ok(())
}

pub fn read_encrypted_vault_file(
    path: impl AsRef<Path>,
) -> Result<EncryptedVaultFile, Box<dyn StdError>> {
    let encoded = fs::read_to_string(path)?;
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded.trim())
        .map_err(|e| IoError::new(ErrorKind::InvalidData, e.to_string()))?;
    let file: EncryptedVaultFile = serde_json::from_slice(&decoded)
        .map_err(|e| IoError::new(ErrorKind::InvalidData, e.to_string()))?;
    Ok(file)
}

// ----------------------------------------------------------------
// Vault Data Manipulation
// ----------------------------------------------------------------

/// Create a new vault file with a random vault key, storing it encrypted by both master password and pattern.
pub fn create_new_vault_file(
    vault_name: &str,
    master_password: &str,
    pattern_hash_str: &str,
    level: SecurityLevel,
) -> Result<(String, String), Box<dyn StdError>> {
    let path = vault_file_path(vault_name);
    let argon2 = argon2_for_level(level);

    // Generate a unique random salt for this vault
    let salt = generate_random_salt();

    let master_hash = argon2
        .hash_password(master_password.as_bytes(), &salt)
        .map_err(|e| IoError::new(ErrorKind::InvalidData, e.to_string()))?
        .to_string();
    let hashed_pattern = argon2
        .hash_password(pattern_hash_str.as_bytes(), &salt)
        .map_err(|e| IoError::new(ErrorKind::InvalidData, e.to_string()))?
        .to_string();

    // Derive random vault_key
    let mut vault_key = [0u8; 32];
    rand::rng().fill_bytes(&mut vault_key);

    // Encrypt the vault_key under the master password
    let (encrypted_key_pw, nonce_pw) =
        encrypt_with_derived_key(&vault_key, master_password.as_bytes(), &salt, level)?;
    // Encrypt the vault_key under the pattern
    let (encrypted_key_pt, nonce_pt) =
        encrypt_with_derived_key(&vault_key, pattern_hash_str.as_bytes(), &salt, level)?;

    // Make an empty vault data
    let vault_data = VaultData {
        entries: Vec::new(),
        metadata: VaultMetadata {
            last_accessed: None,
            custom_tags: Vec::new(),
        },
    };
    let vault_data_json = serde_json::to_vec(&vault_data)?;
    let (vault_nonce, vault_ciphertext) = encrypt_vault_bytes(&vault_data_json, &vault_key)?;

    vault_key.zeroize();

    let ef = EncryptedVaultFile {
        salt: salt.to_string(),
        master_hash,
        pattern_hash: Some(hashed_pattern),
        encrypted_key_pw,
        nonce_pw,
        encrypted_key_pt: Some(encrypted_key_pt),
        nonce_pt: Some(nonce_pt),
        vault_ciphertext,
        vault_nonce,
        security_level: level,
        last_accessed_plaintext: None,
    };

    write_encrypted_vault_file(path, &ef)?;
    Ok((ef.master_hash.clone(), ef.pattern_hash.clone().unwrap()))
}

/// Load just the vault key by verifying either the master password or the pattern.
pub fn load_vault_key_only(
    vault_name: &str,
    master_password: &str,
    pattern: Option<&[u8]>,
    level: SecurityLevel,
) -> Result<(String, Option<String>, Vec<u8>), Box<dyn StdError>> {
    let ef = read_encrypted_vault_file(vault_file_path(vault_name))?;
    let argon2 = argon2_for_level(level);

    // Parse the stored salt
    let salt = SaltString::from_b64(&ef.salt)
        .map_err(|e| IoError::new(ErrorKind::InvalidData, format!("Invalid salt: {}", e)))?;

    if let Some(patt_bytes) = pattern {
        // Check if a pattern hash is stored
        let phash = ef
            .pattern_hash
            .as_ref()
            .ok_or_else(|| IoError::new(ErrorKind::NotFound, "No pattern hash stored"))?;
        let parsed_hash = PasswordHash::new(phash)
            .map_err(|e| IoError::new(ErrorKind::InvalidData, e.to_string()))?;
        argon2
            .verify_password(patt_bytes, &parsed_hash)
            .map_err(|_| IoError::new(ErrorKind::InvalidData, "Pattern mismatch"))?;

        let enc_key_pt = ef
            .encrypted_key_pt
            .as_ref()
            .ok_or_else(|| IoError::new(ErrorKind::NotFound, "No encrypted_key_pt"))?;
        let nonce_pt = ef
            .nonce_pt
            .as_ref()
            .ok_or_else(|| IoError::new(ErrorKind::NotFound, "No nonce_pt"))?;

        let vault_key = decrypt_with_derived_key(enc_key_pt, nonce_pt, patt_bytes, &salt, level)?;
        Ok((ef.master_hash, ef.pattern_hash, vault_key))
    } else {
        // text-based unlock with master password
        if !master_password.is_empty() {
            let parsed_hash = PasswordHash::new(&ef.master_hash)
                .map_err(|e| IoError::new(ErrorKind::InvalidData, e.to_string()))?;
            argon2
                .verify_password(master_password.as_bytes(), &parsed_hash)
                .map_err(|_| IoError::new(ErrorKind::InvalidData, "Master password mismatch"))?;
        }
        let vault_key = decrypt_with_derived_key(
            &ef.encrypted_key_pw,
            &ef.nonce_pw,
            master_password.as_bytes(),
            &salt,
            level,
        )?;
        Ok((ef.master_hash, ef.pattern_hash, vault_key))
    }
}

/// Load and decrypt the entire vault data using the given vault_key.
pub fn load_vault_data_decrypted(
    vault_name: &str,
    vault_key: &[u8],
) -> Result<VaultData, Box<dyn StdError>> {
    let ef = read_encrypted_vault_file(vault_file_path(vault_name))?;
    let plaintext = decrypt_vault_data((&ef.vault_nonce, &ef.vault_ciphertext), vault_key)?;
    let data: VaultData = serde_json::from_slice(&plaintext)
        .map_err(|e| IoError::new(ErrorKind::InvalidData, e.to_string()))?;
    Ok(data)
}

/// Update the last_accessed time in the vault (and optionally the entries) by re-encrypting the file.
pub fn update_last_accessed_in_vault(
    vault_name: &str,
    vault_key: &[u8],
    entries: &[VaultEntry],
) -> Result<(), Box<dyn StdError>> {
    let mut ef = read_encrypted_vault_file(vault_file_path(vault_name))?;
    let plaintext = decrypt_vault_data((&ef.vault_nonce, &ef.vault_ciphertext), vault_key)?;
    let mut data: VaultData = serde_json::from_slice(&plaintext)
        .map_err(|e| IoError::new(ErrorKind::InvalidData, e.to_string()))?;

    // update
    data.entries = entries.to_vec();
    data.metadata.last_accessed = Some(current_utc_timestamp_string());

    let new_json = serde_json::to_vec(&data)?;
    let (vault_nonce, vault_ciphertext) = encrypt_vault_bytes(&new_json, vault_key)?;

    ef.vault_nonce = vault_nonce;
    ef.vault_ciphertext = vault_ciphertext;

    // Also set the plaintext "last_accessed" so we don't have to decrypt in manager
    ef.last_accessed_plaintext = Some(current_utc_timestamp_string());

    write_encrypted_vault_file(vault_file_path(vault_name), &ef)?;
    Ok(())
}

/// Save new vault entries to the existing vault file.
pub fn save_vault_file(
    vault_name: &str,
    master_hash: &str,
    pattern_hash: Option<&str>,
    vault_key: &[u8],
    vault_entries: &[VaultEntry],
) -> Result<(), Box<dyn StdError>> {
    let mut ef = read_encrypted_vault_file(vault_file_path(vault_name))?;
    let old_plain = decrypt_vault_data((&ef.vault_nonce, &ef.vault_ciphertext), vault_key)?;
    let mut data: VaultData = serde_json::from_slice(&old_plain)?;
    data.entries = vault_entries.to_vec();

    let new_json = serde_json::to_vec(&data)?;
    let (vault_nonce, vault_ciphertext) = encrypt_vault_bytes(&new_json, vault_key)?;

    ef.vault_nonce = vault_nonce;
    ef.vault_ciphertext = vault_ciphertext;
    ef.master_hash = master_hash.to_string();
    ef.pattern_hash = pattern_hash.map(|p| p.to_string());

    write_encrypted_vault_file(vault_file_path(vault_name), &ef)?;
    Ok(())
}

/// Update the master password encryption. Returns the new master hash.
pub fn update_master_password_with_key(
    vault_name: &str,
    _old_password: &str,
    new_password: &str,
    vault_key: &[u8],
    vault_entries: &[VaultEntry],
    pattern_hash: Option<&str>,
    level: SecurityLevel,
) -> Result<String, Box<dyn StdError>> {
    let mut ef = read_encrypted_vault_file(vault_file_path(vault_name))?;
    let argon2 = argon2_for_level(level);

    // Use the existing salt from the vault
    let salt = SaltString::from_b64(&ef.salt)
        .map_err(|e| IoError::new(ErrorKind::InvalidData, format!("Invalid salt: {}", e)))?;

    let new_hash = argon2
        .hash_password(new_password.as_bytes(), &salt)
        .map_err(|e| IoError::new(ErrorKind::InvalidData, e.to_string()))?
        .to_string();

    // Re-encrypt vault_key with new password
    let (encrypted_key_pw, nonce_pw) =
        encrypt_with_derived_key(vault_key, new_password.as_bytes(), &salt, level)?;

    // Re-encrypt vault data
    let old_plain = decrypt_vault_data((&ef.vault_nonce, &ef.vault_ciphertext), vault_key)?;
    let mut data: VaultData = serde_json::from_slice(&old_plain)?;
    data.entries = vault_entries.to_vec();

    let new_json = serde_json::to_vec(&data)?;
    let (vault_nonce, vault_ciphertext) = encrypt_vault_bytes(&new_json, vault_key)?;

    ef.master_hash = new_hash.clone();
    ef.pattern_hash = pattern_hash.map(|s| s.to_string());
    ef.encrypted_key_pw = encrypted_key_pw;
    ef.nonce_pw = nonce_pw;
    ef.vault_nonce = vault_nonce;
    ef.vault_ciphertext = vault_ciphertext;

    write_encrypted_vault_file(vault_file_path(vault_name), &ef)?;
    Ok(new_hash)
}

/// Update the pattern encryption. Returns the new pattern hash.
pub fn update_pattern_with_key(
    vault_name: &str,
    _old_password: &str,
    new_pattern_str: &str,
    vault_key: &[u8],
    vault_entries: &[VaultEntry],
    level: SecurityLevel,
) -> Result<String, Box<dyn StdError>> {
    let mut ef = read_encrypted_vault_file(vault_file_path(vault_name))?;
    let argon2 = argon2_for_level(level);

    // Use the existing salt from the vault
    let salt = SaltString::from_b64(&ef.salt)
        .map_err(|e| IoError::new(ErrorKind::InvalidData, format!("Invalid salt: {}", e)))?;

    let new_ph = argon2
        .hash_password(new_pattern_str.as_bytes(), &salt)
        .map_err(|e| IoError::new(ErrorKind::InvalidData, e.to_string()))?
        .to_string();

    let (encrypted_key_pt, nonce_pt) =
        encrypt_with_derived_key(vault_key, new_pattern_str.as_bytes(), &salt, level)?;

    let old_plain = decrypt_vault_data((&ef.vault_nonce, &ef.vault_ciphertext), vault_key)?;
    let mut data: VaultData = serde_json::from_slice(&old_plain)?;
    data.entries = vault_entries.to_vec();

    let new_json = serde_json::to_vec(&data)?;
    let (vault_nonce, vault_ciphertext) = encrypt_vault_bytes(&new_json, vault_key)?;

    ef.pattern_hash = Some(new_ph.clone());
    ef.encrypted_key_pt = Some(encrypted_key_pt);
    ef.nonce_pt = Some(nonce_pt);
    ef.vault_nonce = vault_nonce;
    ef.vault_ciphertext = vault_ciphertext;

    write_encrypted_vault_file(vault_file_path(vault_name), &ef)?;
    Ok(new_ph)
}

/// Update custom tags in the vault metadata.
pub fn update_custom_tags(
    vault_name: &str,
    vault_key: &[u8],
    vault_entries: &[VaultEntry],
    custom_tags: &[String],
) -> Result<(), Box<dyn StdError>> {
    let mut ef = read_encrypted_vault_file(vault_file_path(vault_name))?;
    let old_plain = decrypt_vault_data((&ef.vault_nonce, &ef.vault_ciphertext), vault_key)?;
    let mut data: VaultData = serde_json::from_slice(&old_plain)?;

    data.entries = vault_entries.to_vec();
    data.metadata.custom_tags = custom_tags.to_vec();

    let new_json = serde_json::to_vec(&data)?;
    let (vault_nonce, vault_ciphertext) = encrypt_vault_bytes(&new_json, vault_key)?;

    ef.vault_nonce = vault_nonce;
    ef.vault_ciphertext = vault_ciphertext;

    write_encrypted_vault_file(vault_file_path(vault_name), &ef)?;
    Ok(())
}

// ----------------------------------------------------------------
// Export/Import Functions
// ----------------------------------------------------------------

/// Export vault entries to CSV format (unencrypted).
/// WARNING: This exports passwords in plain text!
pub fn export_to_csv(entries: &[VaultEntry]) -> String {
    let mut csv = String::from("website,username,password,tags\n");
    for entry in entries {
        let tags = entry.tags.join(";");
        // Escape commas and quotes in fields
        let website = escape_csv_field(&entry.website);
        let username = escape_csv_field(&entry.username);
        let password = escape_csv_field(&entry.password);
        let tags_escaped = escape_csv_field(&tags);
        csv.push_str(&format!("{},{},{},{}\n", website, username, password, tags_escaped));
    }
    csv
}

fn escape_csv_field(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

/// Export vault to encrypted JSON format (can be imported later).
pub fn export_encrypted_backup(
    vault_name: &str,
    vault_key: &[u8],
    entries: &[VaultEntry],
    custom_tags: &[String],
) -> Result<String, Box<dyn StdError>> {
    let vault_data = VaultData {
        entries: entries.to_vec(),
        metadata: VaultMetadata {
            last_accessed: Some(current_utc_timestamp_string()),
            custom_tags: custom_tags.to_vec(),
        },
    };

    let json = serde_json::to_vec(&vault_data)?;
    let (nonce, ciphertext) = encrypt_vault_bytes(&json, vault_key)?;

    // Create a backup structure
    #[derive(Serialize)]
    struct BackupFile {
        version: u32,
        vault_name: String,
        nonce: String,
        ciphertext: String,
        created: String,
    }

    let backup = BackupFile {
        version: 1,
        vault_name: vault_name.to_string(),
        nonce: URL_SAFE_NO_PAD.encode(&nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(&ciphertext),
        created: current_utc_timestamp_string(),
    };

    let backup_json = serde_json::to_string_pretty(&backup)?;
    Ok(backup_json)
}

/// Import vault from encrypted backup JSON.
/// Returns the decrypted VaultData if successful.
pub fn import_encrypted_backup(
    backup_json: &str,
    vault_key: &[u8],
) -> Result<VaultData, Box<dyn StdError>> {
    #[derive(Deserialize)]
    struct BackupFile {
        #[allow(dead_code)]
        version: u32,
        #[allow(dead_code)]
        vault_name: String,
        nonce: String,
        ciphertext: String,
        #[allow(dead_code)]
        created: String,
    }

    let backup: BackupFile = serde_json::from_str(backup_json)?;
    let nonce = URL_SAFE_NO_PAD.decode(&backup.nonce)
        .map_err(|e| IoError::new(ErrorKind::InvalidData, e.to_string()))?;
    let ciphertext = URL_SAFE_NO_PAD.decode(&backup.ciphertext)
        .map_err(|e| IoError::new(ErrorKind::InvalidData, e.to_string()))?;

    let plaintext = decrypt_vault_data((&nonce, &ciphertext), vault_key)?;
    let vault_data: VaultData = serde_json::from_slice(&plaintext)?;

    Ok(vault_data)
}

// ----------------------------------------------------------------
// Time Helpers (using chrono for correct date handling)
// ----------------------------------------------------------------

/// Produce a human-readable UTC timestamp using chrono.
fn current_utc_timestamp_string() -> String {
    Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

// ----------------------------------------------------------------
// Pattern Helper
// ----------------------------------------------------------------

/// Convert pattern (row,col) list into a string for Argon2 hashing
pub fn pattern_to_string(pattern: &[(usize, usize)]) -> String {
    pattern
        .iter()
        .map(|(r, c)| format!("{},{}", r, c))
        .collect::<Vec<_>>()
        .join("-")
}

// ------------------ TESTS ------------------
#[cfg(test)]
mod tests {
    use super::*;

    // ---- Pattern Conversion Tests (Phase 5.3) ----

    #[test]
    fn test_pattern_to_string_empty() {
        let pattern: Vec<(usize, usize)> = vec![];
        assert_eq!(pattern_to_string(&pattern), "");
    }

    #[test]
    fn test_pattern_to_string_single() {
        let pattern = vec![(0, 0)];
        assert_eq!(pattern_to_string(&pattern), "0,0");
    }

    #[test]
    fn test_pattern_to_string_multiple() {
        let pattern = vec![(0, 0), (1, 2), (3, 4), (5, 5)];
        assert_eq!(pattern_to_string(&pattern), "0,0-1,2-3,4-5,5");
    }

    #[test]
    fn test_pattern_to_string_eight_cells() {
        // Minimum required pattern length
        let pattern = vec![
            (0, 0), (0, 1), (0, 2), (1, 0),
            (1, 1), (1, 2), (2, 0), (2, 1),
        ];
        let result = pattern_to_string(&pattern);
        assert_eq!(result, "0,0-0,1-0,2-1,0-1,1-1,2-2,0-2,1");
    }

    // ---- Encryption Round-Trip Tests (Phase 5.1) ----

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let test_data = b"Hello, QuickPass!";
        let mut vault_key = [0u8; 32];
        rand::rng().fill_bytes(&mut vault_key);

        let (nonce, ciphertext) = encrypt_vault_bytes(test_data, &vault_key).unwrap();
        let decrypted = decrypt_vault_data((&nonce, &ciphertext), &vault_key).unwrap();

        assert_eq!(decrypted, test_data);
    }

    #[test]
    fn test_encrypt_decrypt_empty_data() {
        let test_data = b"";
        let mut vault_key = [0u8; 32];
        rand::rng().fill_bytes(&mut vault_key);

        let (nonce, ciphertext) = encrypt_vault_bytes(test_data, &vault_key).unwrap();
        let decrypted = decrypt_vault_data((&nonce, &ciphertext), &vault_key).unwrap();

        assert_eq!(decrypted, test_data);
    }

    #[test]
    fn test_encrypt_decrypt_large_data() {
        // Test with larger data (simulating many vault entries)
        let test_data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let mut vault_key = [0u8; 32];
        rand::rng().fill_bytes(&mut vault_key);

        let (nonce, ciphertext) = encrypt_vault_bytes(&test_data, &vault_key).unwrap();
        let decrypted = decrypt_vault_data((&nonce, &ciphertext), &vault_key).unwrap();

        assert_eq!(decrypted, test_data);
    }

    #[test]
    fn test_wrong_key_fails_decrypt() {
        let test_data = b"Secret password data";
        let mut vault_key = [0u8; 32];
        rand::rng().fill_bytes(&mut vault_key);

        let (nonce, ciphertext) = encrypt_vault_bytes(test_data, &vault_key).unwrap();

        // Try decrypting with wrong key
        let mut wrong_key = [0u8; 32];
        rand::rng().fill_bytes(&mut wrong_key);

        let result = decrypt_vault_data((&nonce, &ciphertext), &wrong_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_vault_data_serialization() {
        let vault_data = VaultData {
            entries: vec![
                VaultEntry {
                    website: "example.com".to_string(),
                    username: "user@example.com".to_string(),
                    password: "s3cr3t!".to_string(),
                    tags: vec!["Work".to_string()],
                },
            ],
            metadata: VaultMetadata {
                last_accessed: Some("2026-01-14 12:00:00 UTC".to_string()),
                custom_tags: vec!["CustomTag".to_string()],
            },
        };

        // Serialize and deserialize
        let json = serde_json::to_vec(&vault_data).unwrap();
        let deserialized: VaultData = serde_json::from_slice(&json).unwrap();

        assert_eq!(deserialized.entries.len(), 1);
        assert_eq!(deserialized.entries[0].website, "example.com");
        assert_eq!(deserialized.entries[0].username, "user@example.com");
        assert_eq!(deserialized.entries[0].password, "s3cr3t!");
    }

    #[test]
    fn test_encrypt_decrypt_vault_data_full() {
        let vault_data = VaultData {
            entries: vec![
                VaultEntry {
                    website: "bank.com".to_string(),
                    username: "myuser".to_string(),
                    password: "BankP@ss123!".to_string(),
                    tags: vec!["Finance".to_string(), "Important".to_string()],
                },
                VaultEntry {
                    website: "email.com".to_string(),
                    username: "email@test.com".to_string(),
                    password: "Em@ilS3cure!".to_string(),
                    tags: vec!["Personal".to_string()],
                },
            ],
            metadata: VaultMetadata {
                last_accessed: None,
                custom_tags: Vec::new(),
            },
        };

        let json = serde_json::to_vec(&vault_data).unwrap();
        let mut vault_key = [0u8; 32];
        rand::rng().fill_bytes(&mut vault_key);

        let (nonce, ciphertext) = encrypt_vault_bytes(&json, &vault_key).unwrap();
        let decrypted = decrypt_vault_data((&nonce, &ciphertext), &vault_key).unwrap();
        let restored: VaultData = serde_json::from_slice(&decrypted).unwrap();

        assert_eq!(restored.entries.len(), 2);
        assert_eq!(restored.entries[0].website, "bank.com");
        assert_eq!(restored.entries[1].website, "email.com");
    }
}
