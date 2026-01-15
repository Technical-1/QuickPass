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
    /// When this entry was created (ISO 8601)
    #[serde(default)]
    pub created_at: Option<String>,
    /// When this entry was last modified (ISO 8601)
    #[serde(default)]
    pub modified_at: Option<String>,
    /// TOTP secret (Base32 encoded) for 2FA
    #[serde(default)]
    pub totp_secret: Option<String>,
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

    /// Encrypted TOTP secret for vault-level 2FA (encrypted with vault key)
    #[serde(default)]
    pub totp_secret_encrypted: Option<Vec<u8>>,
    /// Nonce for TOTP secret encryption
    #[serde(default)]
    pub totp_nonce: Option<Vec<u8>>,
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

/// Decrypt bytes with a given 256-bit vault_key.
fn decrypt_vault_bytes(
    ciphertext: &[u8],
    nonce: &[u8],
    vault_key: &[u8],
) -> Result<Vec<u8>, Box<dyn StdError>> {
    let cipher_key = Key::<Aes256Gcm>::from_slice(vault_key);
    let cipher = Aes256Gcm::new(cipher_key);
    let nonce = Nonce::from_slice(nonce);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| IoError::new(ErrorKind::InvalidData, e.to_string()))?;
    Ok(plaintext)
}

/// AES-GCM nonce length (12 bytes)
const AES_GCM_NONCE_LENGTH: usize = 12;
/// AES-GCM authentication tag length (16 bytes)
const AES_GCM_TAG_LENGTH: usize = 16;

/// Validate encrypted data structure before decryption
fn validate_encrypted_data(nonce: &[u8], ciphertext: &[u8]) -> Result<(), Box<dyn StdError>> {
    if nonce.len() != AES_GCM_NONCE_LENGTH {
        return Err(Box::new(IoError::new(
            ErrorKind::InvalidData,
            format!(
                "Invalid nonce length: expected {}, got {} - vault file may be corrupted",
                AES_GCM_NONCE_LENGTH,
                nonce.len()
            ),
        )));
    }
    if ciphertext.len() < AES_GCM_TAG_LENGTH {
        return Err(Box::new(IoError::new(
            ErrorKind::InvalidData,
            "Ciphertext too short - vault file may be corrupted",
        )));
    }
    Ok(())
}

/// Decrypt with a given 256-bit key, returning the plaintext bytes.
fn decrypt_vault_data(
    (nonce_bytes, ciphertext): (&[u8], &[u8]),
    vault_key: &[u8],
) -> Result<Vec<u8>, Box<dyn StdError>> {
    // Validate nonce and ciphertext lengths before attempting decryption
    validate_encrypted_data(nonce_bytes, ciphertext)?;

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
    // Validate nonce and ciphertext lengths before attempting decryption
    validate_encrypted_data(nonce_bytes, ciphertext)?;

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
/// If totp_secret is provided, it will be encrypted and stored for vault-level 2FA.
pub fn create_new_vault_file(
    vault_name: &str,
    master_password: &str,
    pattern_hash_str: &str,
    level: SecurityLevel,
    totp_secret: Option<&str>,
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

    // Encrypt TOTP secret if provided
    let (totp_secret_encrypted, totp_nonce) = if let Some(secret) = totp_secret {
        let (nonce, ciphertext) = encrypt_vault_bytes(secret.as_bytes(), &vault_key)?;
        (Some(ciphertext), Some(nonce))
    } else {
        (None, None)
    };

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
        totp_secret_encrypted,
        totp_nonce,
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
        // SECURITY: Reject empty patterns - defense in depth
        if patt_bytes.is_empty() {
            return Err(Box::new(IoError::new(
                ErrorKind::InvalidInput,
                "Pattern cannot be empty",
            )));
        }

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
        // SECURITY: Reject empty passwords - this is critical to prevent bypass
        if master_password.is_empty() {
            return Err(Box::new(IoError::new(
                ErrorKind::InvalidInput,
                "Master password cannot be empty",
            )));
        }

        let parsed_hash = PasswordHash::new(&ef.master_hash)
            .map_err(|e| IoError::new(ErrorKind::InvalidData, e.to_string()))?;
        argon2
            .verify_password(master_password.as_bytes(), &parsed_hash)
            .map_err(|_| IoError::new(ErrorKind::InvalidData, "Master password mismatch"))?;

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

/// Create a new VaultEntry with current timestamp
pub fn create_entry_with_timestamp(
    website: String,
    username: String,
    password: String,
    tags: Vec<String>,
) -> VaultEntry {
    let now = current_utc_timestamp_string();
    VaultEntry {
        website,
        username,
        password,
        tags,
        created_at: Some(now.clone()),
        modified_at: Some(now),
        totp_secret: None,
    }
}

/// Create a new VaultEntry with TOTP secret
pub fn create_entry_with_totp(
    website: String,
    username: String,
    password: String,
    tags: Vec<String>,
    totp_secret: Option<String>,
) -> VaultEntry {
    let now = current_utc_timestamp_string();
    VaultEntry {
        website,
        username,
        password,
        tags,
        created_at: Some(now.clone()),
        modified_at: Some(now),
        totp_secret,
    }
}

/// Update an entry's modified_at timestamp
pub fn update_entry_timestamp(entry: &mut VaultEntry) {
    entry.modified_at = Some(current_utc_timestamp_string());
}

/// Calculate password age in days from modified_at timestamp
pub fn password_age_days(entry: &VaultEntry) -> Option<i64> {
    let modified = entry.modified_at.as_ref().or(entry.created_at.as_ref())?;
    // Parse the timestamp (format: "2026-01-14 12:00:00 UTC")
    if let Ok(parsed) = chrono::NaiveDateTime::parse_from_str(
        modified.trim_end_matches(" UTC"),
        "%Y-%m-%d %H:%M:%S",
    ) {
        let now = Utc::now().naive_utc();
        Some((now - parsed).num_days())
    } else {
        None
    }
}

// ----------------------------------------------------------------
// TOTP Functions
// ----------------------------------------------------------------

use totp_rs::{Algorithm, TOTP, Secret};

/// Generate a TOTP code from a Base32-encoded secret
/// Returns the 6-digit code and seconds remaining until next code
pub fn generate_totp_code(secret: &str) -> Result<(String, u64), Box<dyn StdError>> {
    let secret_bytes = Secret::Encoded(secret.to_string())
        .to_bytes()
        .map_err(|e| IoError::new(ErrorKind::InvalidData, format!("Invalid TOTP secret: {}", e)))?;

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,      // 6 digits
        1,      // 1 step skew allowed
        30,     // 30 second step
        secret_bytes,
    ).map_err(|e| IoError::new(ErrorKind::InvalidData, format!("Failed to create TOTP: {}", e)))?;

    let code = totp.generate_current()
        .map_err(|e| IoError::new(ErrorKind::InvalidData, format!("Failed to generate TOTP: {}", e)))?;

    // Calculate seconds remaining
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let seconds_remaining = 30 - (now % 30);

    Ok((code, seconds_remaining))
}

/// Generate a new random TOTP secret (Base32 encoded)
pub fn generate_totp_secret() -> String {
    use totp_rs::Secret;
    let secret = Secret::generate_secret();
    secret.to_encoded().to_string()
}

/// Validate a TOTP secret format (must be valid Base32)
pub fn validate_totp_secret(secret: &str) -> bool {
    Secret::Encoded(secret.to_string()).to_bytes().is_ok()
}

/// Generate a TOTP URI for use in QR codes
/// Format: otpauth://totp/Label?secret=SECRET&issuer=Issuer
pub fn generate_totp_uri(secret: &str, account: &str, issuer: &str) -> String {
    let label = if issuer.is_empty() {
        account.to_string()
    } else {
        format!("{}:{}", issuer, account)
    };

    // URL encode the label and issuer
    let encoded_label = label.replace(' ', "%20").replace(':', "%3A");
    let encoded_issuer = issuer.replace(' ', "%20");

    if issuer.is_empty() {
        format!("otpauth://totp/{}?secret={}", encoded_label, secret)
    } else {
        format!(
            "otpauth://totp/{}?secret={}&issuer={}",
            encoded_label, secret, encoded_issuer
        )
    }
}

/// Generate QR code data as a 2D boolean grid
/// Returns (width, data) where data[y * width + x] indicates a dark module
pub fn generate_qr_code_data(content: &str) -> Result<(usize, Vec<bool>), Box<dyn StdError>> {
    use qrcode::QrCode;

    let code = QrCode::new(content.as_bytes())
        .map_err(|e| IoError::new(ErrorKind::InvalidData, format!("QR code generation failed: {}", e)))?;

    let width = code.width();
    let data: Vec<bool> = code
        .into_colors()
        .into_iter()
        .map(|c| c == qrcode::Color::Dark)
        .collect();

    Ok((width, data))
}

// ----------------------------------------------------------------
// Vault-level 2FA Functions
// ----------------------------------------------------------------

/// Check if a vault has 2FA enabled
pub fn vault_has_2fa(vault_name: &str) -> bool {
    if let Ok(ef) = read_encrypted_vault_file(vault_file_path(vault_name)) {
        ef.totp_secret_encrypted.is_some()
    } else {
        false
    }
}

/// Decrypt and verify a TOTP code for vault-level 2FA
/// Returns Ok(true) if code matches, Ok(false) if code doesn't match
pub fn verify_vault_totp(
    vault_name: &str,
    vault_key: &[u8],
    totp_code: &str,
) -> Result<bool, Box<dyn StdError>> {
    let ef = read_encrypted_vault_file(vault_file_path(vault_name))?;

    let encrypted = ef
        .totp_secret_encrypted
        .ok_or_else(|| IoError::new(ErrorKind::NotFound, "Vault does not have 2FA enabled"))?;
    let nonce = ef
        .totp_nonce
        .ok_or_else(|| IoError::new(ErrorKind::NotFound, "Missing TOTP nonce"))?;

    // Decrypt the TOTP secret
    let secret_bytes = decrypt_vault_bytes(&encrypted, &nonce, vault_key)?;
    let secret = String::from_utf8(secret_bytes)
        .map_err(|e| IoError::new(ErrorKind::InvalidData, e.to_string()))?;

    // Generate current TOTP code and compare
    match generate_totp_code(&secret) {
        Ok((expected_code, _)) => Ok(expected_code == totp_code),
        Err(e) => Err(e),
    }
}

/// Enable 2FA on an existing vault
pub fn enable_vault_2fa(
    vault_name: &str,
    vault_key: &[u8],
    totp_secret: &str,
) -> Result<(), Box<dyn StdError>> {
    let path = vault_file_path(vault_name);
    let mut ef = read_encrypted_vault_file(&path)?;

    // Encrypt the TOTP secret
    let (nonce, ciphertext) = encrypt_vault_bytes(totp_secret.as_bytes(), vault_key)?;
    ef.totp_secret_encrypted = Some(ciphertext);
    ef.totp_nonce = Some(nonce);

    write_encrypted_vault_file(path, &ef)
}

/// Disable 2FA on an existing vault
pub fn disable_vault_2fa(vault_name: &str) -> Result<(), Box<dyn StdError>> {
    let path = vault_file_path(vault_name);
    let mut ef = read_encrypted_vault_file(&path)?;

    ef.totp_secret_encrypted = None;
    ef.totp_nonce = None;

    write_encrypted_vault_file(path, &ef)
}

// ----------------------------------------------------------------
// Import from Other Password Managers
// ----------------------------------------------------------------

/// Supported import formats
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ImportFormat {
    /// QuickPass native CSV (website,username,password,tags)
    QuickPass,
    /// Bitwarden CSV export
    Bitwarden,
    /// 1Password CSV export
    OnePassword,
    /// LastPass CSV export
    LastPass,
    /// Generic CSV (tries to auto-detect columns)
    Generic,
}

/// Parse a CSV line, handling quoted fields
fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '"' if in_quotes => {
                // Check for escaped quote
                if chars.peek() == Some(&'"') {
                    current.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            }
            '"' if !in_quotes => {
                in_quotes = true;
            }
            ',' if !in_quotes => {
                fields.push(current.trim().to_string());
                current = String::new();
            }
            _ => {
                current.push(c);
            }
        }
    }
    fields.push(current.trim().to_string());
    fields
}

/// Import entries from Bitwarden CSV export
/// Format: folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
pub fn import_bitwarden_csv(csv_data: &str) -> Result<Vec<VaultEntry>, Box<dyn StdError>> {
    let mut entries = Vec::new();
    let lines: Vec<&str> = csv_data.lines().collect();

    if lines.is_empty() {
        return Ok(entries);
    }

    // Find column indices from header
    let header = parse_csv_line(lines[0]);
    let name_idx = header.iter().position(|h| h == "name");
    let uri_idx = header.iter().position(|h| h == "login_uri");
    let username_idx = header.iter().position(|h| h == "login_username");
    let password_idx = header.iter().position(|h| h == "login_password");
    let folder_idx = header.iter().position(|h| h == "folder");

    for line in lines.iter().skip(1) {
        if line.trim().is_empty() {
            continue;
        }

        let fields = parse_csv_line(line);

        let website = uri_idx
            .and_then(|i| fields.get(i))
            .map(|s| s.to_string())
            .or_else(|| name_idx.and_then(|i| fields.get(i)).map(|s| s.to_string()))
            .unwrap_or_default();

        let username = username_idx
            .and_then(|i| fields.get(i))
            .map(|s| s.to_string())
            .unwrap_or_default();

        let password = password_idx
            .and_then(|i| fields.get(i))
            .map(|s| s.to_string())
            .unwrap_or_default();

        let tag = folder_idx
            .and_then(|i| fields.get(i))
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "Imported".to_string());

        if !website.is_empty() || !username.is_empty() {
            entries.push(create_entry_with_timestamp(
                website,
                username,
                password,
                vec![tag],
            ));
        }
    }

    Ok(entries)
}

/// Import entries from 1Password CSV export
/// Format: Title,Url,Username,Password,Notes,OTPAuth,Tags
pub fn import_1password_csv(csv_data: &str) -> Result<Vec<VaultEntry>, Box<dyn StdError>> {
    let mut entries = Vec::new();
    let lines: Vec<&str> = csv_data.lines().collect();

    if lines.is_empty() {
        return Ok(entries);
    }

    let header = parse_csv_line(lines[0]);
    let title_idx = header.iter().position(|h| h.to_lowercase() == "title");
    let url_idx = header.iter().position(|h| h.to_lowercase() == "url");
    let username_idx = header.iter().position(|h| h.to_lowercase() == "username");
    let password_idx = header.iter().position(|h| h.to_lowercase() == "password");
    let tags_idx = header.iter().position(|h| h.to_lowercase() == "tags");

    for line in lines.iter().skip(1) {
        if line.trim().is_empty() {
            continue;
        }

        let fields = parse_csv_line(line);

        let website = url_idx
            .and_then(|i| fields.get(i))
            .map(|s| s.to_string())
            .or_else(|| title_idx.and_then(|i| fields.get(i)).map(|s| s.to_string()))
            .unwrap_or_default();

        let username = username_idx
            .and_then(|i| fields.get(i))
            .map(|s| s.to_string())
            .unwrap_or_default();

        let password = password_idx
            .and_then(|i| fields.get(i))
            .map(|s| s.to_string())
            .unwrap_or_default();

        let tag = tags_idx
            .and_then(|i| fields.get(i))
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "Imported".to_string());

        if !website.is_empty() || !username.is_empty() {
            entries.push(create_entry_with_timestamp(
                website,
                username,
                password,
                vec![tag],
            ));
        }
    }

    Ok(entries)
}

/// Import entries from LastPass CSV export
/// Format: url,username,password,totp,extra,name,grouping,fav
pub fn import_lastpass_csv(csv_data: &str) -> Result<Vec<VaultEntry>, Box<dyn StdError>> {
    let mut entries = Vec::new();
    let lines: Vec<&str> = csv_data.lines().collect();

    if lines.is_empty() {
        return Ok(entries);
    }

    let header = parse_csv_line(lines[0]);
    let url_idx = header.iter().position(|h| h.to_lowercase() == "url");
    let username_idx = header.iter().position(|h| h.to_lowercase() == "username");
    let password_idx = header.iter().position(|h| h.to_lowercase() == "password");
    let name_idx = header.iter().position(|h| h.to_lowercase() == "name");
    let grouping_idx = header.iter().position(|h| h.to_lowercase() == "grouping");

    for line in lines.iter().skip(1) {
        if line.trim().is_empty() {
            continue;
        }

        let fields = parse_csv_line(line);

        let website = url_idx
            .and_then(|i| fields.get(i))
            .map(|s| s.to_string())
            .or_else(|| name_idx.and_then(|i| fields.get(i)).map(|s| s.to_string()))
            .unwrap_or_default();

        let username = username_idx
            .and_then(|i| fields.get(i))
            .map(|s| s.to_string())
            .unwrap_or_default();

        let password = password_idx
            .and_then(|i| fields.get(i))
            .map(|s| s.to_string())
            .unwrap_or_default();

        let tag = grouping_idx
            .and_then(|i| fields.get(i))
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "Imported".to_string());

        if !website.is_empty() || !username.is_empty() {
            entries.push(create_entry_with_timestamp(
                website,
                username,
                password,
                vec![tag],
            ));
        }
    }

    Ok(entries)
}

/// Import entries from generic CSV (auto-detects columns)
/// Looks for common column names: url/website, username/user/email, password/pass
pub fn import_generic_csv(csv_data: &str) -> Result<Vec<VaultEntry>, Box<dyn StdError>> {
    let mut entries = Vec::new();
    let lines: Vec<&str> = csv_data.lines().collect();

    if lines.is_empty() {
        return Ok(entries);
    }

    let header = parse_csv_line(lines[0]);
    let header_lower: Vec<String> = header.iter().map(|h| h.to_lowercase()).collect();

    // Find website column
    let website_idx = header_lower.iter().position(|h| {
        h.contains("url") || h.contains("website") || h.contains("site") || h.contains("name")
    });

    // Find username column
    let username_idx = header_lower.iter().position(|h| {
        h.contains("username") || h.contains("user") || h.contains("email") || h.contains("login")
    });

    // Find password column
    let password_idx = header_lower.iter().position(|h| {
        h.contains("password") || h.contains("pass") || h.contains("secret")
    });

    // Find tag column
    let tag_idx = header_lower.iter().position(|h| {
        h.contains("tag") || h.contains("folder") || h.contains("group") || h.contains("category")
    });

    for line in lines.iter().skip(1) {
        if line.trim().is_empty() {
            continue;
        }

        let fields = parse_csv_line(line);

        let website = website_idx
            .and_then(|i| fields.get(i))
            .map(|s| s.to_string())
            .unwrap_or_default();

        let username = username_idx
            .and_then(|i| fields.get(i))
            .map(|s| s.to_string())
            .unwrap_or_default();

        let password = password_idx
            .and_then(|i| fields.get(i))
            .map(|s| s.to_string())
            .unwrap_or_default();

        let tag = tag_idx
            .and_then(|i| fields.get(i))
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "Imported".to_string());

        if !website.is_empty() || !username.is_empty() {
            entries.push(create_entry_with_timestamp(
                website,
                username,
                password,
                vec![tag],
            ));
        }
    }

    Ok(entries)
}

/// Auto-detect import format from CSV content
pub fn detect_import_format(csv_data: &str) -> ImportFormat {
    let first_line = csv_data.lines().next().unwrap_or("");
    let header_lower = first_line.to_lowercase();

    if header_lower.contains("login_uri") && header_lower.contains("login_username") {
        ImportFormat::Bitwarden
    } else if header_lower.contains("title") && header_lower.contains("otpauth") {
        ImportFormat::OnePassword
    } else if header_lower.contains("grouping") && header_lower.contains("fav") {
        ImportFormat::LastPass
    } else if header_lower.contains("website") && header_lower.contains("tags") {
        ImportFormat::QuickPass
    } else {
        ImportFormat::Generic
    }
}

/// Import entries using auto-detection
pub fn import_csv_auto(csv_data: &str) -> Result<(Vec<VaultEntry>, ImportFormat), Box<dyn StdError>> {
    let format = detect_import_format(csv_data);
    let entries = match format {
        ImportFormat::Bitwarden => import_bitwarden_csv(csv_data)?,
        ImportFormat::OnePassword => import_1password_csv(csv_data)?,
        ImportFormat::LastPass => import_lastpass_csv(csv_data)?,
        ImportFormat::QuickPass | ImportFormat::Generic => import_generic_csv(csv_data)?,
    };
    Ok((entries, format))
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
                    created_at: Some("2026-01-14 12:00:00 UTC".to_string()),
                    modified_at: Some("2026-01-14 12:00:00 UTC".to_string()),
                    totp_secret: None,
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
                    created_at: None,
                    modified_at: None,
                    totp_secret: None,
                },
                VaultEntry {
                    website: "email.com".to_string(),
                    username: "email@test.com".to_string(),
                    password: "Em@ilS3cure!".to_string(),
                    tags: vec!["Personal".to_string()],
                    created_at: None,
                    modified_at: None,
                    totp_secret: None,
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

    // ---- Nonce Validation Tests (Phase 2.5) ----

    #[test]
    fn test_validate_encrypted_data_valid() {
        let valid_nonce = [0u8; 12];
        let valid_ciphertext = [0u8; 32]; // 16 bytes tag + some data
        assert!(validate_encrypted_data(&valid_nonce, &valid_ciphertext).is_ok());
    }

    #[test]
    fn test_validate_encrypted_data_invalid_nonce_length() {
        let short_nonce = [0u8; 8]; // Too short
        let ciphertext = [0u8; 32];
        assert!(validate_encrypted_data(&short_nonce, &ciphertext).is_err());

        let long_nonce = [0u8; 16]; // Too long
        assert!(validate_encrypted_data(&long_nonce, &ciphertext).is_err());
    }

    #[test]
    fn test_validate_encrypted_data_short_ciphertext() {
        let valid_nonce = [0u8; 12];
        let short_ciphertext = [0u8; 8]; // Less than 16 bytes tag
        assert!(validate_encrypted_data(&valid_nonce, &short_ciphertext).is_err());
    }

    #[test]
    fn test_decrypt_with_invalid_nonce_fails_gracefully() {
        let mut vault_key = [0u8; 32];
        rand::rng().fill_bytes(&mut vault_key);

        // Encrypt some data first
        let test_data = b"Test data";
        let (nonce, ciphertext) = encrypt_vault_bytes(test_data, &vault_key).unwrap();

        // Valid decryption should work
        assert!(decrypt_vault_data((&nonce, &ciphertext), &vault_key).is_ok());

        // Invalid nonce length should fail with error, not panic
        let bad_nonce = [0u8; 8];
        let result = decrypt_vault_data((&bad_nonce, &ciphertext), &vault_key);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("nonce"));
    }

    // ---- CSV Parsing Tests (Phase 4.2) ----

    #[test]
    fn test_parse_csv_line_simple() {
        let line = "field1,field2,field3";
        let fields = parse_csv_line(line);
        assert_eq!(fields, vec!["field1", "field2", "field3"]);
    }

    #[test]
    fn test_parse_csv_line_quoted() {
        let line = r#""field,with,commas",field2,"field3""#;
        let fields = parse_csv_line(line);
        assert_eq!(fields, vec!["field,with,commas", "field2", "field3"]);
    }

    #[test]
    fn test_parse_csv_line_escaped_quotes() {
        let line = r#""field with ""quotes""",field2"#;
        let fields = parse_csv_line(line);
        assert_eq!(fields, vec![r#"field with "quotes""#, "field2"]);
    }

    #[test]
    fn test_import_bitwarden_csv() {
        let csv = r#"folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
Work,0,login,Example,,,0,https://example.com,user@example.com,mypassword123,
Personal,1,login,Bank,,,0,https://bank.com,bankuser,bankpass123,"#;

        let entries = import_bitwarden_csv(csv).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].website, "https://example.com");
        assert_eq!(entries[0].username, "user@example.com");
        assert_eq!(entries[0].password, "mypassword123");
        assert_eq!(entries[0].tags, vec!["Work"]);
        assert_eq!(entries[1].website, "https://bank.com");
        assert_eq!(entries[1].tags, vec!["Personal"]);
    }

    #[test]
    fn test_import_lastpass_csv() {
        let csv = r#"url,username,password,totp,extra,name,grouping,fav
https://example.com,user@test.com,testpass123,,,Example Site,Social,0
https://bank.com,bankuser,bankpass,,,Bank,Finance,1"#;

        let entries = import_lastpass_csv(csv).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].website, "https://example.com");
        assert_eq!(entries[0].username, "user@test.com");
        assert_eq!(entries[0].password, "testpass123");
        assert_eq!(entries[0].tags, vec!["Social"]);
    }

    #[test]
    fn test_import_generic_csv() {
        let csv = r#"website,username,password,category
example.com,user1,pass1,Work
bank.com,user2,pass2,Finance"#;

        let entries = import_generic_csv(csv).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].website, "example.com");
        assert_eq!(entries[0].username, "user1");
        assert_eq!(entries[0].password, "pass1");
        assert_eq!(entries[0].tags, vec!["Work"]);
    }

    #[test]
    fn test_detect_import_format_bitwarden() {
        let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n";
        assert_eq!(detect_import_format(csv), ImportFormat::Bitwarden);
    }

    #[test]
    fn test_detect_import_format_lastpass() {
        let csv = "url,username,password,totp,extra,name,grouping,fav\n";
        assert_eq!(detect_import_format(csv), ImportFormat::LastPass);
    }

    #[test]
    fn test_detect_import_format_generic() {
        let csv = "url,user,pass\n";
        assert_eq!(detect_import_format(csv), ImportFormat::Generic);
    }

    #[test]
    fn test_password_age_calculation() {
        let entry = VaultEntry {
            website: "test.com".to_string(),
            username: "user".to_string(),
            password: "pass".to_string(),
            tags: vec![],
            created_at: None,
            modified_at: Some("2026-01-14 12:00:00 UTC".to_string()),
            totp_secret: None,
        };

        let age = password_age_days(&entry);
        assert!(age.is_some());
        // Age should be non-negative (entry was created today or in the past)
        assert!(age.unwrap() >= 0);
    }

    #[test]
    fn test_create_entry_with_timestamp() {
        let entry = create_entry_with_timestamp(
            "example.com".to_string(),
            "user".to_string(),
            "pass".to_string(),
            vec!["Work".to_string()],
        );

        assert_eq!(entry.website, "example.com");
        assert_eq!(entry.username, "user");
        assert_eq!(entry.password, "pass");
        assert!(entry.created_at.is_some());
        assert!(entry.modified_at.is_some());
        assert!(entry.totp_secret.is_none());
    }

    // ---- TOTP Tests (Phase 4.3) ----

    #[test]
    fn test_generate_totp_secret() {
        let secret = generate_totp_secret();
        // Generated secret should be non-empty and valid Base32
        assert!(!secret.is_empty());
        assert!(validate_totp_secret(&secret));
    }

    #[test]
    fn test_validate_totp_secret_valid() {
        // Standard test secret that meets 128-bit minimum
        assert!(validate_totp_secret("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn test_validate_totp_secret_invalid() {
        // Invalid Base32 characters
        assert!(!validate_totp_secret("invalid!@#"));
    }

    #[test]
    fn test_generate_totp_code() {
        // Use a test secret that meets the 128-bit minimum (26+ Base32 chars)
        let secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
        let result = generate_totp_code(secret);
        assert!(result.is_ok(), "Error: {:?}", result);
        let (code, remaining) = result.unwrap();
        // Code should be 6 digits
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        // Remaining should be 1-30 seconds
        assert!(remaining >= 1 && remaining <= 30);
    }

    #[test]
    fn test_generate_totp_code_invalid_secret() {
        let result = generate_totp_code("invalid!secret");
        assert!(result.is_err());
    }

    #[test]
    fn test_create_entry_with_totp() {
        let secret = generate_totp_secret();
        let entry = create_entry_with_totp(
            "example.com".to_string(),
            "user".to_string(),
            "pass".to_string(),
            vec!["Work".to_string()],
            Some(secret.clone()),
        );

        assert_eq!(entry.website, "example.com");
        assert_eq!(entry.totp_secret, Some(secret));
    }
}
