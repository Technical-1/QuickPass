mod password;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use eframe::{egui, App, Frame, NativeOptions};
use eframe::CreationContext;
use egui::{Color32, RichText};
use zeroize::Zeroize;

use serde::{Serialize, Deserialize};

use std::error::Error as StdError;
use std::fs;
use std::io::{Error as IoError, ErrorKind};
use std::path::PathBuf;
use std::sync::OnceLock;

use rand::RngCore; 
use password::generate_password;

// ----------------------
// Constants / Globals
// ----------------------

static GLOBAL_SALT: OnceLock<SaltString> = OnceLock::new();

fn global_salt() -> &'static SaltString {
    GLOBAL_SALT.get_or_init(|| {
        SaltString::encode_b64(b"MY_APP_STATIC_SALT").unwrap()
    })
}

/// A small struct representing each vault entry
#[derive(Clone, Serialize, Deserialize)]
struct VaultEntry {
    website: String,
    username: String,
    password: String,
}

/// The on-disk format includes two encryptions of the same `vault_key`:
#[derive(Serialize, Deserialize)]
struct EncryptedVaultFile {
    master_hash: String,
    pattern_hash: Option<String>,

    encrypted_key_pw: Vec<u8>,
    nonce_pw: Vec<u8>,

    encrypted_key_pt: Option<Vec<u8>>,
    nonce_pt: Option<Vec<u8>>,

    vault_ciphertext: Vec<u8>,
    vault_nonce: Vec<u8>,
}

/// Main application state
struct QuickPassApp {
    is_logged_in: bool,
    vault: Vec<VaultEntry>,
    file_exists: bool,

    // The currently unlocked vault key, if any:
    current_vault_key: Option<Vec<u8>>,

    // Text-based login
    master_password_input: String,

    // Pattern-based login
    pattern_attempt: Vec<(usize, usize)>,
    is_pattern_unlock: bool,

    // Argon2 hashed credentials
    master_hash: Option<String>,
    pattern_hash: Option<String>,

    // Password generation
    length: usize,
    use_lowercase: bool,
    use_uppercase: bool,
    use_digits: bool,
    use_symbols: bool,
    generated_password: String,

    new_website: String,
    new_username: String,

    show_change_pw: bool,
    new_master_pw: String,

    show_change_pattern: bool,
    new_pattern_attempt: Vec<(usize, usize)>,
    new_pattern_unlocked: bool,

    // first-run UI
    first_run_password: String,
    first_run_pattern: Vec<(usize, usize)>,
    first_run_pattern_unlocked: bool,
}

impl Default for QuickPassApp {
    fn default() -> Self {
        Self {
            is_logged_in: false,
            vault: Vec::new(),
            file_exists: vault_file_path().exists(),

            // We hold the vault_key if logged in
            current_vault_key: None,

            master_password_input: String::new(),
            pattern_attempt: Vec::new(),
            is_pattern_unlock: false,

            master_hash: None,
            pattern_hash: None,

            length: 12,
            use_lowercase: true,
            use_uppercase: true,
            use_digits: true,
            use_symbols: true,
            generated_password: String::new(),

            new_website: String::new(),
            new_username: String::new(),

            show_change_pw: false,
            new_master_pw: String::new(),

            show_change_pattern: false,
            new_pattern_attempt: Vec::new(),
            new_pattern_unlocked: false,

            first_run_password: String::new(),
            first_run_pattern: Vec::new(),
            first_run_pattern_unlocked: false,
        }
    }
}

fn vault_file_path() -> PathBuf {
    PathBuf::from("encrypted_vault.json")
}

fn main() -> eframe::Result<()> {
    let native_options = NativeOptions::default();
    eframe::run_native(
        "QuickPass",
        native_options,
        Box::new(|_cc: &CreationContext| {
            Ok(Box::new(QuickPassApp::default()))
        }),
    )
}

impl App for QuickPassApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            if !self.file_exists && !self.is_logged_in {
                self.show_first_run_ui(ui);
            } else if !self.is_logged_in {
                self.show_login_ui(ui);
            } else {
                if self.show_change_pw {
                    self.show_change_password_ui(ui);
                } else if self.show_change_pattern {
                    self.show_change_pattern_ui(ui);
                } else {
                    self.show_main_ui(ui);
                }
            }
        });
    }
}

// ----------------------------------
// UI Scenes
// ----------------------------------
impl QuickPassApp {
    fn show_first_run_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading(RichText::new("First time opened!").size(28.0).color(Color32::RED));
        ui.label("You must set BOTH a master password AND a pattern.");

        ui.separator();
        ui.label("Master Password:");
        ui.add(egui::TextEdit::singleline(&mut self.first_run_password).password(true));

        ui.separator();
        ui.label("Create a Pattern (click 4+ circles):");
        self.show_pattern_lock_first_run(ui);

        if self.first_run_pattern_unlocked {
            ui.colored_label(Color32::GREEN, "Pattern set!");
        } else {
            ui.colored_label(Color32::RED, "Pattern not set (need >=4).");
        }

        ui.separator();
        if ui.button("Create Vault").clicked() {
            if self.first_run_password.is_empty() {
                eprintln!("Please type a master password!");
            } else if !self.first_run_pattern_unlocked {
                eprintln!("Please create a pattern (4+ clicks)!");
            } else {
                let pattern_hash = hash_pattern(&self.first_run_pattern);
                match create_new_vault_file(&self.first_run_password, &pattern_hash) {
                    Ok((mh, ph)) => {
                        self.master_hash = Some(mh);
                        self.pattern_hash = Some(ph);
                        self.vault.clear();
                        self.file_exists = true;
                        self.is_logged_in = true;
                        self.master_password_input = self.first_run_password.clone();

                        // We now need to load the vault_key so we can do changes later
                        // The easiest way is to re-load from disk:
                        if let Ok((_, _, vault_key)) = load_vault_key_only(
                            &self.first_run_password, 
                            Some(pattern_hash.as_bytes())
                        ) {
                            self.current_vault_key = Some(vault_key);
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed first-run vault: {e}");
                    }
                }
            }
        }
    }

    fn show_login_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading(RichText::new("Welcome Back to QuickPass").size(30.0).color(Color32::GRAY));
        ui.label("Enter your master password:");
        ui.add(egui::TextEdit::singleline(&mut self.master_password_input).password(true));

        if ui.button("Login").clicked() {
            let pass = self.master_password_input.clone();
            match load_vault_key_only(&pass, None) {
                Ok((mh, ph, key)) => {
                    // FIRST use `key` to load vault data
                    match load_vault_data(&key) {
                        Ok(vault) => {
                            // THEN move key into `current_vault_key`
                            self.current_vault_key = Some(key);
                            self.master_hash = Some(mh);
                            self.pattern_hash = ph;
                            self.vault = vault;
                            self.is_logged_in = true;
                        }
                        Err(e) => {
                            eprintln!("Login error (decrypt vault): {e}");
                            self.master_password_input.clear();
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Login error: {e}");
                    self.master_password_input.clear();
                }
            }
            

        ui.separator();
        ui.label(RichText::new("Or unlock with your Pattern").size(20.0).color(Color32::GRAY));
        self.show_pattern_lock_login(ui);

        if self.is_pattern_unlock {
            ui.colored_label(Color32::GREEN, "Pattern unlocked!");
            if ui.button("Enter with Pattern").clicked() {
                let pattern_str = pattern_to_string(&self.pattern_attempt);
                match load_vault_key_only("", Some(pattern_str.as_bytes())) {
                    Ok((mh, ph, key)) => {
                        match load_vault_data(&key) {
                            Ok(vault) => {
                                self.current_vault_key = Some(key);
                                self.master_hash = Some(mh);
                                self.pattern_hash = ph;
                                self.vault = vault;
                                self.is_logged_in = true;
                            }
                            Err(e) => {
                                eprintln!("Pattern login error (decrypt vault): {e}");
                                self.pattern_attempt.clear();
                                self.is_pattern_unlock = false;
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Pattern login error: {e}");
                        self.pattern_attempt.clear();
                        self.is_pattern_unlock = false;
                    }
                }
            }
        }
    }


    fn show_main_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading(RichText::new("QuickPass - Vault").size(30.0).color(Color32::GRAY));

        ui.horizontal(|ui| {
            ui.label("Length:");
            ui.add(egui::Slider::new(&mut self.length, 1..=128).text("characters"));
        });
        ui.checkbox(&mut self.use_lowercase, "Lowercase (a-z)");
        ui.checkbox(&mut self.use_uppercase, "Uppercase (A-Z)");
        ui.checkbox(&mut self.use_digits, "Digits (0-9)");
        ui.checkbox(&mut self.use_symbols, "Symbols (!@#...)");

        if ui.button("Generate Password").clicked() {
            self.generated_password = generate_password(
                self.length,
                self.use_lowercase,
                self.use_uppercase,
                self.use_digits,
                self.use_symbols,
            );
        }
        ui.separator();
        ui.label("Generated Password:");
        ui.monospace(&self.generated_password);

        ui.separator();
        self.show_vault_ui(ui);

        ui.separator();
        if ui.button("Change Master Password").clicked() {
            self.show_change_pw = true;
        }

        ui.separator();
        if ui.button("Change Pattern").clicked() {
            self.show_change_pattern = true;
            self.new_pattern_attempt.clear();
            self.new_pattern_unlocked = false;
        }

        ui.separator();
        if ui.button("Logout").clicked() {
            // Re-encrypt + save the vault if we have a vault_key
            if let Some(ref vault_key) = self.current_vault_key {
                if let Some(mh) = &self.master_hash {
                    if let Err(e) = save_vault_file(mh, self.pattern_hash.as_deref(), vault_key, &self.vault) {
                        eprintln!("Failed to save on logout: {e}");
                    }
                }
            }

            self.master_password_input.clear();
            self.is_logged_in = false;
            self.generated_password.clear();
            self.pattern_attempt.clear();
            self.is_pattern_unlock = false;
            self.show_change_pw = false;
            self.new_master_pw.clear();
            self.show_change_pattern = false;
            self.new_pattern_attempt.clear();
            self.new_pattern_unlocked = false;
            self.current_vault_key = None;
        }
    }

    fn show_change_password_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Change Master Password");
        ui.label("New Password:");
        ui.add(egui::TextEdit::singleline(&mut self.new_master_pw).password(true));

        if ui.button("Confirm").clicked() {
            // If we have a vault_key in memory, we can skip verifying the old password
            // and just re-encrypt the vault_key with the new password, update the file
            if let Some(ref vault_key) = self.current_vault_key {
                let new_pw = std::mem::take(&mut self.new_master_pw);

                match update_master_password_with_key(
                    &new_pw,
                    vault_key,
                    &self.vault,
                    self.pattern_hash.as_deref()
                ) {
                    Ok(new_hash) => {
                        eprintln!("Master password changed!");
                        self.master_hash = Some(new_hash);
                        self.master_password_input = new_pw;
                    }
                    Err(e) => {
                        eprintln!("Change PW error: {e}");
                    }
                }
            } else {
                eprintln!("No vault key in memory, can't change password!");
            }

            self.show_change_pw = false;
        }

        if ui.button("Cancel").clicked() {
            self.show_change_pw = false;
            self.new_master_pw.clear();
        }
    }

    fn show_change_pattern_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Change Pattern");
        ui.label("Create a new pattern (4+ clicks):");

        if self.new_pattern_attempt.len() >= 4 {
            self.new_pattern_unlocked = true;
        }

        for row in 0..3 {
            ui.horizontal(|ui| {
                for col in 0..3 {
                    let clicked = self.new_pattern_attempt.contains(&(row, col));
                    let clr = if clicked { Color32::RED } else { Color32::DARK_BLUE };
                    let btn = egui::Button::new(RichText::new("●").size(40.0).color(clr)).frame(false);
                    if ui.add(btn).clicked() {
                        self.new_pattern_attempt.push((row, col));
                    }
                }
            });
        }

        if self.new_pattern_unlocked {
            ui.colored_label(Color32::GREEN, "New pattern set!");
        } else {
            ui.colored_label(Color32::RED, "Not enough clicks yet.");
        }

        if ui.button("Confirm Pattern").clicked() {
            if let Some(ref vault_key) = self.current_vault_key {
                let new_pat_str = pattern_to_string(&self.new_pattern_attempt);
                match update_pattern_with_key(
                    &new_pat_str,
                    vault_key,
                    &self.vault
                ) {
                    Ok(np) => {
                        self.pattern_hash = Some(np);
                        eprintln!("Pattern changed successfully!");
                    }
                    Err(e) => eprintln!("Change pattern error: {e}"),
                }
            } else {
                eprintln!("No vault_key in memory, can't change pattern!");
            }

            self.show_change_pattern = false;
        }

        if ui.button("Cancel").clicked() {
            self.show_change_pattern = false;
            self.new_pattern_attempt.clear();
            self.new_pattern_unlocked = false;
        }
    }

    fn show_vault_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading(RichText::new("Vault Entries").size(20.0).color(Color32::DARK_GRAY));

        ui.horizontal(|ui| {
            ui.label("Website:");
            ui.text_edit_singleline(&mut self.new_website);

            ui.label("Username:");
            ui.text_edit_singleline(&mut self.new_username);

            if ui.button("Add to Vault").clicked() {
                let new_entry = VaultEntry {
                    website: self.new_website.clone(),
                    username: self.new_username.clone(),
                    password: self.generated_password.clone(),
                };
                self.vault.push(new_entry);

                self.new_website.clear();
                self.new_username.clear();
                self.generated_password.clear();
            }
        });

        ui.separator();
        for (i, entry) in self.vault.iter().enumerate() {
            ui.group(|ui| {
                ui.label(format!("Entry #{}", i + 1));
                ui.label(format!("Website: {}", entry.website));
                ui.label(format!("Username: {}", entry.username));
                ui.label(format!("Password: {}", entry.password));
            });
            ui.separator();
        }
    }

    fn show_pattern_lock_first_run(&mut self, ui: &mut egui::Ui) {
        if self.first_run_pattern.len() >= 4 {
            self.first_run_pattern_unlocked = true;
        }
        for row in 0..3 {
            ui.horizontal(|ui| {
                for col in 0..3 {
                    let clicked = self.first_run_pattern.contains(&(row, col));
                    let clr = if clicked { Color32::RED } else { Color32::DARK_BLUE };
                    let btn = egui::Button::new(RichText::new("●").size(40.0).color(clr)).frame(false);
                    if ui.add(btn).clicked() {
                        self.first_run_pattern.push((row, col));
                    }
                }
            });
        }
    }

    fn show_pattern_lock_login(&mut self, ui: &mut egui::Ui) {
        if self.pattern_attempt.len() >= 4 {
            self.is_pattern_unlock = true;
        }
        for row in 0..3 {
            ui.horizontal(|ui| {
                for col in 0..3 {
                    let clicked = self.pattern_attempt.contains(&(row, col));
                    let clr = if clicked { Color32::RED } else { Color32::DARK_BLUE };
                    let btn = egui::Button::new(RichText::new("●").size(40.0).color(clr)).frame(false);
                    if ui.add(btn).clicked() {
                        self.pattern_attempt.push((row, col));
                    }
                }
            });
        }
    }
}

// ----------------------------------
// HELPER FUNCTIONS
// ----------------------------------

/// On first run, we generate the vault_key, encrypt it with text + pattern, etc.
fn create_new_vault_file(
    master_password: &str,
    pattern_hash_str: &str,
) -> Result<(String, String), Box<dyn StdError>> {
    let argon2 = Argon2::default();
    let salt_str = global_salt();

    let master_hash = argon2
        .hash_password(master_password.as_bytes(), salt_str)
        .map_err(|e| e.to_string())?
        .to_string();

    let hashed_pattern = argon2
        .hash_password(pattern_hash_str.as_bytes(), salt_str)
        .map_err(|e| e.to_string())?
        .to_string();

    let mut vault_key = [0u8; 32];
    let mut rng = rand::rng();
    rng.fill_bytes(&mut vault_key);

    let (encrypted_key_pw, nonce_pw) = encrypt_with_derived_key(&vault_key, master_password.as_bytes())?;
    let (encrypted_key_pt, nonce_pt) = encrypt_with_derived_key(&vault_key, pattern_hash_str.as_bytes())?;

    let (vault_nonce, vault_ciphertext) = encrypt_vault_data(&[], &vault_key)?;
    vault_key.zeroize();

    let file_data = EncryptedVaultFile {
        master_hash,
        pattern_hash: Some(hashed_pattern),
        encrypted_key_pw,
        nonce_pw,
        encrypted_key_pt: Some(encrypted_key_pt),
        nonce_pt: Some(nonce_pt),
        vault_ciphertext,
        vault_nonce,
    };

    let serialized = serde_json::to_string_pretty(&file_data)?;
    fs::write(vault_file_path(), serialized)?;

    Ok((file_data.master_hash.clone(), file_data.pattern_hash.clone().unwrap()))
}

/// Load just the vault_key (not the entire vault).
/// If `pattern` is Some(...), we do pattern-based approach, else text-based with `master_password`.
fn load_vault_key_only(
    master_password: &str,
    pattern: Option<&[u8]>,
) -> Result<(String, Option<String>, Vec<u8>), Box<dyn StdError>> {
    let data = fs::read_to_string(vault_file_path())?;
    let file: EncryptedVaultFile = serde_json::from_str(&data)?;

    if let Some(patt_bytes) = pattern {
        // pattern-based
        let phash = file.pattern_hash.as_ref().ok_or("No pattern hash stored!")?;
        let parsed_hash = PasswordHash::new(phash).map_err(|e| e.to_string())?;
        Argon2::default()
            .verify_password(patt_bytes, &parsed_hash)
            .map_err(|_| IoError::new(ErrorKind::InvalidData, "Pattern mismatch"))?;

        let enc_key_pt = file.encrypted_key_pt.as_ref().ok_or("No encrypted_key_pt!")?;
        let nonce_pt = file.nonce_pt.as_ref().ok_or("No nonce_pt!")?;

        let vault_key = decrypt_with_derived_key(enc_key_pt, nonce_pt, patt_bytes)?;
        Ok((file.master_hash, file.pattern_hash, vault_key))
    } else {
        // text-based
        if !master_password.is_empty() {
            let parsed_hash = PasswordHash::new(&file.master_hash).map_err(|e| e.to_string())?;
            Argon2::default()
                .verify_password(master_password.as_bytes(), &parsed_hash)
                .map_err(|_| IoError::new(ErrorKind::InvalidData, "Master password mismatch"))?;
        }
        let vault_key = decrypt_with_derived_key(
            &file.encrypted_key_pw,
            &file.nonce_pw,
            master_password.as_bytes(),
        )?;
        Ok((file.master_hash, file.pattern_hash, vault_key))
    }
}

/// Once we have the vault_key, we decrypt the vault data
fn load_vault_data(vault_key: &[u8]) -> Result<Vec<VaultEntry>, Box<dyn StdError>> {
    let data = fs::read_to_string(vault_file_path())?;
    let file: EncryptedVaultFile = serde_json::from_str(&data)?;

    let vault = decrypt_vault_data((&file.vault_nonce, &file.vault_ciphertext), vault_key)?;
    Ok(vault)
}

/// Save the vault again with the known vault_key
fn save_vault_file(
    master_hash: &str,
    pattern_hash: Option<&str>,
    vault_key: &[u8],
    vault: &[VaultEntry]
) -> Result<(), Box<dyn StdError>> {
    let data = fs::read_to_string(vault_file_path())?;
    let mut file: EncryptedVaultFile = serde_json::from_str(&data)?;

    // Re-encrypt the vault data with the known vault_key
    let (vault_nonce, vault_ciphertext) = encrypt_vault_data(vault, vault_key)?;
    file.vault_nonce = vault_nonce;
    file.vault_ciphertext = vault_ciphertext;

    file.master_hash = master_hash.to_string();
    file.pattern_hash = pattern_hash.map(|s| s.to_string());

    let serialized = serde_json::to_string_pretty(&file)?;
    fs::write(vault_file_path(), serialized)?;
    Ok(())
}

/// We have the existing vault_key in memory, so skip verifying old password
fn update_master_password_with_key(
    new_password: &str,
    vault_key: &[u8],
    vault: &[VaultEntry],
    pattern_hash: Option<&str>,
) -> Result<String, Box<dyn StdError>> {
    // 1) Argon2-hash the new password
    let argon2 = Argon2::default();
    let salt_str = global_salt();
    let new_hash = argon2
        .hash_password(new_password.as_bytes(), salt_str)
        .map_err(|e| e.to_string())?
        .to_string();

    // 2) Re-encrypt the vault_key with new password
    let (encrypted_key_pw, nonce_pw) = encrypt_with_derived_key(vault_key, new_password.as_bytes())?;

    // 3) Re-encrypt the vault data
    let (vault_nonce, vault_ciphertext) = encrypt_vault_data(vault, vault_key)?;

    // 4) Update the file
    let data = fs::read_to_string(vault_file_path())?;
    let mut file: EncryptedVaultFile = serde_json::from_str(&data)?;
    file.master_hash = new_hash.clone();
    file.pattern_hash = pattern_hash.map(|s| s.to_string());

    file.encrypted_key_pw = encrypted_key_pw;
    file.nonce_pw = nonce_pw;
    file.vault_nonce = vault_nonce;
    file.vault_ciphertext = vault_ciphertext;

    let serialized = serde_json::to_string_pretty(&file)?;
    fs::write(vault_file_path(), serialized)?;
    Ok(new_hash)
}

/// We have the existing vault_key in memory, so skip verifying old text password
fn update_pattern_with_key(
    new_pattern_str: &str,
    vault_key: &[u8],
    vault: &[VaultEntry],
) -> Result<String, Box<dyn StdError>> {
    // 1) Hash the new pattern
    let argon2 = Argon2::default();
    let salt_str = global_salt();
    let new_ph = argon2
        .hash_password(new_pattern_str.as_bytes(), salt_str)
        .map_err(|e| e.to_string())?
        .to_string();

    // 2) Re-encrypt vault_key with new pattern
    let (encrypted_key_pt, nonce_pt) = encrypt_with_derived_key(vault_key, new_pattern_str.as_bytes())?;

    // 3) Re-encrypt vault data
    let (vault_nonce, vault_ciphertext) = encrypt_vault_data(vault, vault_key)?;

    // 4) Update file
    let data = fs::read_to_string(vault_file_path())?;
    let mut file: EncryptedVaultFile = serde_json::from_str(&data)?;

    file.pattern_hash = Some(new_ph.clone());
    file.encrypted_key_pt = Some(encrypted_key_pt);
    file.nonce_pt = Some(nonce_pt);
    file.vault_nonce = vault_nonce;
    file.vault_ciphertext = vault_ciphertext;

    let serialized = serde_json::to_string_pretty(&file)?;
    fs::write(vault_file_path(), serialized)?;
    Ok(new_ph)
}

// Pattern strings
fn hash_pattern(pattern: &[(usize, usize)]) -> String {
    pattern_to_string(pattern)
}

fn pattern_to_string(pattern: &[(usize, usize)]) -> String {
    pattern
        .iter()
        .map(|(r, c)| format!("{},{}", r, c))
        .collect::<Vec<_>>()
        .join("-")
}

// Derive key from user input
fn derive_key_from_input(input: &[u8]) -> [u8; 32] {
    let argon2 = Argon2::default();
    let mut salt_buf = [0u8; 16];
    let _ = global_salt().decode_b64(&mut salt_buf);

    let mut key = [0u8; 32];
    let _ = argon2.hash_password_into(input, &salt_buf, &mut key);
    key
}

/// AES-GCM encrypt `plaintext` using a key derived from `input`
fn encrypt_with_derived_key(
    plaintext: &[u8],
    input: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn StdError>> {
    let key_bytes = derive_key_from_input(input);
    let cipher_key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(cipher_key);

    let mut rng = rand::rng();
    let mut nonce_arr = [0u8; 12];
    rng.fill_bytes(&mut nonce_arr);

    let nonce = Nonce::from_slice(&nonce_arr);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| e.to_string())?;

    let mut kb = key_bytes;
    kb.zeroize();

    Ok((ciphertext, nonce_arr.to_vec()))
}

/// AES-GCM decrypt `ciphertext` using a key derived from `input`
fn decrypt_with_derived_key(
    ciphertext: &[u8],
    nonce_bytes: &[u8],
    input: &[u8],
) -> Result<Vec<u8>, Box<dyn StdError>> {
    let key_bytes = derive_key_from_input(input);
    let cipher_key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(cipher_key);

    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| e.to_string())?;

    let mut kb = key_bytes;
    kb.zeroize();

    Ok(plaintext)
}

// Vault encryption
fn encrypt_vault_data(
    vault: &[VaultEntry],
    vault_key: &[u8]
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn StdError>> {
    let cipher_key = Key::<Aes256Gcm>::from_slice(vault_key);
    let cipher = Aes256Gcm::new(cipher_key);

    let json = serde_json::to_vec(vault)?;
    let mut rng = rand::rng();
    let mut nonce_arr = [0u8; 12];
    rng.fill_bytes(&mut nonce_arr);

    let nonce = Nonce::from_slice(&nonce_arr);
    let ciphertext = cipher
        .encrypt(nonce, json.as_slice())
        .map_err(|e| e.to_string())?;

    Ok((nonce_arr.to_vec(), ciphertext))
}

fn decrypt_vault_data(
    (nonce_bytes, ciphertext): (&[u8], &[u8]),
    vault_key: &[u8]
) -> Result<Vec<VaultEntry>, Box<dyn StdError>> {
    let cipher_key = Key::<Aes256Gcm>::from_slice(vault_key);
    let cipher = Aes256Gcm::new(cipher_key);

    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|e| e.to_string())?;

    let vault: Vec<VaultEntry> = serde_json::from_slice(&plaintext)?;
    Ok(vault)
}
