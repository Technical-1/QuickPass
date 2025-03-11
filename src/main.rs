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
use std::process;
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

/// For letting the user pick exactly which symbols to include:
#[derive(Clone)]
struct SymbolToggle {
    sym: char,
    enabled: bool,
}

/// A small struct representing each vault entry
#[derive(Clone, Serialize, Deserialize)]
struct VaultEntry {
    website: String,
    username: String,
    password: String,
}

/// The on-disk format now includes two encryptions of the same `vault_key`:
#[derive(Serialize, Deserialize)]
struct EncryptedVaultFile {
    // Argon2-Hashed credentials
    master_hash: String,
    pattern_hash: Option<String>,

    // The vault key, encrypted with the text-based password:
    encrypted_key_pw: Vec<u8>,
    nonce_pw: Vec<u8>,

    // The same vault key, encrypted with the pattern-based key:
    encrypted_key_pt: Option<Vec<u8>>,
    nonce_pt: Option<Vec<u8>>,

    // Finally, the actual vault data:
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

    // Password generation toggles
    length: usize,
    use_lowercase: bool,
    use_uppercase: bool,
    use_digits: bool,
    // Removed old `use_symbols` bool
    symbol_toggles: Vec<SymbolToggle>, // user picks exactly which symbols

    generated_password: String,

    // Vault entry temp fields
    new_website: String,
    new_username: String,

    // Changing master password
    show_change_pw: bool,
    new_master_pw: String,

    // Changing pattern
    show_change_pattern: bool,
    new_pattern_attempt: Vec<(usize, usize)>,
    new_pattern_unlocked: bool,

    // First-run UI
    first_run_password: String,
    first_run_pattern: Vec<(usize, usize)>,
    first_run_pattern_unlocked: bool,

    // Vault delete after 3 fails
    failed_attempts: u32,
    login_error_msg: String,
}

impl Default for QuickPassApp {
    fn default() -> Self {
        Self {
            is_logged_in: false,
            vault: Vec::new(),
            file_exists: vault_file_path().exists(),
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
            // Pre-populate some common symbols:
            symbol_toggles: vec![
                SymbolToggle { sym: '!', enabled: true },
                SymbolToggle { sym: '@', enabled: true },
                SymbolToggle { sym: '#', enabled: true },
                SymbolToggle { sym: '$', enabled: true },
                SymbolToggle { sym: '%', enabled: true },
                SymbolToggle { sym: '^', enabled: true },
                SymbolToggle { sym: '&', enabled: true },
                SymbolToggle { sym: '*', enabled: true },
                SymbolToggle { sym: '(', enabled: true },
                SymbolToggle { sym: ')', enabled: true },
                SymbolToggle { sym: '-', enabled: true },
                SymbolToggle { sym: '_', enabled: true },
                SymbolToggle { sym: '=', enabled: true },
                SymbolToggle { sym: '+', enabled: true },
                SymbolToggle { sym: '[', enabled: true },
                SymbolToggle { sym: ']', enabled: true },
                SymbolToggle { sym: '{', enabled: true },
                SymbolToggle { sym: '}', enabled: true },
                SymbolToggle { sym: ':', enabled: true },
                SymbolToggle { sym: ';', enabled: true },
                SymbolToggle { sym: ',', enabled: true },
                SymbolToggle { sym: '.', enabled: true },
                SymbolToggle { sym: '<', enabled: true },
                SymbolToggle { sym: '>', enabled: true },
                SymbolToggle { sym: '?', enabled: true },
                SymbolToggle { sym: '/', enabled: true },
            ],
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

            failed_attempts: 0,
            login_error_msg: String::new(),
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

/// Egui app
impl App for QuickPassApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            if !self.login_error_msg.is_empty() {
                ui.colored_label(Color32::RED, &self.login_error_msg);
            }

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
    // --------------- FIRST RUN UI ---------------
    fn show_first_run_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading(RichText::new("First time opened!").size(28.0).color(Color32::RED));
        ui.label("You must set BOTH a master password AND a pattern.");

        ui.separator();
        ui.label("Master Password:");
        ui.add(egui::TextEdit::singleline(&mut self.first_run_password).password(true));

        ui.separator();
        ui.label("Create a Pattern (6×6 grid, need >=8 clicks):");
        self.show_pattern_lock_first_run(ui);

        if self.first_run_pattern_unlocked {
            ui.colored_label(Color32::GREEN, "Pattern set!");
        } else {
            ui.colored_label(Color32::RED, "Pattern not set (need >=8).");
        }

        ui.separator();
        if ui.button("Create Vault").clicked() {
            if self.first_run_password.is_empty() {
                self.login_error_msg = "Please type a master password!".into();
            } else if !self.first_run_pattern_unlocked {
                self.login_error_msg = "Please create a pattern (8+ clicks)!".into();
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
                        self.login_error_msg.clear();

                        // Load vault key
                        if let Ok((_, _, vault_key)) = load_vault_key_only(
                            &self.first_run_password,
                            Some(pattern_hash.as_bytes())
                        ) {
                            self.current_vault_key = Some(vault_key);
                        }
                    }
                    Err(e) => {
                        self.login_error_msg = format!("Failed first-run vault: {e}");
                    }
                }
            }
        }
    }

    // --------------- LOGIN UI ---------------
    fn show_login_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading(RichText::new("Welcome Back to QuickPass").size(30.0).color(Color32::GRAY));
        ui.label("Enter your master password:");
        ui.add(egui::TextEdit::singleline(&mut self.master_password_input).password(true));

        if ui.button("Login").clicked() {
            let pass = self.master_password_input.clone();

            match load_vault_key_only(&pass, None) {
                Ok((mh, ph, key)) => {
                    match load_vault_data(&key) {
                        Ok(vault) => {
                            self.current_vault_key = Some(key);
                            self.master_hash = Some(mh);
                            self.pattern_hash = ph;
                            self.vault = vault;
                            self.is_logged_in = true;
                            self.login_error_msg.clear();
                            self.failed_attempts = 0;
                        }
                        Err(e) => {
                            self.handle_login_failure(format!("Login error (decrypt vault): {e}"));
                        }
                    }
                }
                Err(e) => {
                    self.handle_login_failure(format!("Login error: {e}"));
                }
            }
        }

        ui.separator();
        ui.label(RichText::new("Or unlock with your Pattern (6×6 grid, >=8 clicks)").size(20.0).color(Color32::GRAY));
        self.show_pattern_lock_login(ui);

        if self.is_pattern_unlock {
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
                                self.login_error_msg.clear();
                                self.failed_attempts = 0;
                            }
                            Err(e) => {
                                self.handle_login_failure(format!("Pattern login error (decrypt vault): {e}"));
                                self.pattern_attempt.clear();
                                self.is_pattern_unlock = false;
                            }
                        }
                    }
                    Err(e) => {
                        self.handle_login_failure(format!("Pattern login error: {e}"));
                        self.pattern_attempt.clear();
                        self.is_pattern_unlock = false;
                    }
                }
            }
        } else {
            ui.colored_label(Color32::RED, "Pattern locked");
        }

        if ui.button("Reset Pattern").clicked() {
            self.pattern_attempt.clear();
            self.is_pattern_unlock = false;
        }
    }

    // --------------- MAIN UI ---------------
    fn show_main_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading(RichText::new("QuickPass - Vault").size(30.0).color(Color32::GRAY));

        // Sliders/checkboxes for password generation
        ui.horizontal(|ui| {
            ui.label("Length:");
            ui.add(egui::Slider::new(&mut self.length, 1..=128).text("characters"));
        });
        ui.checkbox(&mut self.use_lowercase, "Lowercase (a-z)");
        ui.checkbox(&mut self.use_uppercase, "Uppercase (A-Z)");
        ui.checkbox(&mut self.use_digits,   "Digits (0-9)");

        // Instead of a single `use_symbols` bool, we show a grid of symbol toggles
        ui.separator();
        ui.label("Select which symbols to include:");
        let original_spacing = ui.spacing().clone();
        // For a cleaner symbol layout, let's do a grid:
        egui::Grid::new("symbol_grid").num_columns(8).show(ui, |ui| {
            for (i, st) in self.symbol_toggles.iter_mut().enumerate() {
                ui.checkbox(&mut st.enabled, format!("{}", st.sym));
                if (i + 1) % 8 == 0 {
                    ui.end_row();
                }
            }
        });
        *ui.spacing_mut() = original_spacing;

        // Generate
        if ui.button("Generate Password").clicked() {
            let user_symbols = self.collect_enabled_symbols();
            self.generated_password = generate_password(
                self.length,
                self.use_lowercase,
                self.use_uppercase,
                self.use_digits,
                &user_symbols
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

    /// Gathers all user-enabled symbols into a Vec<char>.
    fn collect_enabled_symbols(&self) -> Vec<char> {
        self.symbol_toggles
            .iter()
            .filter(|s| s.enabled)
            .map(|s| s.sym)
            .collect()
    }

    // --------------- CHANGE MASTER PASSWORD UI ---------------
    fn show_change_password_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Change Master Password");
        ui.label("New Password:");
        ui.add(egui::TextEdit::singleline(&mut self.new_master_pw).password(true));

        if ui.button("Confirm").clicked() {
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

    // --------------- CHANGE PATTERN UI ---------------
    fn show_change_pattern_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Change Pattern (6×6 grid)");
        ui.label("Create a new pattern (need >=8 clicks).");

        if self.new_pattern_attempt.len() >= 8 {
            self.new_pattern_unlocked = true;
        }

        // Remove spacing so in-between squares can't be clicked
        let original_spacing = ui.spacing().clone();
        ui.spacing_mut().item_spacing = egui::vec2(0.0, 0.0);

        // 6×6 grid
        for row in 0..6 {
            ui.horizontal(|ui| {
                for col in 0..6 {
                    let clicked = self.new_pattern_attempt.contains(&(row, col));
                    let clr = if clicked { Color32::RED } else { Color32::DARK_BLUE };
                    // fix button size so no space in between
                    let btn = egui::Button::new(RichText::new("●").size(30.0).color(clr)).frame(false);
                    if ui.add_sized((35.0, 35.0), btn).clicked() {
                        self.new_pattern_attempt.push((row, col));
                    }
                }
            });
        }

        *ui.spacing_mut() = original_spacing;

        if self.new_pattern_unlocked {
            ui.colored_label(Color32::GREEN, "New pattern set!");
        } else {
            ui.colored_label(Color32::RED, "Not enough clicks yet (need >=8).");
        }

        if ui.button("Confirm Pattern").clicked() {
            if let Some(ref vault_key) = self.current_vault_key {
                let new_pat_str = pattern_to_string(&self.new_pattern_attempt);
                match update_pattern_with_key(&new_pat_str, vault_key, &self.vault) {
                    Ok(np) => {
                        self.pattern_hash = Some(np);
                        eprintln!("Pattern changed successfully!");
                    }
                    Err(e) => eprintln!("Change pattern error: {e}"),
                }
            } else {
                eprintln!("No vault key in memory, can't change pattern!");
            }
            self.show_change_pattern = false;
        }

        if ui.button("Cancel").clicked() {
            self.show_change_pattern = false;
            self.new_pattern_attempt.clear();
            self.new_pattern_unlocked = false;
        }
    }

    // --------------- VAULT UI ---------------
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

    // --------------- FIRST-RUN PATTERN (6×6) ---------------
    fn show_pattern_lock_first_run(&mut self, ui: &mut egui::Ui) {
        if self.first_run_pattern.len() >= 8 {
            self.first_run_pattern_unlocked = true;
        }

        // remove spacing
        let original_spacing = ui.spacing().clone();
        ui.spacing_mut().item_spacing = egui::vec2(0.0, 0.0);

        for row in 0..6 {
            ui.horizontal(|ui| {
                for col in 0..6 {
                    let clicked = self.first_run_pattern.contains(&(row, col));
                    let clr = if clicked { Color32::RED } else { Color32::DARK_BLUE };
                    let btn = egui::Button::new(RichText::new("●").size(30.0).color(clr)).frame(false);
                    if ui.add_sized((35.0, 35.0), btn).clicked() {
                        self.first_run_pattern.push((row, col));
                    }
                }
            });
        }

        // restore spacing
        *ui.spacing_mut() = original_spacing;
    }

    // --------------- LOGIN PATTERN (6×6) ---------------
    fn show_pattern_lock_login(&mut self, ui: &mut egui::Ui) {
        if self.pattern_attempt.len() >= 8 {
            self.is_pattern_unlock = true;
        }

        let original_spacing = ui.spacing().clone();
        ui.spacing_mut().item_spacing = egui::vec2(0.0, 0.0);

        for row in 0..6 {
            ui.horizontal(|ui| {
                for col in 0..6 {
                    let clicked = self.pattern_attempt.contains(&(row, col));
                    let clr = if clicked { Color32::RED } else { Color32::DARK_BLUE };
                    let btn = egui::Button::new(RichText::new("●").size(30.0).color(clr)).frame(false);
                    if ui.add_sized((35.0, 35.0), btn).clicked() {
                        self.pattern_attempt.push((row, col));
                    }
                }
            });
        }

        *ui.spacing_mut() = original_spacing;
    }

    // --------------- FAILED ATTEMPTS ---------------
    fn handle_login_failure(&mut self, err_msg: String) {
        self.failed_attempts += 1;
        let attempts_left = 3 - self.failed_attempts;
        if self.failed_attempts >= 3 {
            // Delete vault + exit
            if vault_file_path().exists() {
                let _ = fs::remove_file(vault_file_path());
            }
            eprintln!("Too many failed attempts! Vault deleted, exiting...");
            process::exit(1);
        } else {
            self.login_error_msg = format!("{err_msg} - Wrong credentials! You have {attempts_left} attempt(s) left before vault deletion.");
        }
    }
}

// ----------------------------------
// HELPER FUNCTIONS
// ----------------------------------

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

/// Load just the vault_key
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
        Ok((file.master_hash.clone(), file.pattern_hash.clone(), vault_key))
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
        Ok((file.master_hash.clone(), file.pattern_hash.clone(), vault_key))
    }
}

/// Once we have the vault_key, we decrypt the vault data
fn load_vault_data(vault_key: &[u8]) -> Result<Vec<VaultEntry>, Box<dyn StdError>> {
    let data = fs::read_to_string(vault_file_path())?;
    let file: EncryptedVaultFile = serde_json::from_str(&data)?;

    let vault = decrypt_vault_data((&file.vault_nonce, &file.vault_ciphertext), vault_key)?;
    Ok(vault)
}

/// Save the vault with an already-known vault_key
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
    file.pattern_hash = pattern_hash.map(str::to_string);

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
    // Argon2-hash the new password
    let argon2 = Argon2::default();
    let salt_str = global_salt();
    let new_hash = argon2
        .hash_password(new_password.as_bytes(), salt_str)
        .map_err(|e| e.to_string())?
        .to_string();

    // Re-encrypt the vault_key with new password
    let (encrypted_key_pw, nonce_pw) = encrypt_with_derived_key(vault_key, new_password.as_bytes())?;

    // Re-encrypt the vault data
    let (vault_nonce, vault_ciphertext) = encrypt_vault_data(vault, vault_key)?;

    // Update the file
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
    // Hash the new pattern
    let argon2 = Argon2::default();
    let salt_str = global_salt();
    let new_ph = argon2
        .hash_password(new_pattern_str.as_bytes(), salt_str)
        .map_err(|e| e.to_string())?
        .to_string();

    // Re-encrypt vault_key with new pattern
    let (encrypted_key_pt, nonce_pt) = encrypt_with_derived_key(vault_key, new_pattern_str.as_bytes())?;

    // Re-encrypt vault data
    let (vault_nonce, vault_ciphertext) = encrypt_vault_data(vault, vault_key)?;

    // Update file
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

// --- Pattern strings ---
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

// --- Key Derivation, Encryption, Decryption ---
fn derive_key_from_input(input: &[u8]) -> [u8; 32] {
    let argon2 = Argon2::default();
    let mut salt_buf = [0u8; 16];
    let _ = global_salt().decode_b64(&mut salt_buf);

    let mut key = [0u8; 32];
    let _ = argon2.hash_password_into(input, &salt_buf, &mut key);
    key
}

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

fn decrypt_with_derived_key(
    ciphertext: &[u8],
    nonce_bytes: &[u8],
    input: &[u8],
) -> Result<Vec<u8>, Box<dyn StdError>> {
    let key_bytes = derive_key_from_input(input);
    let cipher_key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(cipher_key);

    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|e| e.to_string())?;

    let mut kb = key_bytes;
    kb.zeroize();

    Ok(plaintext)
}

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
