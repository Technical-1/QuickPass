mod password;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use base64::{
    engine::general_purpose::URL_SAFE_NO_PAD,
    Engine as _ // trait alias so we can call .encode()/.decode() on the chosen engine
};
use directories::ProjectDirs;
use eframe::{egui, App, Frame, NativeOptions};
use eframe::CreationContext;
use egui::{Color32, RichText};
use zeroize::Zeroize;

use serde::{Deserialize, Serialize};
use once_cell::sync::Lazy;
use std::error::Error as StdError;
use std::fs;
use std::io::{Error as IoError, ErrorKind};
use std::path::{Path, PathBuf};

use password::generate_password;
use rand::RngCore;

// ----------------------------------------
// Argon2 config: Argon2id with memory/time cost
// ----------------------------------------
fn secure_argon2() -> Argon2<'static> {
    let algorithm = Algorithm::Argon2id;
    let version = Version::V0x13;

    // Example: memory=65536 KiB (~64MB), iterations=3, parallelism=1
    let params = Params::new(65536, 2, 2, Some(32))
        .expect("Invalid Argon2 params");
    Argon2::new(algorithm, version, params)
}

// ----------------------
// Constants / Globals
// ----------------------
static GLOBAL_SALT: Lazy<SaltString> = Lazy::new(|| {
    SaltString::encode_b64(b"MY_APP_STATIC_SALT").unwrap()
});

fn global_salt() -> &'static SaltString {
    &GLOBAL_SALT
}

/// Let user pick exactly which symbols to include:
#[derive(Clone)]
struct SymbolToggle {
    sym: char,
    enabled: bool,
}

/// Each vault entry
#[derive(Clone, Serialize, Deserialize)]
struct VaultEntry {
    website: String,
    username: String,
    password: String,
}

/// On-disk format
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

/// The main app state
struct QuickPassApp {
    // If true, we show Vault Manager screen
    show_vault_manager: bool,

    // The name (identifier) of the currently open vault
    active_vault_name: Option<String>,

    is_logged_in: bool,
    vault: Vec<VaultEntry>,

    // The currently unlocked vault key, if any
    current_vault_key: Option<Vec<u8>>,

    // Master login input
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
    symbol_toggles: Vec<SymbolToggle>,
    generated_password: String,

    // For adding new vault entries
    new_website: String,
    new_username: String,

    // Changing master password
    show_change_pw: bool,
    new_master_pw_old_input: String,
    new_master_pw: String,

    // Changing pattern
    show_change_pattern: bool,
    old_password_for_pattern: String,
    new_pattern_attempt: Vec<(usize, usize)>,
    new_pattern_unlocked: bool,

    // "Initial Creation"
    first_run_password: String,
    first_run_pattern: Vec<(usize, usize)>,
    first_run_pattern_unlocked: bool,

    // login fails
    failed_attempts: u32,
    login_error_msg: String,

    // Editing an existing VaultEntry
    editing_index: Option<usize>,
    editing_website: String,
    editing_username: String,
    editing_password: String,

    // Password visibility per entry
    password_visible: Vec<bool>,

    // For the Vault Manager
    new_vault_name: String,
    manager_vaults: Vec<String>,
}

impl Default for QuickPassApp {
    fn default() -> Self {
        let manager_vaults = scan_vaults_in_dir();
        Self {
            show_vault_manager: true,
            active_vault_name: None,

            is_logged_in: false,
            vault: Vec::new(),
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
            new_master_pw_old_input: String::new(),
            new_master_pw: String::new(),

            show_change_pattern: false,
            old_password_for_pattern: String::new(),
            new_pattern_attempt: Vec::new(),
            new_pattern_unlocked: false,

            first_run_password: String::new(),
            first_run_pattern: Vec::new(),
            first_run_pattern_unlocked: false,

            failed_attempts: 0,
            login_error_msg: String::new(),

            editing_index: None,
            editing_website: String::new(),
            editing_username: String::new(),
            editing_password: String::new(),

            password_visible: Vec::new(),

            new_vault_name: String::new(),
            manager_vaults,
        }
    }
}

// Where multi-vault files live
fn data_dir() -> PathBuf {
    if let Some(proj_dirs) = ProjectDirs::from("com", "KANFER", "QuickPass") {
        let dir = proj_dirs.data_dir();
        let _ = fs::create_dir_all(dir);
        dir.to_path_buf()
    } else {
        PathBuf::from(".")
    }
}

fn vault_file_path(vault_name: &str) -> PathBuf {
    data_dir().join(format!("encrypted_vault_{vault_name}.json"))
}

fn scan_vaults_in_dir() -> Vec<String> {
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

// ------------------------------
// eframe App Implementation
// ------------------------------
impl App for QuickPassApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            if !self.login_error_msg.is_empty() {
                ui.colored_label(Color32::RED, &self.login_error_msg);
            }

            if self.show_vault_manager {
                self.show_vault_manager_ui(ui);
                return;
            }

            if self.active_vault_name.is_none() {
                self.show_vault_manager = true;
                return;
            }
            let vault_name = self.active_vault_name.as_ref().unwrap();
            let path = vault_file_path(vault_name);
            let file_exists = path.exists();

            if !file_exists && !self.is_logged_in {
                self.show_initial_creation_ui(ui);
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

// ------------------------------
// UI Scenes
// ------------------------------
impl QuickPassApp {
    /// Vault Manager
    fn show_vault_manager_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading(RichText::new("Vault Manager").size(28.0).color(Color32::YELLOW));
        ui.label("Manage multiple vaults below.");

        ui.separator();

        if !self.manager_vaults.is_empty() {
            ui.label("Existing vaults:");
            let vault_list = self.manager_vaults.clone();
            for vault_name in vault_list {
                ui.horizontal(|ui| {
                    ui.label(format!("Vault: {}", vault_name));
                    if ui.button("Open").clicked() {
                        // Switch to this vault
                        self.active_vault_name = Some(vault_name.clone());
                        self.show_vault_manager = false;
                        self.login_error_msg.clear();

                        // CLEAR old state
                        self.vault.clear();
                        self.password_visible.clear();
                        self.is_logged_in = false;
                        self.master_password_input.clear();
                        self.pattern_attempt.clear();
                        self.is_pattern_unlock = false;
                        self.failed_attempts = 0;

                        // Also clear the first-run fields in case user tries to "create" again
                        self.first_run_password.clear();
                        self.first_run_pattern.clear();
                        self.first_run_pattern_unlocked = false;
                    }
                    if ui.button("Delete").clicked() {
                        let path = vault_file_path(&vault_name);
                        let _ = fs::remove_file(path);
                        // Re-scan
                        self.manager_vaults = scan_vaults_in_dir();
                    }
                });
            }
        } else {
            ui.colored_label(Color32::RED, "No vault files found yet.");
        }

        ui.separator();
        ui.heading("Create a brand-new vault");
        ui.label("Vault Name:");
        ui.text_edit_singleline(&mut self.new_vault_name);

        if ui.button("Create").clicked() {
            if self.new_vault_name.trim().is_empty() {
                self.login_error_msg = "Please enter a vault name!".into();
            } else {
                let path = vault_file_path(&self.new_vault_name);
                if path.exists() {
                    self.login_error_msg = "Vault with that name already exists!".into();
                } else {
                    self.active_vault_name = Some(self.new_vault_name.clone());
                    self.show_vault_manager = false;
                    self.login_error_msg.clear();

                    // Clear old state
                    self.vault.clear();
                    self.password_visible.clear();
                    self.is_logged_in = false;
                    self.master_password_input.clear();
                    self.pattern_attempt.clear();
                    self.is_pattern_unlock = false;
                    self.failed_attempts = 0;

                    self.first_run_password.clear();
                    self.first_run_pattern.clear();
                    self.first_run_pattern_unlocked = false;
                }
            }
        }
    }

    fn show_initial_creation_ui(&mut self, ui: &mut egui::Ui) {
        let vault_name = self.active_vault_name.clone().unwrap_or_default();
        ui.heading(
            RichText::new(format!("Initial Creation for: {}", vault_name))
                .size(28.0)
                .color(Color32::RED),
        );
        ui.label("You must set BOTH a master password AND a pattern for this new vault.");

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
                let pattern_hash = pattern_to_string(&self.first_run_pattern);
                let vault_name = self.active_vault_name.clone().unwrap_or_default();
                match create_new_vault_file(&vault_name, &self.first_run_password, &pattern_hash) {
                    Ok((mh, ph)) => {
                        self.master_hash = Some(mh);
                        self.pattern_hash = Some(ph);
                        self.vault.clear();
                        self.password_visible.clear();

                        self.is_logged_in = true;
                        self.master_password_input = self.first_run_password.clone();
                        self.login_error_msg.clear();

                        if let Ok((_, _, vault_key)) =
                            load_vault_key_only(&vault_name, &self.first_run_password, Some(pattern_hash.as_bytes()))
                        {
                            self.current_vault_key = Some(vault_key);
                        }
                        self.manager_vaults = scan_vaults_in_dir();
                    }
                    Err(e) => {
                        self.login_error_msg = format!("Failed first-run vault: {e}");
                    }
                }
            }
        }
    }

    fn show_login_ui(&mut self, ui: &mut egui::Ui) {
        let vault_name = self.active_vault_name.clone().unwrap_or_default();
        ui.heading(
            RichText::new(format!("Welcome to: {}", vault_name))
                .size(30.0)
                .color(Color32::GRAY),
        );
        ui.label("Enter your master password:");
        ui.add(egui::TextEdit::singleline(&mut self.master_password_input).password(true));

        if ui.button("Login").clicked() {
            let pass = self.master_password_input.clone();
            match load_vault_key_only(&vault_name, &pass, None) {
                Ok((mh, ph, key)) => match load_vault_data(&vault_name, &key) {
                    Ok(vault) => {
                        self.current_vault_key = Some(key);
                        self.master_hash = Some(mh);
                        self.pattern_hash = ph;
                        self.vault = vault;
                        self.password_visible = vec![false; self.vault.len()];
                        self.is_logged_in = true;
                        self.login_error_msg.clear();
                        self.failed_attempts = 0;
                    }
                    Err(e) => {
                        self.handle_login_failure(format!("Login error (decrypt vault): {e}"));
                    }
                },
                Err(e) => {
                    self.handle_login_failure(format!("Login error: {e}"));
                }
            }
        }

        ui.separator();
        ui.label(
            RichText::new("Or unlock with your Pattern (6×6 grid, >=8 clicks)")
                .size(20.0)
                .color(Color32::GRAY),
        );
        self.show_pattern_lock_login(ui);

        if self.is_pattern_unlock {
            if ui.button("Enter with Pattern").clicked() {
                let pattern_str = pattern_to_string(&self.pattern_attempt);
                let name = self.active_vault_name.clone().unwrap_or_default();
                match load_vault_key_only(&name, "", Some(pattern_str.as_bytes())) {
                    Ok((mh, ph, key)) => match load_vault_data(&name, &key) {
                        Ok(vault) => {
                            self.current_vault_key = Some(key);
                            self.master_hash = Some(mh);
                            self.pattern_hash = ph;
                            self.vault = vault;
                            self.password_visible = vec![false; self.vault.len()];
                            self.is_logged_in = true;
                            self.login_error_msg.clear();
                            self.failed_attempts = 0;
                        }
                        Err(e) => {
                            self.handle_login_failure(format!(
                                "Pattern login error (decrypt vault): {e}"
                            ));
                            self.pattern_attempt.clear();
                            self.is_pattern_unlock = false;
                        }
                    },
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

        ui.separator();
        if ui.button("Return to Vault Manager").clicked() {
            self.show_vault_manager = true;
            // Clear state
            self.active_vault_name = None;
            self.is_logged_in = false;
            self.vault.clear();
            self.password_visible.clear();
            self.master_password_input.clear();
            self.pattern_attempt.clear();
            self.is_pattern_unlock = false;
            self.login_error_msg.clear();
            self.failed_attempts = 0;
        }
    }

    fn show_main_ui(&mut self, ui: &mut egui::Ui) {
        let vault_name = self.active_vault_name.clone().unwrap_or_default();
        ui.heading(
            RichText::new(format!("QuickPass - Vault: {}", vault_name))
                .size(30.0)
                .color(Color32::GRAY),
        );

        ui.horizontal(|ui| {
            ui.label("Length:");
            ui.add(egui::Slider::new(&mut self.length, 1..=128).text("characters"));
        });
        ui.checkbox(&mut self.use_lowercase, "Lowercase (a-z)");
        ui.checkbox(&mut self.use_uppercase, "Uppercase (A-Z)");
        ui.checkbox(&mut self.use_digits, "Digits (0-9)");

        ui.separator();
        ui.label("Select which symbols to include:");
        let original_spacing = ui.spacing().clone();
        egui::Grid::new("symbol_grid")
            .num_columns(8)
            .show(ui, |ui| {
                for (i, st) in self.symbol_toggles.iter_mut().enumerate() {
                    ui.checkbox(&mut st.enabled, format!("{}", st.sym));
                    if (i + 1) % 8 == 0 {
                        ui.end_row();
                    }
                }
            });
        *ui.spacing_mut() = original_spacing;

        if ui.button("Generate Password").clicked() {
            let user_symbols = self.collect_enabled_symbols();
            self.generated_password = generate_password(
                self.length,
                self.use_lowercase,
                self.use_uppercase,
                self.use_digits,
                &user_symbols,
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
            self.new_master_pw_old_input.clear();
            self.new_master_pw.clear();
        }

        ui.separator();
        if ui.button("Change Pattern").clicked() {
            self.show_change_pattern = true;
            self.old_password_for_pattern.clear();
            self.new_pattern_attempt.clear();
            self.new_pattern_unlocked = false;
        }

        ui.separator();
        if ui.button("Logout").clicked() {
            if let Some(ref vault_key) = self.current_vault_key {
                if let Some(mh) = &self.master_hash {
                    let name = self.active_vault_name.clone().unwrap_or_default();
                    if let Err(e) = save_vault_file(&name, mh, self.pattern_hash.as_deref(), vault_key, &self.vault) {
                        eprintln!("Failed to save on logout: {e}");
                    }
                }
            }

            // Return to manager
            self.show_vault_manager = true;
            self.active_vault_name = None;
            self.is_logged_in = false;
            self.vault.clear();
            self.password_visible.clear();
            self.master_password_input.clear();
            self.pattern_attempt.clear();
            self.is_pattern_unlock = false;
            self.show_change_pw = false;
            self.new_master_pw_old_input.clear();
            self.new_master_pw.clear();
            self.show_change_pattern = false;
            self.old_password_for_pattern.clear();
            self.new_pattern_attempt.clear();
            self.new_pattern_unlocked = false;
            self.current_vault_key = None;
        }
    }

    fn collect_enabled_symbols(&self) -> Vec<char> {
        self.symbol_toggles
            .iter()
            .filter(|s| s.enabled)
            .map(|s| s.sym)
            .collect()
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
                self.password_visible.push(false);

                self.new_website.clear();
                self.new_username.clear();
                self.generated_password.clear();
            }
        });

        ui.separator();
        while self.password_visible.len() < self.vault.len() {
            self.password_visible.push(false);
        }

        let mut delete_index: Option<usize> = None;
        let user_symbols = self.collect_enabled_symbols();

        for i in 0..self.vault.len() {
            ui.group(|ui| {
                ui.label(format!("Entry #{}", i + 1));
                let entry = &mut self.vault[i];

                if self.editing_index == Some(i) {
                    // Editing UI
                    ui.label("Edit Website:");
                    ui.text_edit_singleline(&mut self.editing_website);
                    ui.label("Edit Username:");
                    ui.text_edit_singleline(&mut self.editing_username);
                    ui.label("Edit Password:");
                    ui.text_edit_singleline(&mut self.editing_password);

                    ui.horizontal(|ui| {
                        if ui.button("Save").clicked() {
                            entry.website = self.editing_website.clone();
                            entry.username = self.editing_username.clone();
                            entry.password = self.editing_password.clone();
                            self.editing_index = None;
                        }
                        if ui.button("Cancel").clicked() {
                            self.editing_index = None;
                        }
                    });
                } else {
                    // Normal UI
                    ui.horizontal(|ui| {
                        ui.label(format!("Website: {}", entry.website));
                        if ui.button("Copy").clicked() {
                            ui.ctx().copy_text(entry.website.clone());
                        }
                    });
                    ui.horizontal(|ui| {
                        ui.label(format!("Username: {}", entry.username));
                        if ui.button("Copy").clicked() {
                            ui.ctx().copy_text(entry.username.clone());
                        }
                    });
                    ui.horizontal(|ui| {
                        let visible = self.password_visible[i];
                        let display_str = if visible { &entry.password } else { "***" };
                        ui.label(format!("Password: {}", display_str));
                        if ui.button("Copy").clicked() {
                            ui.ctx().copy_text(entry.password.clone());
                        }
                        let eye_label = if visible { "🙈" } else { "👁" };
                        if ui.button(eye_label)
                            .on_hover_text("Toggle visibility")
                            .clicked()
                        {
                            self.password_visible[i] = !self.password_visible[i];
                        }
                    });

                    // Buttons: Edit, Regenerate, Delete
                    ui.horizontal(|ui| {
                        if ui.button("Edit").clicked() {
                            self.editing_index = Some(i);
                            self.editing_website = entry.website.clone();
                            self.editing_username = entry.username.clone();
                            self.editing_password = entry.password.clone();
                        }

                        if ui.button("↻").on_hover_text("Regenerate Password").clicked() {
                            let old_len = entry.password.len();
                            let new_pwd = generate_password(
                                old_len,
                                self.use_lowercase,
                                self.use_uppercase,
                                self.use_digits,
                                &user_symbols,
                            );
                            entry.password = new_pwd;
                        }

                        // Secure Delete button
                        if ui.button("Delete")
                            .on_hover_text("Remove this entry from the vault")
                            .clicked()
                        {
                            delete_index = Some(i);
                        }
                    });
                }
            });
            ui.separator();

            if delete_index.is_some() {
                break;
            }
        }

        // If an entry was marked for deletion, remove it now
        if let Some(idx) = delete_index {
            let ent = &mut self.vault[idx];
            // zeroize the sensitive fields first
            ent.website.zeroize();
            ent.username.zeroize();
            ent.password.zeroize();

            self.vault.remove(idx);
            self.password_visible.remove(idx);

            // Re-save the vault after removal
            if let Some(ref vault_key) = self.current_vault_key {
                if let Some(mh) = &self.master_hash {
                    let vault_name = self.active_vault_name.clone().unwrap_or_default();
                    let _ = save_vault_file(
                        &vault_name,
                        mh,
                        self.pattern_hash.as_deref(),
                        vault_key,
                        &self.vault,
                    );
                }
            }
        }
    }

    fn show_change_password_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Change Master Password (requires old password)");
        ui.label("Old Password:");
        ui.add(egui::TextEdit::singleline(&mut self.new_master_pw_old_input).password(true));

        ui.label("New Password:");
        ui.add(egui::TextEdit::singleline(&mut self.new_master_pw).password(true));

        if ui.button("Confirm").clicked() {
            let vault_name = self.active_vault_name.clone().unwrap_or_default();
            if let Some(ref vault_key) = self.current_vault_key {
                let old_pass = self.new_master_pw_old_input.clone();
                match load_vault_key_only(&vault_name, &old_pass, None) {
                    Ok((_, _, _)) => {
                        let new_pw = std::mem::take(&mut self.new_master_pw);
                        match update_master_password_with_key(
                            &vault_name,
                            &old_pass,
                            &new_pw,
                            vault_key,
                            &self.vault,
                            self.pattern_hash.as_deref(),
                        ) {
                            Ok(new_hash) => {
                                eprintln!("Master password changed!");
                                self.master_hash = Some(new_hash);
                                self.master_password_input = new_pw;
                                self.login_error_msg.clear();
                            }
                            Err(e) => {
                                eprintln!("Change PW error: {e}");
                                self.login_error_msg = format!("Failed to change PW: {e}");
                            }
                        }
                    }
                    Err(_) => {
                        self.login_error_msg = "Old password incorrect!".into();
                    }
                }
            } else {
                eprintln!("No vault key in memory, can't change password!");
            }
            self.show_change_pw = false;
        }

        if ui.button("Cancel").clicked() {
            self.show_change_pw = false;
            self.new_master_pw_old_input.clear();
            self.new_master_pw.clear();
        }
    }

    fn show_change_pattern_ui(&mut self, ui: &mut egui::Ui) {
        let vault_name = self.active_vault_name.clone().unwrap_or_default();
        ui.heading("Change Pattern (requires old password)");
        ui.label("Enter your old master password:");
        ui.add(egui::TextEdit::singleline(&mut self.old_password_for_pattern).password(true));

        ui.separator();
        ui.label("Create a new pattern (need >=8 clicks).");
        if self.new_pattern_attempt.len() >= 8 {
            self.new_pattern_unlocked = true;
        }

        let original_spacing = ui.spacing().clone();
        ui.spacing_mut().item_spacing = egui::vec2(0.0, 0.0);
        ui.spacing_mut().button_padding = egui::vec2(0.0, 0.0);

        for row in 0..6 {
            ui.horizontal(|ui| {
                for col in 0..6 {
                    let clicked = self.new_pattern_attempt.contains(&(row, col));
                    let clr = if clicked { Color32::RED } else { Color32::DARK_BLUE };
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
            let old_pass = self.old_password_for_pattern.clone();
            match load_vault_key_only(&vault_name, &old_pass, None) {
                Ok((_, _, _)) => {
                    if let Some(ref vault_key) = self.current_vault_key {
                        let new_pat_str = pattern_to_string(&self.new_pattern_attempt);
                        match update_pattern_with_key(&vault_name, &old_pass, &new_pat_str, vault_key, &self.vault) {
                            Ok(np) => {
                                self.pattern_hash = Some(np);
                                eprintln!("Pattern changed successfully!");
                                self.login_error_msg.clear();
                            }
                            Err(e) => {
                                eprintln!("Change pattern error: {e}");
                                self.login_error_msg = format!("Failed to change pattern: {e}");
                            }
                        }
                    } else {
                        eprintln!("No vault_key in memory, can't change pattern!");
                    }
                }
                Err(_) => {
                    self.login_error_msg = "Old password incorrect for pattern change!".into();
                }
            }
            self.show_change_pattern = false;
        }

        if ui.button("Cancel").clicked() {
            self.show_change_pattern = false;
            self.old_password_for_pattern.clear();
            self.new_pattern_attempt.clear();
            self.new_pattern_unlocked = false;
        }
    }

    fn show_pattern_lock_first_run(&mut self, ui: &mut egui::Ui) {
        if self.first_run_pattern.len() >= 8 {
            self.first_run_pattern_unlocked = true;
        }

        let original_spacing = ui.spacing().clone();
        ui.spacing_mut().item_spacing = egui::vec2(0.0, 0.0);
        ui.spacing_mut().button_padding = egui::vec2(0.0, 0.0);

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

        *ui.spacing_mut() = original_spacing;
    }

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

    fn handle_login_failure(&mut self, err_msg: String) {
        self.failed_attempts += 1;
        let attempts_left = 3 - self.failed_attempts;
        if self.failed_attempts >= 3 {
            let vault_name = self.active_vault_name.clone().unwrap_or_default();
            let path = vault_file_path(&vault_name);
            if path.exists() {
                let _ = fs::remove_file(&path);
            }
            eprintln!("Too many failed attempts! Vault deleted, exiting to manager...");
            self.show_vault_manager = true;
            self.active_vault_name = None;
            self.is_logged_in = false;
            self.vault.clear();
            self.password_visible.clear();
            self.master_password_input.clear();
            self.pattern_attempt.clear();
            self.is_pattern_unlock = false;
            self.failed_attempts = 0;
            self.login_error_msg = "Vault was deleted after too many failed attempts!".into();
        } else {
            self.login_error_msg = format!("{err_msg} - Wrong credentials! {attempts_left} attempts left.");
        }
    }
}

// ------------------------------
// I/O with base64 for obfuscation
// ------------------------------
fn write_encrypted_vault_file(path: impl AsRef<Path>, file_data: &EncryptedVaultFile)
    -> Result<(), Box<dyn StdError>>
{
    // Convert to JSON
    let json = serde_json::to_string_pretty(file_data)
        .map_err(|e| IoError::new(ErrorKind::InvalidData, e.to_string()))?;

    // Base64-encode
    let encoded = URL_SAFE_NO_PAD.encode(json);
    fs::write(path, encoded)?;
    Ok(())
}

fn read_encrypted_vault_file(path: impl AsRef<Path>)
    -> Result<EncryptedVaultFile, Box<dyn StdError>>
{
    let encoded = fs::read_to_string(path)?;
    let decoded_bytes = URL_SAFE_NO_PAD.decode(encoded.trim())
        .map_err(|e| IoError::new(ErrorKind::InvalidData, e.to_string()))?;

    let file: EncryptedVaultFile = serde_json::from_slice(&decoded_bytes)
        .map_err(|e| IoError::new(ErrorKind::InvalidData, e.to_string()))?;
    Ok(file)
}

// ------------------------------
// CREATE / LOAD / SAVE
// with Argon2 error -> IoError
// ------------------------------
fn create_new_vault_file(
    vault_name: &str,
    master_password: &str,
    pattern_hash_str: &str,
) -> Result<(String, String), Box<dyn StdError>>
{
    let path = vault_file_path(vault_name);
    let argon2 = secure_argon2();
    let salt_str = global_salt();

    let master_hash = argon2
        .hash_password(master_password.as_bytes(), salt_str)
        .map_err(|e| IoError::new(ErrorKind::InvalidData, e.to_string()))?
        .to_string();

    let hashed_pattern = argon2
        .hash_password(pattern_hash_str.as_bytes(), salt_str)
        .map_err(|e| IoError::new(ErrorKind::InvalidData, e.to_string()))?
        .to_string();

    let mut vault_key = [0u8; 32];
    rand::rng().fill_bytes(&mut vault_key);

    let (encrypted_key_pw, nonce_pw) =
        encrypt_with_derived_key(&vault_key, master_password.as_bytes())?;
    let (encrypted_key_pt, nonce_pt) =
        encrypt_with_derived_key(&vault_key, pattern_hash_str.as_bytes())?;

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

    write_encrypted_vault_file(path, &file_data)?;

    Ok((
        file_data.master_hash.clone(),
        file_data.pattern_hash.clone().unwrap(),
    ))
}

fn load_vault_key_only(
    vault_name: &str,
    master_password: &str,
    pattern: Option<&[u8]>,
) -> Result<(String, Option<String>, Vec<u8>), Box<dyn StdError>>
{
    let file = read_encrypted_vault_file(vault_file_path(vault_name))?;
    let argon2 = secure_argon2();

    if let Some(patt_bytes) = pattern {
        let phash = file
            .pattern_hash
            .as_ref()
            .ok_or_else(|| IoError::new(ErrorKind::NotFound, "No pattern hash stored!"))?;
        let parsed_hash = PasswordHash::new(phash)
            .map_err(|e| IoError::new(ErrorKind::InvalidData, e.to_string()))?;
        argon2
            .verify_password(patt_bytes, &parsed_hash)
            .map_err(|_| IoError::new(ErrorKind::InvalidData, "Pattern mismatch"))?;

        let enc_key_pt = file
            .encrypted_key_pt
            .as_ref()
            .ok_or_else(|| IoError::new(ErrorKind::NotFound, "No encrypted_key_pt!"))?;
        let nonce_pt = file
            .nonce_pt
            .as_ref()
            .ok_or_else(|| IoError::new(ErrorKind::NotFound, "No nonce_pt!"))?;

        let vault_key = decrypt_with_derived_key(enc_key_pt, nonce_pt, patt_bytes)?;
        Ok((file.master_hash, file.pattern_hash, vault_key))
    } else {
        if !master_password.is_empty() {
            let parsed_hash = PasswordHash::new(&file.master_hash)
                .map_err(|e| IoError::new(ErrorKind::InvalidData, e.to_string()))?;
            argon2
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

fn load_vault_data(
    vault_name: &str,
    vault_key: &[u8]
) -> Result<Vec<VaultEntry>, Box<dyn StdError>>
{
    let file = read_encrypted_vault_file(vault_file_path(vault_name))?;
    let vault = decrypt_vault_data((&file.vault_nonce, &file.vault_ciphertext), vault_key)?;
    Ok(vault)
}

fn save_vault_file(
    vault_name: &str,
    master_hash: &str,
    pattern_hash: Option<&str>,
    vault_key: &[u8],
    vault: &[VaultEntry],
) -> Result<(), Box<dyn StdError>>
{
    let mut file = read_encrypted_vault_file(vault_file_path(vault_name))?;
    let (vault_nonce, vault_ciphertext) = encrypt_vault_data(vault, vault_key)?;

    file.vault_nonce = vault_nonce;
    file.vault_ciphertext = vault_ciphertext;
    file.master_hash = master_hash.to_string();
    file.pattern_hash = pattern_hash.map(|s| s.to_string());

    write_encrypted_vault_file(vault_file_path(vault_name), &file)?;
    Ok(())
}

fn update_master_password_with_key(
    vault_name: &str,
    _old_password: &str,
    new_password: &str,
    vault_key: &[u8],
    vault: &[VaultEntry],
    pattern_hash: Option<&str>,
) -> Result<String, Box<dyn StdError>>
{
    let mut file = read_encrypted_vault_file(vault_file_path(vault_name))?;
    let argon2 = secure_argon2();
    let salt_str = global_salt();
    let new_hash = argon2
        .hash_password(new_password.as_bytes(), salt_str)
        .map_err(|e| IoError::new(ErrorKind::InvalidData, e.to_string()))?
        .to_string();

    let (encrypted_key_pw, nonce_pw) =
        encrypt_with_derived_key(vault_key, new_password.as_bytes())?;
    let (vault_nonce, vault_ciphertext) = encrypt_vault_data(vault, vault_key)?;

    file.master_hash = new_hash.clone();
    file.pattern_hash = pattern_hash.map(|s| s.to_string());
    file.encrypted_key_pw = encrypted_key_pw;
    file.nonce_pw = nonce_pw;
    file.vault_nonce = vault_nonce;
    file.vault_ciphertext = vault_ciphertext;

    write_encrypted_vault_file(vault_file_path(vault_name), &file)?;
    Ok(new_hash)
}

fn update_pattern_with_key(
    vault_name: &str,
    _old_password: &str,
    new_pattern_str: &str,
    vault_key: &[u8],
    vault: &[VaultEntry],
) -> Result<String, Box<dyn StdError>>
{
    let mut file = read_encrypted_vault_file(vault_file_path(vault_name))?;
    let argon2 = secure_argon2();
    let salt_str = global_salt();
    let new_ph = argon2
        .hash_password(new_pattern_str.as_bytes(), salt_str)
        .map_err(|e| IoError::new(ErrorKind::InvalidData, e.to_string()))?
        .to_string();

    let (encrypted_key_pt, nonce_pt) =
        encrypt_with_derived_key(vault_key, new_pattern_str.as_bytes())?;
    let (vault_nonce, vault_ciphertext) = encrypt_vault_data(vault, vault_key)?;

    file.pattern_hash = Some(new_ph.clone());
    file.encrypted_key_pt = Some(encrypted_key_pt);
    file.nonce_pt = Some(nonce_pt);
    file.vault_nonce = vault_nonce;
    file.vault_ciphertext = vault_ciphertext;

    write_encrypted_vault_file(vault_file_path(vault_name), &file)?;
    Ok(new_ph)
}

// pattern helper
fn pattern_to_string(pattern: &[(usize, usize)]) -> String {
    pattern
        .iter()
        .map(|(r, c)| format!("{},{}", r, c))
        .collect::<Vec<_>>()
        .join("-")
}

// key derivation
fn derive_key_from_input(input: &[u8]) -> [u8; 32] {
    let argon2 = secure_argon2();
    let mut salt_buf = [0u8; 16];
    let _ = global_salt().decode_b64(&mut salt_buf);

    let mut key = [0u8; 32];
    let _ = argon2
        .hash_password_into(input, &salt_buf, &mut key)
        .map_err(|_e| {
            IoError::new(ErrorKind::InvalidData, "hash_password_into error")
        })
        .ok();
    key
}

// encryption / decryption
fn encrypt_with_derived_key(
    plaintext: &[u8],
    input: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn StdError>>
{
    let key_bytes = derive_key_from_input(input);
    let cipher_key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(cipher_key);

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

fn decrypt_with_derived_key(
    ciphertext: &[u8],
    nonce_bytes: &[u8],
    input: &[u8],
) -> Result<Vec<u8>, Box<dyn StdError>>
{
    let key_bytes = derive_key_from_input(input);
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

fn encrypt_vault_data(
    vault: &[VaultEntry],
    vault_key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn StdError>>
{
    let cipher_key = Key::<Aes256Gcm>::from_slice(vault_key);
    let cipher = Aes256Gcm::new(cipher_key);

    let json = serde_json::to_vec(vault)
        .map_err(|e| IoError::new(ErrorKind::InvalidData, e.to_string()))?;

    let mut rng = rand::rng();
    let mut nonce_arr = [0u8; 12];
    rng.fill_bytes(&mut nonce_arr);

    let nonce = Nonce::from_slice(&nonce_arr);

    // FIX: pass `json.as_slice()` rather than `&json`
    let ciphertext = cipher
        .encrypt(nonce, json.as_slice())
        .map_err(|e| IoError::new(ErrorKind::InvalidData, e.to_string()))?;

    Ok((nonce_arr.to_vec(), ciphertext))
}

fn decrypt_vault_data(
    (nonce_bytes, ciphertext): (&[u8], &[u8]),
    vault_key: &[u8],
) -> Result<Vec<VaultEntry>, Box<dyn StdError>>
{
    let cipher_key = Key::<Aes256Gcm>::from_slice(vault_key);
    let cipher = Aes256Gcm::new(cipher_key);

    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| IoError::new(ErrorKind::InvalidData, e.to_string()))?;

    let vault: Vec<VaultEntry> = serde_json::from_slice(&plaintext)
        .map_err(|e| IoError::new(ErrorKind::InvalidData, e.to_string()))?;
    Ok(vault)
}

// Secure memory clearing on Drop
impl Drop for QuickPassApp {
    fn drop(&mut self) {
        // zeroize sensitive fields
        self.master_password_input.zeroize();
        self.old_password_for_pattern.zeroize();
        self.new_master_pw_old_input.zeroize();
        self.new_master_pw.zeroize();

        self.new_website.zeroize();
        self.new_username.zeroize();
        self.generated_password.zeroize();

        for entry in &mut self.vault {
            entry.website.zeroize();
            entry.username.zeroize();
            entry.password.zeroize();
        }
        self.vault.clear();

        self.first_run_password.zeroize();
        self.first_run_pattern.clear();

        self.editing_website.zeroize();
        self.editing_username.zeroize();
        self.editing_password.zeroize();

        if let Some(ref mut k) = self.current_vault_key {
            k.zeroize();
        }
    }
}
