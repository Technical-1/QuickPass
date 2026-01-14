use eframe::{App, Frame, egui};
use egui::{Color32, RichText};
use std::time::Instant;
use zeroize::Zeroize;

use crate::manager::{scan_vaults_in_dir, vault_file_path};
use crate::password::{estimate_entropy, generate_password, validate_master_password};
use crate::security::SecurityLevel;
use crate::vault::{
    VaultEntry, create_new_vault_file, export_encrypted_backup, export_to_csv,
    import_encrypted_backup, load_vault_data_decrypted, load_vault_key_only,
    pattern_to_string, save_vault_file, update_custom_tags, update_last_accessed_in_vault,
    update_master_password_with_key, update_pattern_with_key,
};

/// Clipboard clear timeout in seconds
const CLIPBOARD_CLEAR_SECONDS: u64 = 30;

/// Auto-lock timeout in seconds (5 minutes)
const AUTO_LOCK_SECONDS: u64 = 300;

#[derive(Clone)]
pub struct SymbolToggle {
    pub sym: char,
    pub enabled: bool,
}

/// The main eframe app struct
pub struct QuickPassApp {
    // If true, show the Vault Manager screen
    pub show_vault_manager: bool,
    // The name (identifier) of the currently open vault
    pub active_vault_name: Option<String>,
    // Are we logged into that vault?
    pub is_logged_in: bool,

    // The in-memory vault data
    pub vault: Vec<VaultEntry>,
    pub current_vault_key: Option<Vec<u8>>,

    // Master password & pattern for login
    pub master_password_input: String,
    pub pattern_attempt: Vec<(usize, usize)>,
    pub is_pattern_unlock: bool,

    // Argon2 hashed credentials
    pub master_hash: Option<String>,
    pub pattern_hash: Option<String>,

    // Security level (affects Argon2 parameters)
    pub security_level: SecurityLevel,

    // Password generation toggles
    pub length: usize,
    pub use_lowercase: bool,
    pub use_uppercase: bool,
    pub use_digits: bool,
    pub symbol_toggles: Vec<SymbolToggle>,
    pub generated_password: String,

    // For adding new vault entries
    pub new_website: String,
    pub new_username: String,
    pub new_tags_str: String, // typed tags for new entry
    pub tag_filter: String,   // filter string
    pub search_query: String, // search by website/username

    // Custom tags management
    pub custom_tags: Vec<String>,
    pub new_custom_tag: String,
    pub show_tag_manager: bool,

    // Changing master password
    pub show_change_pw: bool,
    pub new_master_pw_old_input: String,
    pub new_master_pw: String,

    // Changing pattern
    pub show_change_pattern: bool,
    pub old_password_for_pattern: String,
    pub new_pattern_attempt: Vec<(usize, usize)>,
    pub new_pattern_unlocked: bool,

    // "Initial Creation"
    pub first_run_password: String,
    pub first_run_pattern: Vec<(usize, usize)>,
    pub first_run_pattern_unlocked: bool,

    // login fails
    pub failed_attempts: u32,
    pub login_error_msg: String,

    // Editing an existing VaultEntry
    pub editing_index: Option<usize>,
    pub editing_website: String,
    pub editing_username: String,
    pub editing_password: String,

    // Password visibility per entry
    pub password_visible: Vec<bool>,

    // For the Vault Manager
    pub new_vault_name: String,
    pub manager_vaults: Vec<String>,

    // Clipboard auto-clear
    pub clipboard_copy_time: Option<Instant>,
    pub clipboard_copy_type: Option<String>,

    // Confirmation dialogs
    pub pending_delete_entry: Option<usize>,
    pub pending_delete_vault: Option<String>,

    // Auto-lock timeout tracking
    pub last_activity_time: Instant,

    // Export/Import state
    pub show_export_dialog: bool,
    pub export_result: Option<String>,
    pub show_import_dialog: bool,
    pub import_data: String,
    pub import_error: Option<String>,
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

            // Default to Medium
            security_level: SecurityLevel::Medium,

            length: 12,
            use_lowercase: true,
            use_uppercase: true,
            use_digits: true,
            symbol_toggles: build_default_symbol_toggles(),
            generated_password: String::new(),

            new_website: String::new(),
            new_username: String::new(),
            new_tags_str: String::new(),
            tag_filter: String::new(),
            search_query: String::new(),

            custom_tags: Vec::new(),
            new_custom_tag: String::new(),
            show_tag_manager: false,

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

            clipboard_copy_time: None,
            clipboard_copy_type: None,

            pending_delete_entry: None,
            pending_delete_vault: None,

            last_activity_time: Instant::now(),

            show_export_dialog: false,
            export_result: None,
            show_import_dialog: false,
            import_data: String::new(),
            import_error: None,
        }
    }
}

fn build_default_symbol_toggles() -> Vec<SymbolToggle> {
    let symbols = "!@#$%^&*()-_=+[]{}:;,.<>?/".chars();
    let mut toggles = Vec::new();
    for c in symbols {
        toggles.push(SymbolToggle {
            sym: c,
            enabled: true,
        });
    }
    toggles
}

impl App for QuickPassApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut Frame) {
        // Check clipboard auto-clear
        if let Some(copy_time) = self.clipboard_copy_time {
            if copy_time.elapsed().as_secs() >= CLIPBOARD_CLEAR_SECONDS {
                ctx.copy_text(String::new());
                self.clipboard_copy_time = None;
                self.clipboard_copy_type = None;
            }
        }

        // Check auto-lock timeout (only when logged in)
        if self.is_logged_in && self.last_activity_time.elapsed().as_secs() >= AUTO_LOCK_SECONDS {
            self.perform_logout();
            self.login_error_msg = "Vault locked due to inactivity".into();
        }

        // Update activity timer on any input
        if ctx.input(|i| i.pointer.any_click() || !i.keys_down.is_empty() || i.raw_scroll_delta.length() > 0.0) {
            self.last_activity_time = Instant::now();
        }

        // Handle keyboard shortcuts (only when logged in and in main UI)
        if self.is_logged_in && !self.show_vault_manager && !self.show_change_pw && !self.show_change_pattern {
            ctx.input(|i| {
                // Ctrl+L: Lock vault
                if i.modifiers.ctrl && i.key_pressed(egui::Key::L) {
                    self.perform_logout();
                }
                // Ctrl+G: Generate password
                if i.modifiers.ctrl && i.key_pressed(egui::Key::G) {
                    let user_symbols = self.collect_enabled_symbols();
                    self.generated_password = generate_password(
                        self.length,
                        self.use_lowercase,
                        self.use_uppercase,
                        self.use_digits,
                        &user_symbols,
                    );
                }
            });
        }

        // Escape: Cancel current action
        ctx.input(|i| {
            if i.key_pressed(egui::Key::Escape) {
                // Cancel editing
                if self.editing_index.is_some() {
                    self.editing_index = None;
                    self.editing_website.zeroize();
                    self.editing_username.zeroize();
                    self.editing_password.zeroize();
                }
                // Cancel pending deletes
                self.pending_delete_entry = None;
                self.pending_delete_vault = None;
                // Cancel change password/pattern
                if self.show_change_pw {
                    self.show_change_pw = false;
                    self.new_master_pw_old_input.zeroize();
                    self.new_master_pw.zeroize();
                }
                if self.show_change_pattern {
                    self.show_change_pattern = false;
                    self.old_password_for_pattern.zeroize();
                    self.new_pattern_attempt.clear();
                    self.new_pattern_unlocked = false;
                }
            }
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            // Show clipboard countdown if active
            if let Some(copy_time) = self.clipboard_copy_time {
                let remaining = CLIPBOARD_CLEAR_SECONDS.saturating_sub(copy_time.elapsed().as_secs());
                if let Some(ref copy_type) = self.clipboard_copy_type {
                    ui.colored_label(
                        Color32::YELLOW,
                        format!("{} copied - clipboard clears in {}s", copy_type, remaining),
                    );
                }
            }

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
                // Before calling show_login_ui, read the EncryptedVaultFile to retrieve security_level
                if file_exists {
                    if let Ok(ef) =
                        crate::vault::read_encrypted_vault_file(vault_file_path(&vault_name))
                    {
                        // We override our current self.security_level with the stored one
                        self.security_level = ef.security_level;
                    }
                }
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

// ----------------------------------------------------------
// Internal UI Implementation
// ----------------------------------------------------------
impl QuickPassApp {
    /// Clears all sensitive state - call when switching vaults or logging out
    fn clear_sensitive_state(&mut self) {
        self.editing_index = None;
        self.editing_website.zeroize();
        self.editing_username.zeroize();
        self.editing_password.zeroize();

        self.generated_password.zeroize();
        self.new_website.zeroize();
        self.new_username.zeroize();
        self.master_password_input.zeroize();
        self.old_password_for_pattern.zeroize();
        self.new_master_pw_old_input.zeroize();
        self.new_master_pw.zeroize();
        self.pattern_attempt.clear();
        self.is_pattern_unlock = false;
        self.new_pattern_attempt.clear();
        self.new_pattern_unlocked = false;
        self.first_run_password.zeroize();
        self.first_run_pattern.clear();
        self.first_run_pattern_unlocked = false;
        self.search_query.clear();
        self.new_tags_str.clear();
        self.tag_filter.clear();
        self.custom_tags.clear();
        self.new_custom_tag.clear();
        self.show_tag_manager = false;
        self.show_export_dialog = false;
        self.export_result = None;
        self.show_import_dialog = false;
        self.import_data.clear();
        self.import_error = None;
    }

    /// Copy text to clipboard with auto-clear timer
    fn copy_to_clipboard(&mut self, ctx: &egui::Context, text: &str, content_type: &str) {
        ctx.copy_text(text.to_string());
        self.clipboard_copy_time = Some(Instant::now());
        self.clipboard_copy_type = Some(content_type.to_string());
    }

    /// Perform logout - save vault and clear sensitive state
    fn perform_logout(&mut self) {
        // Save before logout
        if let Some(ref vault_key) = self.current_vault_key {
            if let Some(mh) = &self.master_hash {
                if let Err(e) = save_vault_file(
                    &self.active_vault_name.clone().unwrap_or_default(),
                    mh,
                    self.pattern_hash.as_deref(),
                    vault_key,
                    &self.vault,
                ) {
                    eprintln!("Failed to save on logout: {e}");
                }
            }
        }

        self.clear_sensitive_state();
        self.show_vault_manager = true;
        self.active_vault_name = None;
        self.is_logged_in = false;
        self.vault.clear();
        self.password_visible.clear();
        self.show_change_pw = false;
        self.show_change_pattern = false;
        self.current_vault_key = None;
        self.failed_attempts = 0;
        self.last_activity_time = Instant::now();
    }

    // (A) Vault Manager UI
    fn show_vault_manager_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading(
            RichText::new("Vault Manager")
                .size(28.0)
                .color(Color32::WHITE),
        );
        ui.label("Manage multiple vaults below.");

        ui.separator();

        // Handle pending vault deletion confirmation
        if let Some(ref vault_to_delete) = self.pending_delete_vault.clone() {
            ui.group(|ui| {
                ui.colored_label(Color32::RED, format!("Delete vault '{}'?", vault_to_delete));
                ui.label("This action cannot be undone!");
                ui.horizontal(|ui| {
                    if ui.button("Yes, Delete").clicked() {
                        let path = vault_file_path(&vault_to_delete);
                        let _ = std::fs::remove_file(path);
                        self.manager_vaults = scan_vaults_in_dir();
                        self.pending_delete_vault = None;
                    }
                    if ui.button("Cancel").clicked() {
                        self.pending_delete_vault = None;
                    }
                });
            });
            ui.separator();
        }

        if !self.manager_vaults.is_empty() {
            ui.label("Existing vaults:");
            let vault_list = self.manager_vaults.clone();
            for vault_name in vault_list {
                ui.horizontal(|ui| {
                    use crate::vault::read_encrypted_vault_file;
                    let maybe_timestamp =
                        if let Ok(ef) = read_encrypted_vault_file(vault_file_path(&vault_name)) {
                            ef.last_accessed_plaintext
                                .clone()
                                .unwrap_or_else(|| "Never".into())
                        } else {
                            "Never".into()
                        };
                    ui.label(format!("Vault: {vault_name}"));
                    ui.label(format!("(Last Accessed: {maybe_timestamp})"));

                    if ui.button("Open").clicked() {
                        self.clear_sensitive_state();
                        self.failed_attempts = 0;
                        self.login_error_msg.clear();

                        // Switch
                        self.active_vault_name = Some(vault_name.clone());
                        self.show_vault_manager = false;
                        self.vault.clear();
                        self.password_visible.clear();
                        self.is_logged_in = false;
                    }
                    if ui.button("Delete").clicked() {
                        self.pending_delete_vault = Some(vault_name.clone());
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

    // (B) Initial Creation UI
    fn show_initial_creation_ui(&mut self, ui: &mut egui::Ui) {
        let vault_name = self.active_vault_name.clone().unwrap_or_default();
        ui.heading(
            RichText::new(format!("Initial Creation for: {}", vault_name))
                .size(28.0)
                .color(Color32::RED),
        );

        ui.label("Pick your Argon2 Security Level (affects how expensive brute-forcing is):");
        ui.radio_value(&mut self.security_level, SecurityLevel::Low, "Low");
        ui.radio_value(&mut self.security_level, SecurityLevel::Medium, "Medium");
        ui.radio_value(&mut self.security_level, SecurityLevel::High, "High");
        ui.separator();

        ui.label("You must set BOTH a master password AND a pattern.");

        ui.separator();
        ui.label("Master Password (min 8 chars, uppercase, lowercase, digit):");
        ui.add(egui::TextEdit::singleline(&mut self.first_run_password).password(true));

        // Show password strength feedback
        if !self.first_run_password.is_empty() {
            match validate_master_password(&self.first_run_password) {
                Ok(()) => {
                    ui.colored_label(Color32::GREEN, "Password meets requirements");
                }
                Err(errors) => {
                    for err in errors {
                        ui.colored_label(Color32::RED, format!("- {}", err));
                    }
                }
            }
        }

        ui.separator();
        ui.label("Create a Pattern (6x6 grid, need >=8 unique clicks):");
        self.show_pattern_lock_first_run(ui);

        if self.first_run_pattern_unlocked {
            ui.colored_label(Color32::GREEN, format!("Pattern set! ({} cells)", self.first_run_pattern.len()));
        } else {
            ui.colored_label(Color32::RED, format!("Pattern not set (need >=8 unique, have {}).", self.first_run_pattern.len()));
        }

        if ui.button("Reset Pattern").clicked() {
            self.first_run_pattern.clear();
            self.first_run_pattern_unlocked = false;
        }

        ui.separator();
        if ui.button("Create Vault").clicked() {
            // Validate master password
            if let Err(errors) = validate_master_password(&self.first_run_password) {
                self.login_error_msg = format!("Password: {}", errors.join(", "));
            } else if !self.first_run_pattern_unlocked {
                self.login_error_msg = "Please create a pattern (8+ unique clicks)!".into();
            } else {
                let pattern_hash = pattern_to_string(&self.first_run_pattern);
                match create_new_vault_file(
                    &vault_name,
                    &self.first_run_password,
                    &pattern_hash,
                    self.security_level,
                ) {
                    Ok((mh, ph)) => {
                        self.master_hash = Some(mh);
                        self.pattern_hash = Some(ph);
                        self.vault.clear();
                        self.password_visible.clear();

                        self.is_logged_in = true;
                        self.master_password_input = self.first_run_password.clone();
                        self.login_error_msg.clear();

                        if let Ok((_, _, vault_key)) = load_vault_key_only(
                            &vault_name,
                            &self.first_run_password,
                            Some(pattern_hash.as_bytes()),
                            self.security_level,
                        ) {
                            self.current_vault_key = Some(vault_key);
                            // Update last_accessed to now, store in metadata
                            let _ = update_last_accessed_in_vault(
                                &vault_name,
                                self.current_vault_key.as_ref().unwrap(),
                                &[],
                            );
                        }

                        // Re-scan manager
                        self.manager_vaults = scan_vaults_in_dir();
                    }
                    Err(e) => {
                        self.login_error_msg = format!("Failed first-run vault: {e}");
                    }
                }
            }
        }

        if ui.button("Return to Vault Manager").clicked() {
            self.clear_sensitive_state();
            self.login_error_msg.clear();
            self.failed_attempts = 0;
            self.show_vault_manager = true;
            self.active_vault_name = None;
            self.is_logged_in = false;
            self.vault.clear();
            self.password_visible.clear();
        }
    }

    // (C) Login UI
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
            match load_vault_key_only(&vault_name, &pass, None, self.security_level) {
                Ok((mh, ph, key)) => match load_vault_data_decrypted(&vault_name, &key) {
                    Ok(vault_data) => {
                        self.current_vault_key = Some(key);
                        self.master_hash = Some(mh);
                        self.pattern_hash = ph;
                        self.vault = vault_data.entries;
                        self.custom_tags = vault_data.metadata.custom_tags;
                        self.password_visible = vec![false; self.vault.len()];
                        self.is_logged_in = true;
                        self.login_error_msg.clear();
                        self.failed_attempts = 0;

                        let _ = update_last_accessed_in_vault(
                            &vault_name,
                            self.current_vault_key.as_ref().unwrap(),
                            &self.vault,
                        );
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
            RichText::new("Or unlock with your Pattern (6x6 grid, >=8 clicks)")
                .size(20.0)
                .color(Color32::GRAY),
        );
        self.show_pattern_lock_login(ui);

        if self.is_pattern_unlock {
            if ui.button("Enter with Pattern").clicked() {
                let pattern_str = pattern_to_string(&self.pattern_attempt);
                match load_vault_key_only(
                    &vault_name,
                    "",
                    Some(pattern_str.as_bytes()),
                    self.security_level,
                ) {
                    Ok((mh, ph, key)) => match load_vault_data_decrypted(&vault_name, &key) {
                        Ok(vault_data) => {
                            self.current_vault_key = Some(key);
                            self.master_hash = Some(mh);
                            self.pattern_hash = ph;
                            self.vault = vault_data.entries;
                            self.custom_tags = vault_data.metadata.custom_tags;
                            self.password_visible = vec![false; self.vault.len()];
                            self.is_logged_in = true;
                            self.login_error_msg.clear();
                            self.failed_attempts = 0;

                            let _ = update_last_accessed_in_vault(
                                &vault_name,
                                self.current_vault_key.as_ref().unwrap(),
                                &self.vault,
                            );
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
            ui.colored_label(Color32::RED, format!("Pattern: {}/8 cells", self.pattern_attempt.len()));
        }

        if ui.button("Reset Pattern").clicked() {
            self.pattern_attempt.clear();
            self.is_pattern_unlock = false;
        }

        ui.separator();
        if ui.button("Return to Vault Manager").clicked() {
            self.clear_sensitive_state();
            self.login_error_msg.clear();
            self.failed_attempts = 0;

            // Return to manager
            self.show_vault_manager = true;
            self.active_vault_name = None;
            self.is_logged_in = false;
            self.vault.clear();
            self.password_visible.clear();
        }
    }

    // (D) Main Vault UI
    fn show_main_ui(&mut self, ui: &mut egui::Ui) {
        // We'll wrap the entire page in a vertical scroll so if things are cut off,
        // the user can scroll down.
        egui::ScrollArea::vertical()
            .auto_shrink([false; 2])
            .max_width(750.0)
            .show(ui, |ui| {
                // Handle pending entry deletion confirmation
                if let Some(idx) = self.pending_delete_entry {
                    ui.group(|ui| {
                        ui.colored_label(Color32::RED, format!("Delete entry #{}?", idx + 1));
                        if idx < self.vault.len() {
                            ui.label(format!("Website: {}", self.vault[idx].website));
                        }
                        ui.horizontal(|ui| {
                            if ui.button("Yes, Delete").clicked() {
                                if idx < self.vault.len() {
                                    let ent = &mut self.vault[idx];
                                    ent.website.zeroize();
                                    ent.username.zeroize();
                                    ent.password.zeroize();

                                    self.vault.remove(idx);
                                    self.password_visible.remove(idx);

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
                                self.pending_delete_entry = None;
                            }
                            if ui.button("Cancel").clicked() {
                                self.pending_delete_entry = None;
                            }
                        });
                    });
                    ui.separator();
                }

                // (1) Center the vault name, smaller text:
                ui.vertical_centered(|ui| {
                    ui.heading(
                        RichText::new("Password Options:")
                            .size(22.0)
                            .color(Color32::WHITE),
                    );
                });

                ui.separator();
                // (2) Two columns for password generation toggles:
                ui.columns(2, |cols| {
                    // Left column for checkboxes
                    cols[0].with_layout(egui::Layout::top_down(egui::Align::LEFT), |ui| {
                        ui.checkbox(&mut self.use_lowercase, "Lowercase (a-z)");
                        ui.checkbox(&mut self.use_uppercase, "Uppercase (A-Z)");
                        ui.checkbox(&mut self.use_digits, "Digits (0-9)");
                        ui.horizontal(|ui| {
                            ui.label("Length:");
                            ui.add(egui::Slider::new(&mut self.length, 1..=128).text("chars"));
                        });
                    });

                    // Right column for symbol selection
                    cols[1].with_layout(egui::Layout::top_down(egui::Align::LEFT), |ui| {
                        ui.label("Symbols to include:");
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
                        ui.spacing_mut().clone_from(&original_spacing);
                    });
                });

                ui.separator();

                ui.vertical_centered(|ui| {
                    ui.heading(
                        RichText::new("Store/Generate Logins")
                            .size(22.0)
                            .color(Color32::WHITE),
                    );
                });
                ui.separator();

                // Website + Username in one line:
                ui.horizontal(|ui| {
                    ui.label("Website:");
                    ui.text_edit_singleline(&mut self.new_website);
                    ui.label("Tag:");
                    // Build list of all tags (default + custom)
                    let default_tags = vec!["Social", "Work", "School", "Personal", "Extra"];
                    egui::ComboBox::from_label("")
                        .selected_text(&self.new_tags_str)
                        .show_ui(ui, |ui| {
                            // Default tags
                            for tag in &default_tags {
                                ui.selectable_value(
                                    &mut self.new_tags_str,
                                    tag.to_string(),
                                    *tag,
                                );
                            }
                            // Custom tags
                            for tag in &self.custom_tags.clone() {
                                ui.selectable_value(
                                    &mut self.new_tags_str,
                                    tag.clone(),
                                    format!("* {}", tag),
                                );
                            }
                        });
                    if ui.button("Manage Tags").clicked() {
                        self.show_tag_manager = !self.show_tag_manager;
                    }
                });

                // Tag manager UI (collapsible)
                if self.show_tag_manager {
                    ui.group(|ui| {
                        ui.label(RichText::new("Custom Tags Manager").color(Color32::YELLOW));
                        ui.horizontal(|ui| {
                            ui.label("New tag:");
                            ui.text_edit_singleline(&mut self.new_custom_tag);
                            if ui.button("Add Tag").clicked() {
                                let tag_name = self.new_custom_tag.trim().to_string();
                                if !tag_name.is_empty() && !self.custom_tags.contains(&tag_name) {
                                    self.custom_tags.push(tag_name);
                                    self.new_custom_tag.clear();
                                    // Save custom tags to vault
                                    if let Some(ref vault_key) = self.current_vault_key {
                                        let vault_name = self.active_vault_name.clone().unwrap_or_default();
                                        let _ = update_custom_tags(
                                            &vault_name,
                                            vault_key,
                                            &self.vault,
                                            &self.custom_tags,
                                        );
                                    }
                                }
                            }
                        });

                        if !self.custom_tags.is_empty() {
                            ui.label("Your custom tags:");
                            let tags_to_show = self.custom_tags.clone();
                            let mut tag_to_remove: Option<usize> = None;
                            for (idx, tag) in tags_to_show.iter().enumerate() {
                                ui.horizontal(|ui| {
                                    ui.label(format!("  * {}", tag));
                                    if ui.small_button("×").clicked() {
                                        tag_to_remove = Some(idx);
                                    }
                                });
                            }
                            if let Some(idx) = tag_to_remove {
                                self.custom_tags.remove(idx);
                                // Save custom tags to vault
                                if let Some(ref vault_key) = self.current_vault_key {
                                    let vault_name = self.active_vault_name.clone().unwrap_or_default();
                                    let _ = update_custom_tags(
                                        &vault_name,
                                        vault_key,
                                        &self.vault,
                                        &self.custom_tags,
                                    );
                                }
                            }
                        } else {
                            ui.colored_label(Color32::GRAY, "No custom tags yet");
                        }
                    });
                }

                ui.horizontal(|ui| {
                    ui.label("Username:");
                    ui.text_edit_singleline(&mut self.new_username);
                });

                // Next line: password + generate button + tag
                ui.horizontal(|ui| {
                    ui.label("Password:");
                    // Visible text field so the user can see the password
                    ui.text_edit_singleline(&mut self.generated_password);

                    if ui.button("Generate (Ctrl+G)").clicked() {
                        let user_symbols = self.collect_enabled_symbols();
                        self.generated_password = generate_password(
                            self.length,
                            self.use_lowercase,
                            self.use_uppercase,
                            self.use_digits,
                            &user_symbols,
                        );
                    }
                    // Show the entropy rating below the password text field, if not empty
                    if !self.generated_password.is_empty() {
                        let bits = estimate_entropy(&self.generated_password);
                        let strength_label = if bits < 60.0 {
                            ("Weak", Color32::RED)
                        } else if bits <= 100.0 {
                            ("Okay", Color32::YELLOW)
                        } else {
                            ("Strong", Color32::GREEN)
                        };
                        ui.horizontal(|ui| {
                            ui.colored_label(
                                strength_label.1,
                                format!("Entropy: ~{:.1} bits ({})", bits, strength_label.0),
                            );
                        });
                    }
                });

                ui.add_space(5.0);

                let add_button = egui::Button::new(
                    RichText::new("ADD TO VAULT")
                        .size(16.0)
                        .color(Color32::WHITE),
                )
                .fill(Color32::RED)
                .min_size(egui::vec2(150.0, 40.0));
                ui.vertical_centered(|ui| {
                    if ui.add(add_button).clicked() {
                        // Check empties
                        if self.new_website.trim().is_empty()
                            || self.new_username.trim().is_empty()
                            || self.generated_password.trim().is_empty()
                        {
                            self.login_error_msg =
                                "Website, Username, or Password is empty!".into();
                        } else {
                            // Check repeated password
                            for e in &self.vault {
                                if e.password == self.generated_password {
                                    self.login_error_msg =
                                        "Password is already used in vault!".into();
                                    return;
                                }
                            }

                            // We'll treat self.new_tags_str as the single chosen tag, if any
                            let mut tags = Vec::new();
                            if !self.new_tags_str.trim().is_empty() {
                                tags.push(self.new_tags_str.clone());
                            }

                            let new_entry = VaultEntry {
                                website: self.new_website.clone(),
                                username: self.new_username.clone(),
                                password: self.generated_password.clone(),
                                tags,
                            };

                            self.vault.push(new_entry);
                            self.password_visible.push(false);
                            self.login_error_msg.clear();

                            // Immediately save
                            if let Some(ref vault_key) = self.current_vault_key {
                                if let Some(mh) = &self.master_hash {
                                    let vault_name =
                                        self.active_vault_name.clone().unwrap_or_default();
                                    let _ = save_vault_file(
                                        &vault_name,
                                        mh,
                                        self.pattern_hash.as_deref(),
                                        vault_key,
                                        &self.vault,
                                    );
                                }
                            }

                            // Clear fields
                            self.new_website.zeroize();
                            self.new_website.clear();

                            self.new_username.zeroize();
                            self.new_username.clear();

                            self.generated_password.zeroize();
                            self.generated_password.clear();

                            self.new_tags_str.zeroize();
                            self.new_tags_str.clear();
                        }
                    }
                });
                ui.add_space(5.0);

                ui.separator();
                // (4) "Vault Entries" with tag filter and search on same line
                ui.vertical_centered(|ui| {
                    if let Some(name) = &self.active_vault_name {
                        ui.heading(
                            RichText::new(format!("Vault: {name} Entries"))
                                .size(22.0)
                                .color(Color32::WHITE),
                        );
                    }
                });

                ui.horizontal(|ui| {
                    ui.label("Search:");
                    ui.text_edit_singleline(&mut self.search_query);

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::TOP), |ui| {
                        ui.add_space(10.0);
                        let default_tags = vec!["Social", "Work", "School", "Personal", "Extra"];
                        egui::ComboBox::from_label("Tag Filter")
                            .selected_text(if self.tag_filter.is_empty() {
                                "All".to_string()
                            } else {
                                self.tag_filter.clone()
                            })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut self.tag_filter, "".to_string(), "All");
                                // Default tags
                                for tag in &default_tags {
                                    ui.selectable_value(
                                        &mut self.tag_filter,
                                        tag.to_string(),
                                        *tag,
                                    );
                                }
                                // Custom tags
                                for tag in &self.custom_tags.clone() {
                                    ui.selectable_value(
                                        &mut self.tag_filter,
                                        tag.clone(),
                                        format!("* {}", tag),
                                    );
                                }
                            });
                    });
                });

                ui.separator();

                // Build the list of relevant indices (filter by tag and search)
                let search_lower = self.search_query.to_lowercase();
                let mut relevant_indices = Vec::new();
                for (idx, entry) in self.vault.iter().enumerate() {
                    // Check tag filter
                    let tag_match = if self.tag_filter.is_empty() {
                        true
                    } else {
                        entry.tags.iter().any(|t| t.eq_ignore_ascii_case(&self.tag_filter))
                    };

                    // Check search query
                    let search_match = if self.search_query.is_empty() {
                        true
                    } else {
                        entry.website.to_lowercase().contains(&search_lower)
                            || entry.username.to_lowercase().contains(&search_lower)
                    };

                    if tag_match && search_match {
                        relevant_indices.push(idx);
                    }
                }

                let user_symbols = self.collect_enabled_symbols();

                // Now show the vault entries
                egui::ScrollArea::vertical()
                    .auto_shrink([false; 2])
                    .max_height(390.0)
                    .max_width(750.0)
                    .show(ui, |ui| {
                        for i in relevant_indices {
                            ui.group(|ui| {
                                ui.set_width(750.0);
                                ui.label(format!("Entry #{}", i + 1));

                                // Show tags only - access by index to avoid borrow issues
                                let tag_list = self.vault[i].tags.join(", ");
                                ui.horizontal(|ui| {
                                    ui.label("Tags:");
                                    ui.label(tag_list);
                                });

                                if self.editing_index == Some(i) {
                                    // Editing UI
                                    ui.group(|ui| {
                                        ui.set_max_width(750.0);
                                        ui.label("Edit Website:");
                                        ui.text_edit_singleline(&mut self.editing_website);
                                        ui.label("Edit Username:");
                                        ui.text_edit_singleline(&mut self.editing_username);
                                        ui.label("Edit Password:");
                                        ui.text_edit_singleline(&mut self.editing_password);
                                    });

                                    // Show a dynamic meter for typed password
                                    let e_bits = estimate_entropy(&self.editing_password);
                                    let e_label = if e_bits < 60.0 {
                                        ("Weak", Color32::RED)
                                    } else if e_bits <= 100.0 {
                                        ("Okay", Color32::YELLOW)
                                    } else {
                                        ("Strong", Color32::GREEN)
                                    };
                                    ui.horizontal(|ui| {
                                        ui.colored_label(
                                            e_label.1,
                                            format!("Entropy: ~{:.1} bits ({})", e_bits, e_label.0),
                                        );
                                    });

                                    // Track button clicks
                                    let save_clicked = ui.button("Save").clicked();
                                    let cancel_clicked = ui.button("Cancel").clicked();

                                    if save_clicked {
                                        self.vault[i].website = self.editing_website.clone();
                                        self.vault[i].username = self.editing_username.clone();
                                        self.vault[i].password = self.editing_password.clone();

                                        // FIXED: Save changes to disk
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

                                        self.editing_index = None;
                                        self.editing_website.zeroize();
                                        self.editing_username.zeroize();
                                        self.editing_password.zeroize();
                                    }
                                    if cancel_clicked {
                                        self.editing_index = None;
                                        self.editing_website.zeroize();
                                        self.editing_username.zeroize();
                                        self.editing_password.zeroize();
                                    }
                                } else {
                                    // Normal display UI - copy values to avoid borrow issues
                                    let website = self.vault[i].website.clone();
                                    let username = self.vault[i].username.clone();
                                    let password = self.vault[i].password.clone();
                                    let visible = self.password_visible[i];

                                    ui.horizontal(|ui| {
                                        ui.label(format!("Website: {}", website));
                                        ui.with_layout(
                                            egui::Layout::right_to_left(egui::Align::Center),
                                            |ui| {
                                                if ui.button("Copy").clicked() {
                                                    self.copy_to_clipboard(ui.ctx(), &website, "Website");
                                                }
                                            },
                                        );
                                    });

                                    ui.horizontal(|ui| {
                                        ui.label(format!("Username: {}", username));
                                        ui.with_layout(
                                            egui::Layout::right_to_left(egui::Align::Center),
                                            |ui| {
                                                if ui.button("Copy").clicked() {
                                                    self.copy_to_clipboard(ui.ctx(), &username, "Username");
                                                }
                                            },
                                        );
                                    });

                                    ui.horizontal(|ui| {
                                        let display_str = if visible { &password } else { "***" };
                                        ui.label(format!("Password: {}", display_str));

                                        ui.with_layout(
                                            egui::Layout::right_to_left(egui::Align::Center),
                                            |ui| {
                                                if ui.button("Copy").clicked() {
                                                    self.copy_to_clipboard(ui.ctx(), &password, "Password");
                                                }
                                                let eye_label = if visible { "Hide" } else { "Show" };
                                                if ui
                                                    .button(eye_label)
                                                    .on_hover_text("Toggle visibility")
                                                    .clicked()
                                                {
                                                    self.password_visible[i] = !self.password_visible[i];
                                                }
                                            },
                                        );
                                    });

                                    // Track button clicks outside closures
                                    let edit_clicked = ui.button("Edit").clicked();
                                    let regenerate_clicked = ui.button("Regenerate").on_hover_text("Regenerate Password").clicked();
                                    let delete_clicked = ui.button("Delete").on_hover_text("Remove this entry").clicked();

                                    if edit_clicked {
                                        self.editing_index = Some(i);
                                        self.editing_website = self.vault[i].website.clone();
                                        self.editing_username = self.vault[i].username.clone();
                                        self.editing_password = self.vault[i].password.clone();
                                    }

                                    if regenerate_clicked {
                                        let old_len = self.vault[i].password.len();
                                        let new_pwd = generate_password(
                                            old_len,
                                            self.use_lowercase,
                                            self.use_uppercase,
                                            self.use_digits,
                                            &user_symbols,
                                        );
                                        self.vault[i].password = new_pwd;

                                        // Save after regeneration
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

                                    if delete_clicked {
                                        self.pending_delete_entry = Some(i);
                                    }
                                }
                            });
                            ui.separator();
                        }
                    });

                ui.horizontal(|ui| {
                    if ui.button("Change Master Password").clicked() {
                        self.show_change_pw = true;
                        self.new_master_pw_old_input.clear();
                        self.new_master_pw.clear();
                    }
                    if ui.button("Change Pattern").clicked() {
                        self.show_change_pattern = true;
                        self.old_password_for_pattern.clear();
                        self.new_pattern_attempt.clear();
                        self.new_pattern_unlocked = false;
                    }

                    if ui.button("Logout (Ctrl+L)").clicked() {
                        self.perform_logout();
                    }
                });

                // Export/Import buttons
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("Export Backup").clicked() {
                        self.show_export_dialog = true;
                        self.export_result = None;
                    }
                    if ui.button("Import Backup").clicked() {
                        self.show_import_dialog = true;
                        self.import_data.clear();
                        self.import_error = None;
                    }
                });

                // Export dialog
                if self.show_export_dialog {
                    ui.group(|ui| {
                        ui.label(RichText::new("Export Vault").color(Color32::YELLOW).size(18.0));

                        if let Some(result) = self.export_result.clone() {
                            ui.label("Export successful! Copy the data below:");
                            egui::ScrollArea::vertical()
                                .max_height(150.0)
                                .show(ui, |ui| {
                                    ui.add(egui::TextEdit::multiline(&mut result.clone()).desired_width(f32::INFINITY));
                                });
                            if ui.button("Copy to Clipboard").clicked() {
                                self.copy_to_clipboard(ui.ctx(), &result, "Backup");
                            }
                        } else {
                            ui.colored_label(Color32::RED, "WARNING: CSV export contains passwords in plain text!");
                            ui.horizontal(|ui| {
                                if ui.button("Export Encrypted (Recommended)").clicked() {
                                    if let Some(ref vault_key) = self.current_vault_key {
                                        let vault_name = self.active_vault_name.clone().unwrap_or_default();
                                        match export_encrypted_backup(&vault_name, vault_key, &self.vault, &self.custom_tags) {
                                            Ok(backup) => {
                                                self.export_result = Some(backup);
                                            }
                                            Err(e) => {
                                                self.login_error_msg = format!("Export failed: {e}");
                                            }
                                        }
                                    }
                                }
                                if ui.button("Export CSV (Unencrypted)").clicked() {
                                    let csv = export_to_csv(&self.vault);
                                    self.export_result = Some(csv);
                                }
                            });
                        }

                        if ui.button("Close").clicked() {
                            self.show_export_dialog = false;
                            self.export_result = None;
                        }
                    });
                }

                // Import dialog
                if self.show_import_dialog {
                    ui.group(|ui| {
                        ui.label(RichText::new("Import Backup").color(Color32::YELLOW).size(18.0));
                        ui.label("Paste encrypted backup data below:");

                        egui::ScrollArea::vertical()
                            .max_height(150.0)
                            .show(ui, |ui| {
                                ui.add(egui::TextEdit::multiline(&mut self.import_data).desired_width(f32::INFINITY));
                            });

                        if let Some(ref err) = self.import_error {
                            ui.colored_label(Color32::RED, err);
                        }

                        ui.horizontal(|ui| {
                            if ui.button("Import (Merge)").clicked() {
                                if let Some(ref vault_key) = self.current_vault_key {
                                    match import_encrypted_backup(&self.import_data, vault_key) {
                                        Ok(imported_data) => {
                                            // Merge entries (avoid duplicates by website+username)
                                            let mut added = 0;
                                            for entry in imported_data.entries {
                                                let exists = self.vault.iter().any(|e| {
                                                    e.website == entry.website && e.username == entry.username
                                                });
                                                if !exists {
                                                    self.vault.push(entry);
                                                    self.password_visible.push(false);
                                                    added += 1;
                                                }
                                            }
                                            // Merge custom tags
                                            for tag in imported_data.metadata.custom_tags {
                                                if !self.custom_tags.contains(&tag) {
                                                    self.custom_tags.push(tag);
                                                }
                                            }
                                            // Save
                                            if let Some(mh) = &self.master_hash {
                                                let vault_name = self.active_vault_name.clone().unwrap_or_default();
                                                let _ = save_vault_file(
                                                    &vault_name,
                                                    mh,
                                                    self.pattern_hash.as_deref(),
                                                    vault_key,
                                                    &self.vault,
                                                );
                                                let _ = update_custom_tags(
                                                    &vault_name,
                                                    vault_key,
                                                    &self.vault,
                                                    &self.custom_tags,
                                                );
                                            }
                                            self.login_error_msg = format!("Imported {} new entries", added);
                                            self.show_import_dialog = false;
                                            self.import_data.clear();
                                            self.import_error = None;
                                        }
                                        Err(e) => {
                                            self.import_error = Some(format!("Import failed: {e}"));
                                        }
                                    }
                                }
                            }
                            if ui.button("Cancel").clicked() {
                                self.show_import_dialog = false;
                                self.import_data.clear();
                                self.import_error = None;
                            }
                        });

                        ui.colored_label(Color32::GRAY, "Note: Import merges entries. Duplicates (same website+username) are skipped.");
                    });
                }
            });
    }

    fn collect_enabled_symbols(&self) -> Vec<char> {
        self.symbol_toggles
            .iter()
            .filter(|s| s.enabled)
            .map(|s| s.sym)
            .collect()
    }

    fn show_change_password_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Change Master Password (requires old password)");
        ui.label("Old Password:");
        ui.add(egui::TextEdit::singleline(&mut self.new_master_pw_old_input).password(true));

        ui.label("New Password (min 8 chars, uppercase, lowercase, digit):");
        ui.add(egui::TextEdit::singleline(&mut self.new_master_pw).password(true));

        // Show new password strength feedback
        if !self.new_master_pw.is_empty() {
            match validate_master_password(&self.new_master_pw) {
                Ok(()) => {
                    ui.colored_label(Color32::GREEN, "New password meets requirements");
                }
                Err(errors) => {
                    for err in errors {
                        ui.colored_label(Color32::RED, format!("- {}", err));
                    }
                }
            }
        }

        if ui.button("Confirm").clicked() {
            // Validate new password first
            if let Err(errors) = validate_master_password(&self.new_master_pw) {
                self.login_error_msg = format!("New password: {}", errors.join(", "));
                return;
            }

            let vault_name = self.active_vault_name.clone().unwrap_or_default();
            if let Some(ref vault_key) = self.current_vault_key {
                let old_pass = self.new_master_pw_old_input.clone();
                match load_vault_key_only(&vault_name, &old_pass, None, self.security_level) {
                    Ok((_, _, _)) => {
                        let new_pw = std::mem::take(&mut self.new_master_pw);
                        match update_master_password_with_key(
                            &vault_name,
                            &old_pass,
                            &new_pw,
                            vault_key,
                            &self.vault,
                            self.pattern_hash.as_deref(),
                            self.security_level,
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
        ui.label("Enter your master password:");
        ui.add(egui::TextEdit::singleline(&mut self.old_password_for_pattern).password(true));

        ui.separator();
        ui.label("Create a new pattern (need >=8 unique clicks).");
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
                    let clr = if clicked {
                        Color32::RED
                    } else {
                        Color32::DARK_BLUE
                    };
                    let btn =
                        egui::Button::new(RichText::new("*").size(30.0).color(clr)).frame(false);
                    if ui.add_sized((35.0, 35.0), btn).clicked() {
                        // FIXED: Only add if not already clicked (unique cells only)
                        if !self.new_pattern_attempt.contains(&(row, col)) {
                            self.new_pattern_attempt.push((row, col));
                        }
                    }
                }
            });
        }

        *ui.spacing_mut() = original_spacing;

        if self.new_pattern_unlocked {
            ui.colored_label(Color32::GREEN, format!("New pattern set! ({} cells)", self.new_pattern_attempt.len()));
        } else {
            ui.colored_label(Color32::RED, format!("Need >=8 unique cells (have {}).", self.new_pattern_attempt.len()));
        }

        if ui.button("Reset Pattern").clicked() {
            self.new_pattern_attempt.clear();
            self.new_pattern_unlocked = false;
        }

        if ui.button("Confirm Pattern").clicked() {
            let old_pass = self.old_password_for_pattern.clone();
            match load_vault_key_only(&vault_name, &old_pass, None, self.security_level) {
                Ok((_, _, _)) => {
                    if let Some(ref vault_key) = self.current_vault_key {
                        let new_pat_str = pattern_to_string(&self.new_pattern_attempt);
                        match update_pattern_with_key(
                            &vault_name,
                            &old_pass,
                            &new_pat_str,
                            vault_key,
                            &self.vault,
                            self.security_level,
                        ) {
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
                    let clr = if clicked {
                        Color32::RED
                    } else {
                        Color32::DARK_BLUE
                    };
                    let btn =
                        egui::Button::new(RichText::new("*").size(30.0).color(clr)).frame(false);
                    if ui.add_sized((35.0, 35.0), btn).clicked() {
                        // FIXED: Only add if not already clicked (unique cells only)
                        if !self.first_run_pattern.contains(&(row, col)) {
                            self.first_run_pattern.push((row, col));
                        }
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
                    let clr = if clicked {
                        Color32::RED
                    } else {
                        Color32::DARK_BLUE
                    };
                    let btn =
                        egui::Button::new(RichText::new("*").size(30.0).color(clr)).frame(false);
                    if ui.add_sized((35.0, 35.0), btn).clicked() {
                        // FIXED: Only add if not already clicked (unique cells only)
                        if !self.pattern_attempt.contains(&(row, col)) {
                            self.pattern_attempt.push((row, col));
                        }
                    }
                }
            });
        }

        *ui.spacing_mut() = original_spacing;
    }

    fn handle_login_failure(&mut self, err_msg: String) {
        self.failed_attempts += 1;
        let max_attempts = 5; // Increased from 3 to 5
        let attempts_left = max_attempts - self.failed_attempts;
        if self.failed_attempts >= max_attempts {
            let vault_name = self.active_vault_name.clone().unwrap_or_default();
            let path = vault_file_path(&vault_name);
            if path.exists() {
                let _ = std::fs::remove_file(&path);
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
            self.manager_vaults = scan_vaults_in_dir();
        } else {
            self.login_error_msg =
                format!("{err_msg} - Wrong credentials! {attempts_left} attempts left.");
        }
    }
}

// We'll zeroize sensitive fields on Drop
impl Drop for QuickPassApp {
    fn drop(&mut self) {
        self.master_password_input.zeroize();
        self.old_password_for_pattern.zeroize();
        self.new_master_pw_old_input.zeroize();
        self.new_master_pw.zeroize();

        self.new_website.zeroize();
        self.new_username.zeroize();
        self.generated_password.zeroize();
        self.new_tags_str.zeroize();
        self.tag_filter.zeroize();
        self.search_query.zeroize();

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
