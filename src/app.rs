use eframe::{App, Frame, egui};
use egui::{Color32, RichText};
use zeroize::Zeroize;

use crate::manager::{scan_vaults_in_dir, vault_file_path};
use crate::password::{estimate_entropy, generate_password};
use crate::security::SecurityLevel;
use crate::vault::{
    VaultEntry, create_new_vault_file, load_vault_data_decrypted, load_vault_key_only,
    pattern_to_string, save_vault_file, update_last_accessed_in_vault,
    update_master_password_with_key, update_pattern_with_key,
};

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
    // (A) Vault Manager UI
    fn show_vault_manager_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading(
            RichText::new("Vault Manager")
                .size(28.0)
                .color(Color32::WHITE),
        );
        ui.label("Manage multiple vaults below.");

        ui.separator();

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
                        // Zeroize text fields first
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
                        let path = vault_file_path(&vault_name);
                        let _ = std::fs::remove_file(path);
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
            RichText::new("Or unlock with your Pattern (6×6 grid, >=8 clicks)")
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
            ui.colored_label(Color32::RED, "Pattern locked");
        }

        if ui.button("Reset Pattern").clicked() {
            self.pattern_attempt.clear();
            self.is_pattern_unlock = false;
        }

        ui.separator();
        if ui.button("Return to Vault Manager").clicked() {
            // Dismiss editing
            self.editing_index = None;
            self.editing_website.zeroize();
            self.editing_username.zeroize();
            self.editing_password.zeroize();
            // Zeroize text fields
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
                    egui::ComboBox::from_label("")
                        .selected_text(&self.new_tags_str)
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut self.new_tags_str,
                                "Social".to_string(),
                                "Social",
                            );
                            ui.selectable_value(&mut self.new_tags_str, "Work".to_string(), "Work");
                            ui.selectable_value(
                                &mut self.new_tags_str,
                                "School".to_string(),
                                "School",
                            );
                            ui.selectable_value(
                                &mut self.new_tags_str,
                                "Personal".to_string(),
                                "Personal",
                            );
                            ui.selectable_value(
                                &mut self.new_tags_str,
                                "Extra".to_string(),
                                "Extra",
                            );
                        });
                });
                ui.horizontal(|ui| {
                    ui.label("Username:");
                    ui.text_edit_singleline(&mut self.new_username);
                });

                // Next line: password + generate button + tag
                ui.horizontal(|ui| {
                    ui.label("Password:");
                    // Visible text field so the user can see the password
                    ui.text_edit_singleline(&mut self.generated_password);

                    if ui.button("↻ Generate").clicked() {
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
                // (4) "Vault Entries" with tag filter on same line
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
                    
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::TOP), |ui| {
                        ui.add_space(10.0);
                        egui::ComboBox::from_label("Tag Filter")
                            .selected_text(if self.tag_filter.is_empty() {
                                "All".to_string()
                            } else {
                                self.tag_filter.clone()
                            })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut self.tag_filter, "".to_string(), "All");
                                ui.selectable_value(
                                    &mut self.tag_filter,
                                    "Social".to_string(),
                                    "Social",
                                );
                                ui.selectable_value(
                                    &mut self.tag_filter,
                                    "Work".to_string(),
                                    "Work",
                                );
                                ui.selectable_value(
                                    &mut self.tag_filter,
                                    "School".to_string(),
                                    "School",
                                );
                                ui.selectable_value(
                                    &mut self.tag_filter,
                                    "Personal".to_string(),
                                    "Personal",
                                );
                                ui.selectable_value(
                                    &mut self.tag_filter,
                                    "Extra".to_string(),
                                    "Extra",
                                );
                            });
                    });
                });

                ui.separator();

                // Build the list of relevant indices
                let mut relevant_indices = Vec::new();
                for (idx, entry) in self.vault.iter().enumerate() {
                    if self.tag_filter.is_empty() {
                        relevant_indices.push(idx);
                    } else {
                        // if any tag matches ignoring ASCII case
                        if entry
                            .tags
                            .iter()
                            .any(|t| t.eq_ignore_ascii_case(&self.tag_filter))
                        {
                            relevant_indices.push(idx);
                        }
                    }
                }

                let mut delete_index: Option<usize> = None;
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
                                let entry = &mut self.vault[i];

                                // Show tags only
                                ui.horizontal(|ui| {
                                    ui.label("Tags:");
                                    let tag_list = entry.tags.join(", ");
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
                                    // Normal display UI
                                    ui.horizontal(|ui| {
                                        ui.label(format!("Website: {}", entry.website));
                                        // Right-justify copy
                                        ui.with_layout(
                                            egui::Layout::right_to_left(egui::Align::Center),
                                            |ui| {
                                                if ui.button("Copy").clicked() {
                                                    ui.ctx().copy_text(entry.website.clone());
                                                }
                                            },
                                        );
                                    });

                                    ui.horizontal(|ui| {
                                        ui.label(format!("Username: {}", entry.username));
                                        // Right-justify copy
                                        ui.with_layout(
                                            egui::Layout::right_to_left(egui::Align::Center),
                                            |ui| {
                                                if ui.button("Copy").clicked() {
                                                    ui.ctx().copy_text(entry.username.clone());
                                                }
                                            },
                                        );
                                    });

                                    ui.horizontal(|ui| {
                                        let visible = self.password_visible[i];
                                        let display_str =
                                            if visible { &entry.password } else { "***" };
                                        ui.label(format!("Password: {}", display_str));

                                        // Right-justify eye, then copy
                                        ui.with_layout(
                                            egui::Layout::right_to_left(egui::Align::Center),
                                            |ui| {
                                                if ui.button("Copy").clicked() {
                                                    ui.ctx().copy_text(entry.password.clone());
                                                }
                                                let eye_label =
                                                    if visible { "🙈" } else { "👁" };
                                                if ui
                                                    .button(eye_label)
                                                    .on_hover_text("Toggle visibility")
                                                    .clicked()
                                                {
                                                    self.password_visible[i] =
                                                        !self.password_visible[i];
                                                }
                                            },
                                        );
                                    });

                                    // Buttons: Edit, Regenerate, Delete
                                    ui.horizontal(|ui| {
                                        if ui.button("Edit").clicked() {
                                            self.editing_index = Some(i);
                                            self.editing_website = entry.website.clone();
                                            self.editing_username = entry.username.clone();
                                            self.editing_password = entry.password.clone();
                                        }

                                        if ui
                                            .button("↻")
                                            .on_hover_text("Regenerate Password")
                                            .clicked()
                                        {
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

                                        if ui
                                            .button("Delete")
                                            .on_hover_text("Remove this entry")
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
                    });

                // If an entry was marked for deletion, remove it now
                if let Some(idx) = delete_index {
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

                    if ui.button("Logout").clicked() {
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
                        // zero everything
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

                        self.show_vault_manager = true;
                        self.active_vault_name = None;
                        self.is_logged_in = false;
                        self.vault.clear();
                        self.password_visible.clear();
                        self.show_change_pw = false;
                        self.show_change_pattern = false;
                        self.current_vault_key = None;
                        self.failed_attempts = 0;
                        self.login_error_msg.clear();
                    }
                });
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

        ui.label("New Password:");
        ui.add(egui::TextEdit::singleline(&mut self.new_master_pw).password(true));

        if ui.button("Confirm").clicked() {
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
                    let clr = if clicked {
                        Color32::RED
                    } else {
                        Color32::DARK_BLUE
                    };
                    let btn =
                        egui::Button::new(RichText::new("●").size(30.0).color(clr)).frame(false);
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
                        egui::Button::new(RichText::new("●").size(30.0).color(clr)).frame(false);
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
                    let clr = if clicked {
                        Color32::RED
                    } else {
                        Color32::DARK_BLUE
                    };
                    let btn =
                        egui::Button::new(RichText::new("●").size(30.0).color(clr)).frame(false);
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

        for entry in &mut self.vault {
            entry.website.zeroize();
            entry.username.zeroize();
            entry.password.zeroize();
            // tags themselves are non-sensitive, but we could also zero them if desired
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
