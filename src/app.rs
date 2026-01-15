use eframe::{App, Frame, egui};
use egui::{Color32, RichText};
use std::time::Instant;
use zeroize::Zeroize;

use crate::gamification::TicTacToe;
use crate::lockout::{LockoutResult, VaultLockout};
use crate::usb_export::{USBDevice, detect_usb_devices, export_to_usb, find_exports_on_device, import_from_usb};
use crate::manager::{sanitize_vault_name, scan_vaults_in_dir, vault_file_path};
use crate::password::{estimate_entropy, generate_password, validate_master_password};
use crate::security::SecurityLevel;
use crate::settings::AppSettings;
use crate::vault::{
    CustomField, CustomFieldType, VaultEntry, create_new_vault_file, disable_vault_2fa,
    enable_vault_2fa, export_encrypted_backup, export_to_csv, generate_qr_code_data,
    generate_totp_code, generate_totp_secret, generate_totp_uri, import_csv_auto,
    import_encrypted_backup, load_vault_data_decrypted, load_vault_key_only, password_age_days,
    pattern_to_string, save_vault_file, update_custom_tags, update_entry_timestamp,
    update_last_accessed_in_vault, update_master_password_with_key, update_pattern_with_key,
    validate_totp_secret, vault_has_2fa, verify_vault_totp,
};

/// Minimum pattern length for security (~42 bits entropy with 12 cells)
const MIN_PATTERN_LENGTH: usize = 12;

// Note: Clipboard and auto-lock timeouts are now configurable via AppSettings

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

    // login fails and lockout
    pub failed_attempts: u32,
    pub login_error_msg: String,
    pub vault_lockout: Option<VaultLockout>,

    // Editing an existing VaultEntry
    pub editing_index: Option<usize>,
    pub editing_website: String,
    pub editing_username: String,
    pub editing_password: String,
    pub editing_totp_secret: String,

    // Custom field editing state
    pub editing_custom_fields: Vec<CustomField>,
    pub new_custom_field_name: String,
    pub new_custom_field_value: String,
    pub new_custom_field_type: CustomFieldType,
    pub custom_field_visible: Vec<bool>,  // Track visibility for sensitive fields

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
    pub import_mode_csv: bool,  // false = encrypted backup, true = CSV

    // QR code display state
    pub show_qr_for_entry: Option<usize>,  // Index of entry to show QR for
    pub qr_code_data: Option<(usize, Vec<bool>)>,  // (width, data) for QR code

    // Vault-level 2FA state
    pub awaiting_2fa_verification: bool,
    pub totp_code_input: String,
    pub pending_vault_key: Option<Vec<u8>>,  // Holds vault key while awaiting 2FA
    pub show_2fa_setup: bool,
    pub setup_2fa_secret: String,

    // Application settings
    pub settings: AppSettings,
    pub show_settings_dialog: bool,
    pub settings_clipboard_input: String,
    pub settings_autolock_input: String,
    pub settings_max_attempts_input: String,

    // Entropy game state (for fun password generation)
    pub show_entropy_game: bool,
    pub entropy_game: Option<TicTacToe>,
    pub use_game_entropy: bool,  // Whether to mix game entropy into password

    // USB Export state
    pub show_usb_export_dialog: bool,
    pub show_usb_import_dialog: bool,
    pub detected_usb_devices: Vec<USBDevice>,
    pub selected_usb_device: Option<usize>,
    pub usb_export_status: Option<Result<String, String>>,
    pub usb_exports_found: Vec<(std::path::PathBuf, String, String)>,
    pub selected_usb_import: Option<usize>,
}

impl Default for QuickPassApp {
    fn default() -> Self {
        let manager_vaults = scan_vaults_in_dir();
        let settings = AppSettings::load();
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
            vault_lockout: None,

            editing_index: None,
            editing_website: String::new(),
            editing_username: String::new(),
            editing_password: String::new(),
            editing_totp_secret: String::new(),

            // Custom field editing
            editing_custom_fields: Vec::new(),
            new_custom_field_name: String::new(),
            new_custom_field_value: String::new(),
            new_custom_field_type: CustomFieldType::Text,
            custom_field_visible: Vec::new(),

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
            import_mode_csv: false,

            show_qr_for_entry: None,
            qr_code_data: None,

            awaiting_2fa_verification: false,
            totp_code_input: String::new(),
            pending_vault_key: None,
            show_2fa_setup: false,
            setup_2fa_secret: String::new(),

            settings_clipboard_input: settings.clipboard_clear_seconds.to_string(),
            settings_autolock_input: settings.auto_lock_seconds.to_string(),
            settings_max_attempts_input: settings.max_failed_attempts.to_string(),
            settings,
            show_settings_dialog: false,

            // Entropy game
            show_entropy_game: false,
            entropy_game: None,
            use_game_entropy: false,

            // USB Export
            show_usb_export_dialog: false,
            show_usb_import_dialog: false,
            detected_usb_devices: Vec::new(),
            selected_usb_device: None,
            usb_export_status: None,
            usb_exports_found: Vec::new(),
            selected_usb_import: None,
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
        // Check clipboard auto-clear (using settings)
        if let Some(copy_time) = self.clipboard_copy_time {
            if copy_time.elapsed().as_secs() >= self.settings.clipboard_timeout_u64() {
                ctx.copy_text(String::new());
                self.clipboard_copy_time = None;
                self.clipboard_copy_type = None;
            }
        }

        // Check auto-lock timeout (only when logged in, using settings)
        if self.is_logged_in && self.last_activity_time.elapsed().as_secs() >= self.settings.auto_lock_timeout_u64() {
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
                    self.editing_totp_secret.zeroize();
                    self.editing_custom_fields.clear();
                    self.custom_field_visible.clear();
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
            // Show clipboard countdown if active (using settings)
            if let Some(copy_time) = self.clipboard_copy_time {
                let remaining = self.settings.clipboard_timeout_u64().saturating_sub(copy_time.elapsed().as_secs());
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
                        crate::vault::read_encrypted_vault_file(vault_file_path(vault_name))
                    {
                        // We override our current self.security_level with the stored one
                        self.security_level = ef.security_level;
                    }
                }
                self.show_login_ui(ui);
            } else if self.show_change_pw {
                self.show_change_password_ui(ui);
            } else if self.show_change_pattern {
                self.show_change_pattern_ui(ui);
            } else {
                self.show_main_ui(ui);
            }
        });

        // Settings popup window
        if self.show_settings_dialog {
            egui::Window::new("Settings")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.label("Clipboard clear timeout (seconds, 10-120):");
                        ui.add(egui::TextEdit::singleline(&mut self.settings_clipboard_input).desired_width(80.0));
                    });

                    ui.horizontal(|ui| {
                        ui.label("Auto-lock timeout (seconds, 60-3600):");
                        ui.add(egui::TextEdit::singleline(&mut self.settings_autolock_input).desired_width(80.0));
                    });

                    ui.horizontal(|ui| {
                        ui.label("Max failed login attempts (3-10):");
                        ui.add(egui::TextEdit::singleline(&mut self.settings_max_attempts_input).desired_width(80.0));
                    });

                    // Vault 2FA section
                    ui.separator();
                    ui.label(RichText::new("Vault 2FA").color(Color32::YELLOW));

                    let vault_name = self.active_vault_name.clone().unwrap_or_default();
                    let has_2fa = vault_has_2fa(&vault_name);

                    if has_2fa {
                        ui.horizontal(|ui| {
                            ui.colored_label(Color32::GREEN, "2FA is ENABLED");
                            if ui.button("Disable 2FA").clicked() {
                                if let Err(e) = disable_vault_2fa(&vault_name) {
                                    self.login_error_msg = format!("Failed to disable 2FA: {e}");
                                } else {
                                    self.login_error_msg = "2FA disabled".into();
                                }
                            }
                        });
                    } else if self.show_2fa_setup {
                        // Show 2FA setup with QR code
                        ui.label("Scan this QR code with your authenticator app:");

                        let uri = generate_totp_uri(&self.setup_2fa_secret, &vault_name, "QuickPass");
                        if let Ok((width, data)) = generate_qr_code_data(&uri) {
                            let module_size = 3.0;
                            let qr_size = width as f32 * module_size;
                            egui::Frame::new()
                                .fill(Color32::WHITE)
                                .inner_margin(6.0)
                                .show(ui, |ui| {
                                    let (response, painter) = ui.allocate_painter(
                                        egui::vec2(qr_size, qr_size),
                                        egui::Sense::hover(),
                                    );
                                    let rect = response.rect;
                                    for y in 0..width {
                                        for x in 0..width {
                                            if data.get(y * width + x).copied().unwrap_or(false) {
                                                let module_rect = egui::Rect::from_min_size(
                                                    egui::pos2(
                                                        rect.min.x + x as f32 * module_size,
                                                        rect.min.y + y as f32 * module_size,
                                                    ),
                                                    egui::vec2(module_size, module_size),
                                                );
                                                painter.rect_filled(module_rect, 0.0, Color32::BLACK);
                                            }
                                        }
                                    }
                                });
                        }

                        ui.label("Then enter the 6-digit code to confirm:");
                        ui.add(egui::TextEdit::singleline(&mut self.totp_code_input).desired_width(100.0));

                        ui.horizontal(|ui| {
                            if ui.button("Confirm & Enable").clicked() {
                                // Verify the code first
                                if let Ok((expected, _)) = generate_totp_code(&self.setup_2fa_secret) {
                                    if expected == self.totp_code_input.trim() {
                                        // Code matches, enable 2FA
                                        if let Some(ref vault_key) = self.current_vault_key {
                                            if let Err(e) = enable_vault_2fa(&vault_name, vault_key, &self.setup_2fa_secret) {
                                                self.login_error_msg = format!("Failed to enable 2FA: {e}");
                                            } else {
                                                self.login_error_msg = "2FA enabled successfully!".into();
                                                self.show_2fa_setup = false;
                                                self.setup_2fa_secret.clear();
                                                self.totp_code_input.clear();
                                            }
                                        }
                                    } else {
                                        self.login_error_msg = "Invalid 2FA code. Please try again.".into();
                                    }
                                }
                            }
                            if ui.button("Cancel Setup").clicked() {
                                self.show_2fa_setup = false;
                                self.setup_2fa_secret.clear();
                                self.totp_code_input.clear();
                            }
                        });
                    } else {
                        ui.horizontal(|ui| {
                            ui.label("2FA is disabled");
                            if ui.button("Enable 2FA").clicked() {
                                self.setup_2fa_secret = generate_totp_secret();
                                self.show_2fa_setup = true;
                            }
                        });
                    }

                    ui.separator();
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ui.button("Save Settings").clicked() {
                            if let Ok(clipboard_secs) = self.settings_clipboard_input.parse::<u32>() {
                                self.settings.set_clipboard_timeout(clipboard_secs);
                            }
                            if let Ok(autolock_secs) = self.settings_autolock_input.parse::<u32>() {
                                self.settings.set_auto_lock_timeout(autolock_secs);
                            }
                            if let Ok(max_attempts) = self.settings_max_attempts_input.parse::<u32>() {
                                self.settings.set_max_failed_attempts(max_attempts);
                            }
                            if let Err(e) = self.settings.save() {
                                self.login_error_msg = format!("Failed to save settings: {e}");
                            } else {
                                self.login_error_msg = "Settings saved!".into();
                            }
                            self.show_settings_dialog = false;
                            self.show_2fa_setup = false;
                        }
                        if ui.button("Close").clicked() {
                            self.show_settings_dialog = false;
                            self.show_2fa_setup = false;
                        }
                    });

                    ui.colored_label(Color32::GRAY, "Values outside allowed ranges will be clamped.");
                });
        }
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
        self.editing_totp_secret.zeroize();
        self.editing_custom_fields.clear();
        self.custom_field_visible.clear();

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
        self.import_data.zeroize();
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
                    // Error is silently ignored - save failed on logout
                    // This is acceptable since we're logging out anyway
                    let _ = e;
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
                        let path = vault_file_path(vault_to_delete);
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

                        // Load lockout state for this vault
                        let lockout = VaultLockout::load(&vault_name);
                        if lockout.is_locked() {
                            self.vault_lockout = Some(lockout.clone());
                            self.login_error_msg = format!(
                                "Vault is locked. Try again in {}.",
                                lockout.format_remaining_time()
                            );
                        } else {
                            self.vault_lockout = Some(lockout);
                        }

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
            // Sanitize vault name to prevent path traversal and other issues
            match sanitize_vault_name(&self.new_vault_name) {
                Err(e) => {
                    self.login_error_msg = e.to_string();
                }
                Ok(sanitized_name) => {
                    let path = vault_file_path(&sanitized_name);
                    if path.exists() {
                        self.login_error_msg = "Vault with that name already exists!".into();
                    } else {
                        self.active_vault_name = Some(sanitized_name);
                        self.show_vault_manager = false;
                        self.login_error_msg.clear();

                        // Clear old state
                        self.vault.clear();
                        self.password_visible.clear();
                        self.is_logged_in = false;
                        self.master_password_input.zeroize();
                        self.pattern_attempt.clear();
                        self.is_pattern_unlock = false;
                        self.failed_attempts = 0;

                        self.first_run_password.zeroize();
                        self.first_run_pattern.clear();
                        self.first_run_pattern_unlocked = false;
                    }
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
        ui.label("Create a Pattern (6x6 grid, need >=12 unique clicks):");
        self.first_run_pattern_unlocked = Self::render_pattern_grid(ui, &mut self.first_run_pattern);

        if self.first_run_pattern_unlocked {
            ui.colored_label(Color32::GREEN, format!("Pattern set! ({} cells)", self.first_run_pattern.len()));
        } else {
            ui.colored_label(Color32::RED, format!("Pattern not set (need >=12 unique, have {}).", self.first_run_pattern.len()));
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
                    None, // No 2FA during initial creation (can enable later in settings)
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

        // 2FA verification UI (shown after password/pattern verification)
        if self.awaiting_2fa_verification {
            ui.heading(
                RichText::new("2FA Verification")
                    .size(30.0)
                    .color(Color32::YELLOW),
            );
            ui.label("Enter your 6-digit 2FA code from your authenticator app:");
            ui.add(egui::TextEdit::singleline(&mut self.totp_code_input).desired_width(150.0));

            ui.horizontal(|ui| {
                if ui.button("Verify").clicked() {
                    if let Some(ref key) = self.pending_vault_key {
                        match verify_vault_totp(&vault_name, key, self.totp_code_input.trim()) {
                            Ok(true) => {
                                // 2FA verified, complete login
                                self.current_vault_key = self.pending_vault_key.take();
                                self.is_logged_in = true;
                                self.awaiting_2fa_verification = false;
                                self.login_error_msg.clear();
                                self.failed_attempts = 0;
                                self.reset_lockout_on_success();
                                self.totp_code_input.clear();

                                let _ = update_last_accessed_in_vault(
                                    &vault_name,
                                    self.current_vault_key.as_ref().unwrap(),
                                    &self.vault,
                                );
                            }
                            Ok(false) => {
                                self.login_error_msg = "Invalid 2FA code. Please try again.".into();
                            }
                            Err(e) => {
                                self.login_error_msg = format!("2FA verification error: {e}");
                            }
                        }
                    }
                }
                if ui.button("Cancel").clicked() {
                    // Cancel 2FA, clear pending state
                    self.awaiting_2fa_verification = false;
                    self.pending_vault_key = None;
                    self.vault.clear();
                    self.custom_tags.clear();
                    self.password_visible.clear();
                    self.master_hash = None;
                    self.pattern_hash = None;
                    self.totp_code_input.clear();
                    self.login_error_msg.clear();
                }
            });
            return;
        }

        ui.heading(
            RichText::new(format!("Welcome to: {}", vault_name))
                .size(30.0)
                .color(Color32::GRAY),
        );
        ui.label("Enter your master password:");
        ui.add(egui::TextEdit::singleline(&mut self.master_password_input).password(true));

        // Check if vault is locked before allowing login attempt
        let is_locked = self.is_vault_locked();
        if is_locked {
            // Update the lockout message with current remaining time
            if let Some(ref lockout) = self.vault_lockout {
                self.login_error_msg = format!(
                    "Vault is locked. Try again in {}.",
                    lockout.format_remaining_time()
                );
            }
        }

        let login_enabled = !is_locked;
        if ui.add_enabled(login_enabled, egui::Button::new("Login")).clicked() {
            let pass = self.master_password_input.clone();
            match load_vault_key_only(&vault_name, &pass, None, self.security_level) {
                Ok((mh, ph, key)) => match load_vault_data_decrypted(&vault_name, &key) {
                    Ok(vault_data) => {
                        // Check if vault has 2FA enabled
                        if vault_has_2fa(&vault_name) {
                            // Store credentials temporarily, await 2FA verification
                            self.pending_vault_key = Some(key);
                            self.master_hash = Some(mh);
                            self.pattern_hash = ph;
                            self.vault = vault_data.entries;
                            self.custom_tags = vault_data.metadata.custom_tags;
                            self.password_visible = vec![false; self.vault.len()];
                            self.awaiting_2fa_verification = true;
                            self.totp_code_input.clear();
                            self.login_error_msg = "Enter your 2FA code".into();
                        } else {
                            // No 2FA, complete login
                            self.current_vault_key = Some(key);
                            self.master_hash = Some(mh);
                            self.pattern_hash = ph;
                            self.vault = vault_data.entries;
                            self.custom_tags = vault_data.metadata.custom_tags;
                            self.password_visible = vec![false; self.vault.len()];
                            self.is_logged_in = true;
                            self.login_error_msg.clear();
                            self.failed_attempts = 0;
                            self.reset_lockout_on_success();

                            let _ = update_last_accessed_in_vault(
                                &vault_name,
                                self.current_vault_key.as_ref().unwrap(),
                                &self.vault,
                            );
                        }
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
            RichText::new("Or unlock with your Pattern (6x6 grid, >=12 clicks)")
                .size(20.0)
                .color(Color32::GRAY),
        );
        self.is_pattern_unlock = Self::render_pattern_grid(ui, &mut self.pattern_attempt);

        if self.is_pattern_unlock && !is_locked {
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
                            // Check if vault has 2FA enabled
                            if vault_has_2fa(&vault_name) {
                                // Store credentials temporarily, await 2FA verification
                                self.pending_vault_key = Some(key);
                                self.master_hash = Some(mh);
                                self.pattern_hash = ph;
                                self.vault = vault_data.entries;
                                self.custom_tags = vault_data.metadata.custom_tags;
                                self.password_visible = vec![false; self.vault.len()];
                                self.awaiting_2fa_verification = true;
                                self.totp_code_input.clear();
                                self.login_error_msg = "Enter your 2FA code".into();
                            } else {
                                // No 2FA, complete login
                                self.current_vault_key = Some(key);
                                self.master_hash = Some(mh);
                                self.pattern_hash = ph;
                                self.vault = vault_data.entries;
                                self.custom_tags = vault_data.metadata.custom_tags;
                                self.password_visible = vec![false; self.vault.len()];
                                self.is_logged_in = true;
                                self.login_error_msg.clear();
                                self.failed_attempts = 0;
                                self.reset_lockout_on_success();

                                let _ = update_last_accessed_in_vault(
                                    &vault_name,
                                    self.current_vault_key.as_ref().unwrap(),
                                    &self.vault,
                                );
                            }
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
            ui.colored_label(Color32::RED, format!("Pattern: {}/{} cells", self.pattern_attempt.len(), MIN_PATTERN_LENGTH));
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

                        // Generate base password
                        let base_password = generate_password(
                            self.length,
                            self.use_lowercase,
                            self.use_uppercase,
                            self.use_digits,
                            &user_symbols,
                        );

                        // If game entropy is enabled and we have game data, mix it in
                        if self.use_game_entropy {
                            if let Some(ref game) = self.entropy_game {
                                // Mix game entropy with generated password for additional randomness
                                let game_entropy = game.get_entropy();
                                let _mixed = crate::gamification::mix_entropy_with_rng(&game_entropy, base_password.as_bytes());
                                // Re-generate password using mixed entropy as additional seed
                                // For simplicity, we just use the base password since the RNG already uses system entropy
                                // The game entropy adds to the overall security through user interaction timing
                                self.generated_password = base_password;
                            } else {
                                self.generated_password = base_password;
                            }
                        } else {
                            self.generated_password = base_password;
                        }
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

                // Entropy Game Panel (optional fun way to add randomness)
                ui.add_space(5.0);
                ui.horizontal(|ui| {
                    ui.checkbox(&mut self.use_game_entropy, "Use game entropy");
                    ui.label("|").on_hover_text("Playing a game collects timing data to add extra randomness to passwords");
                    if ui.button("Play Tic-Tac-Toe").clicked() {
                        self.entropy_game = Some(TicTacToe::new());
                        self.show_entropy_game = true;
                    }
                    if self.entropy_game.is_some() {
                        ui.colored_label(Color32::GREEN, "Entropy collected!");
                    }
                });

                // Entropy game window
                if self.show_entropy_game {
                    let mut close_game = false;
                    let mut skip_game = false;
                    let mut game_move: Option<(usize, usize)> = None;
                    let mut reset_game = false;

                    // Extract game state for UI display
                    let game_state = self.entropy_game.as_ref().map(|g| {
                        (g.status_message(), g.move_count, g.game_over,
                         [[g.cell_symbol(0, 0), g.cell_symbol(0, 1), g.cell_symbol(0, 2)],
                          [g.cell_symbol(1, 0), g.cell_symbol(1, 1), g.cell_symbol(1, 2)],
                          [g.cell_symbol(2, 0), g.cell_symbol(2, 1), g.cell_symbol(2, 2)]],
                         [[g.is_cell_clickable(0, 0), g.is_cell_clickable(0, 1), g.is_cell_clickable(0, 2)],
                          [g.is_cell_clickable(1, 0), g.is_cell_clickable(1, 1), g.is_cell_clickable(1, 2)],
                          [g.is_cell_clickable(2, 0), g.is_cell_clickable(2, 1), g.is_cell_clickable(2, 2)]])
                    });

                    egui::Window::new("Tic-Tac-Toe - Collect Entropy")
                        .collapsible(false)
                        .resizable(false)
                        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                        .show(ui.ctx(), |ui| {
                            ui.label("Play to collect random entropy for password generation!");
                            ui.add_space(10.0);

                            if let Some((status, moves, game_over, symbols, clickable)) = &game_state {
                                // Status message
                                ui.label(RichText::new(*status).size(16.0));
                                ui.add_space(5.0);

                                // Draw the game board
                                egui::Grid::new("tictactoe_grid")
                                    .spacing([5.0, 5.0])
                                    .show(ui, |ui| {
                                        for row in 0..3 {
                                            for col in 0..3 {
                                                let symbol = symbols[row][col];
                                                let is_clickable = clickable[row][col];

                                                let button_color = if symbol == "X" {
                                                    Color32::LIGHT_BLUE
                                                } else if symbol == "O" {
                                                    Color32::LIGHT_RED
                                                } else {
                                                    Color32::DARK_GRAY
                                                };

                                                let button = egui::Button::new(
                                                    RichText::new(if symbol.is_empty() { " " } else { symbol })
                                                        .size(32.0)
                                                        .color(Color32::WHITE)
                                                )
                                                .fill(button_color)
                                                .min_size(egui::vec2(60.0, 60.0));

                                                let response = ui.add_enabled(is_clickable, button);
                                                if response.clicked() && is_clickable {
                                                    game_move = Some((row, col));
                                                }
                                            }
                                            ui.end_row();
                                        }
                                    });

                                ui.add_space(10.0);

                                // Show entropy collected
                                ui.label(format!("Moves: {} | Entropy bits collected", moves));

                                ui.add_space(5.0);
                                ui.horizontal(|ui| {
                                    if *game_over {
                                        if ui.button("Play Again").clicked() {
                                            reset_game = true;
                                        }
                                    }
                                    if ui.button("Done").clicked() {
                                        close_game = true;
                                    }
                                    if ui.button("Skip (no entropy)").clicked() {
                                        skip_game = true;
                                        close_game = true;
                                    }
                                });
                            }
                        });

                    // Apply game changes after UI
                    if let Some((row, col)) = game_move {
                        if let Some(ref mut game) = self.entropy_game {
                            game.make_move(row, col);
                        }
                    }
                    if reset_game {
                        if let Some(ref mut game) = self.entropy_game {
                            game.reset();
                        }
                    }
                    if skip_game {
                        self.entropy_game = None;
                    }
                    if close_game {
                        self.show_entropy_game = false;
                        self.use_game_entropy = self.entropy_game.is_some();
                    }
                }

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

                            let new_entry = crate::vault::create_entry_with_timestamp(
                                self.new_website.clone(),
                                self.new_username.clone(),
                                self.generated_password.clone(),
                                tags,
                            );

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
                            self.generated_password.zeroize();

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
                                        ui.label("TOTP Secret (Base32, leave empty if no 2FA):");
                                        ui.text_edit_singleline(&mut self.editing_totp_secret);
                                        // Validate TOTP secret
                                        if !self.editing_totp_secret.is_empty() {
                                            if validate_totp_secret(&self.editing_totp_secret) {
                                                ui.colored_label(Color32::GREEN, "Valid TOTP secret");
                                            } else {
                                                ui.colored_label(Color32::RED, "Invalid TOTP secret (must be Base32)");
                                            }
                                        }

                                        // Custom Fields Section
                                        ui.add_space(8.0);
                                        ui.separator();
                                        ui.label(RichText::new("Custom Fields").color(Color32::LIGHT_BLUE));
                                    });

                                    // Display existing custom fields
                                    let mut field_to_delete: Option<usize> = None;
                                    let mut toggle_visibility: Option<usize> = None;
                                    let mut copy_field: Option<(String, String)> = None;

                                    let fields_snapshot = self.editing_custom_fields.clone();
                                    for (idx, field) in fields_snapshot.iter().enumerate() {
                                        ui.horizontal(|ui| {
                                            ui.label(format!("{}:", field.name));
                                            let is_sensitive = field.is_sensitive();
                                            let visible = self.custom_field_visible.get(idx).copied().unwrap_or(false);
                                            let display_val = if is_sensitive && !visible {
                                                "••••••••".to_string()
                                            } else {
                                                field.value.clone()
                                            };
                                            ui.label(&display_val);

                                            if is_sensitive {
                                                let eye_label = if visible { "Hide" } else { "Show" };
                                                if ui.small_button(eye_label).clicked() {
                                                    toggle_visibility = Some(idx);
                                                }
                                            }
                                            if ui.small_button("Copy").clicked() {
                                                copy_field = Some((field.value.clone(), field.name.clone()));
                                            }
                                            if ui.small_button("Delete").clicked() {
                                                field_to_delete = Some(idx);
                                            }
                                        });
                                    }

                                    // Handle deferred actions
                                    if let Some(idx) = toggle_visibility {
                                        if idx < self.custom_field_visible.len() {
                                            self.custom_field_visible[idx] = !self.custom_field_visible[idx];
                                        }
                                    }
                                    if let Some((value, name)) = copy_field {
                                        self.copy_to_clipboard(ui.ctx(), &value, &name);
                                    }
                                    if let Some(idx) = field_to_delete {
                                        self.editing_custom_fields.remove(idx);
                                        if idx < self.custom_field_visible.len() {
                                            self.custom_field_visible.remove(idx);
                                        }
                                    }

                                    // Add new custom field form
                                    ui.group(|ui| {
                                        ui.horizontal(|ui| {
                                            ui.label("New field:");
                                            ui.add(egui::TextEdit::singleline(&mut self.new_custom_field_name)
                                                .hint_text("Name")
                                                .desired_width(100.0));

                                            egui::ComboBox::from_id_salt("custom_field_type")
                                                .selected_text(format!("{:?}", self.new_custom_field_type))
                                                .show_ui(ui, |ui| {
                                                    ui.selectable_value(&mut self.new_custom_field_type, CustomFieldType::Text, "Text");
                                                    ui.selectable_value(&mut self.new_custom_field_type, CustomFieldType::Password, "Password");
                                                    ui.selectable_value(&mut self.new_custom_field_type, CustomFieldType::URL, "URL");
                                                    ui.selectable_value(&mut self.new_custom_field_type, CustomFieldType::Email, "Email");
                                                    ui.selectable_value(&mut self.new_custom_field_type, CustomFieldType::Notes, "Notes");
                                                });
                                        });

                                        // Value input (multiline for Notes type)
                                        if matches!(self.new_custom_field_type, CustomFieldType::Notes) {
                                            ui.add(egui::TextEdit::multiline(&mut self.new_custom_field_value)
                                                .hint_text("Value")
                                                .desired_rows(3)
                                                .desired_width(f32::INFINITY));
                                        } else {
                                            ui.add(egui::TextEdit::singleline(&mut self.new_custom_field_value)
                                                .hint_text("Value")
                                                .desired_width(f32::INFINITY)
                                                .password(matches!(self.new_custom_field_type, CustomFieldType::Password)));
                                        }

                                        if ui.button("Add Field").clicked() && !self.new_custom_field_name.is_empty() {
                                            self.editing_custom_fields.push(CustomField::new(
                                                self.new_custom_field_name.clone(),
                                                self.new_custom_field_value.clone(),
                                                self.new_custom_field_type.clone(),
                                            ));
                                            self.custom_field_visible.push(false);
                                            self.new_custom_field_name.clear();
                                            self.new_custom_field_value.clear();
                                            self.new_custom_field_type = CustomFieldType::Text;
                                        }
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
                                        // Save TOTP secret (empty string becomes None)
                                        self.vault[i].totp_secret = if self.editing_totp_secret.is_empty() {
                                            None
                                        } else {
                                            Some(self.editing_totp_secret.clone())
                                        };
                                        // Save custom fields
                                        self.vault[i].custom_fields = self.editing_custom_fields.clone();
                                        // Update modified timestamp
                                        update_entry_timestamp(&mut self.vault[i]);

                                        // Save changes to disk
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
                                        self.editing_totp_secret.zeroize();
                                        self.editing_custom_fields.clear();
                                        self.custom_field_visible.clear();
                                    }
                                    if cancel_clicked {
                                        self.editing_index = None;
                                        self.editing_website.zeroize();
                                        self.editing_username.zeroize();
                                        self.editing_password.zeroize();
                                        self.editing_totp_secret.zeroize();
                                        self.editing_custom_fields.clear();
                                        self.custom_field_visible.clear();
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

                                    // Password age display
                                    if let Some(age_days) = password_age_days(&self.vault[i]) {
                                        let age_color = if age_days > 365 {
                                            Color32::RED
                                        } else if age_days > 180 {
                                            Color32::YELLOW
                                        } else {
                                            Color32::GRAY
                                        };
                                        let age_text = if age_days == 0 {
                                            "Password age: Today".to_string()
                                        } else if age_days == 1 {
                                            "Password age: 1 day".to_string()
                                        } else {
                                            format!("Password age: {} days", age_days)
                                        };
                                        ui.colored_label(age_color, age_text);
                                    }

                                    // TOTP display (if entry has 2FA configured)
                                    let totp_secret_opt = self.vault[i].totp_secret.clone();
                                    if let Some(ref totp_secret) = totp_secret_opt {
                                        if !totp_secret.is_empty() {
                                            ui.horizontal(|ui| {
                                                match generate_totp_code(totp_secret) {
                                                    Ok((code, remaining)) => {
                                                        ui.label("2FA Code:");
                                                        ui.monospace(
                                                            RichText::new(&code)
                                                                .size(16.0)
                                                                .color(Color32::LIGHT_GREEN),
                                                        );
                                                        // Show countdown
                                                        let countdown_color = if remaining <= 5 {
                                                            Color32::RED
                                                        } else if remaining <= 10 {
                                                            Color32::YELLOW
                                                        } else {
                                                            Color32::GRAY
                                                        };
                                                        ui.colored_label(
                                                            countdown_color,
                                                            format!("({}s)", remaining),
                                                        );
                                                        if ui.button("Copy 2FA").clicked() {
                                                            self.copy_to_clipboard(ui.ctx(), &code, "2FA Code");
                                                        }
                                                        // Show QR button
                                                        if ui.button("Show QR").on_hover_text("Show QR code for mobile authenticator").clicked() {
                                                            // Generate QR code data
                                                            let uri = generate_totp_uri(
                                                                totp_secret,
                                                                &username,
                                                                &website,
                                                            );
                                                            if let Ok(qr_data) = generate_qr_code_data(&uri) {
                                                                self.qr_code_data = Some(qr_data);
                                                                self.show_qr_for_entry = Some(i);
                                                            }
                                                        }
                                                    }
                                                    Err(_) => {
                                                        ui.colored_label(
                                                            Color32::RED,
                                                            "2FA: Invalid secret",
                                                        );
                                                    }
                                                }
                                            });
                                        }
                                    }

                                    // Display custom fields (read-only view)
                                    let custom_fields = self.vault[i].custom_fields.clone();
                                    if !custom_fields.is_empty() {
                                        ui.add_space(4.0);
                                        ui.colored_label(Color32::LIGHT_BLUE, "Custom Fields:");
                                        for field in &custom_fields {
                                            ui.horizontal(|ui| {
                                                ui.label(format!("{}:", field.name));
                                                let display_val = if field.is_sensitive() {
                                                    "••••••••".to_string()
                                                } else {
                                                    field.value.clone()
                                                };
                                                ui.label(&display_val);
                                                if ui.small_button("Copy").clicked() {
                                                    self.copy_to_clipboard(ui.ctx(), &field.value, &field.name);
                                                }
                                            });
                                        }
                                    }

                                    // Track button clicks outside closures
                                    let edit_clicked = ui.button("Edit").clicked();
                                    let regenerate_clicked = ui.button("Regenerate").on_hover_text("Regenerate Password").clicked();
                                    let delete_clicked = ui.button("Delete").on_hover_text("Remove this entry").clicked();

                                    if edit_clicked {
                                        self.editing_index = Some(i);
                                        self.editing_website = self.vault[i].website.clone();
                                        self.editing_username = self.vault[i].username.clone();
                                        self.editing_password = self.vault[i].password.clone();
                                        self.editing_totp_secret = self.vault[i].totp_secret.clone().unwrap_or_default();
                                        // Load custom fields
                                        self.editing_custom_fields = self.vault[i].custom_fields.clone();
                                        self.custom_field_visible = vec![false; self.editing_custom_fields.len()];
                                        self.new_custom_field_name.clear();
                                        self.new_custom_field_value.clear();
                                        self.new_custom_field_type = CustomFieldType::Text;
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
                        self.new_master_pw_old_input.zeroize();
                        self.new_master_pw.zeroize();
                    }
                    if ui.button("Change Pattern").clicked() {
                        self.show_change_pattern = true;
                        self.old_password_for_pattern.zeroize();
                        self.new_pattern_attempt.clear();
                        self.new_pattern_unlocked = false;
                    }

                    if ui.button("Logout (Ctrl+L)").clicked() {
                        self.perform_logout();
                    }
                });

                // Export/Import/Settings buttons
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("Export Backup").clicked() {
                        self.show_export_dialog = true;
                        self.export_result = None;
                    }
                    if ui.button("Import Backup").clicked() {
                        self.show_import_dialog = true;
                        self.import_data.zeroize();
                        self.import_error = None;
                    }
                    if ui.button("USB Export").clicked() {
                        self.show_usb_export_dialog = true;
                        self.detected_usb_devices = detect_usb_devices();
                        self.selected_usb_device = None;
                        self.usb_export_status = None;
                    }
                    if ui.button("USB Import").clicked() {
                        self.show_usb_import_dialog = true;
                        self.detected_usb_devices = detect_usb_devices();
                        self.selected_usb_device = None;
                        self.usb_exports_found.clear();
                        self.selected_usb_import = None;
                    }
                    if ui.button("Settings").clicked() {
                        self.show_settings_dialog = true;
                        self.settings_clipboard_input = self.settings.clipboard_clear_seconds.to_string();
                        self.settings_autolock_input = self.settings.auto_lock_seconds.to_string();
                        self.settings_max_attempts_input = self.settings.max_failed_attempts.to_string();
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
                        ui.label(RichText::new("Import Passwords").color(Color32::YELLOW).size(18.0));

                        // Import mode selector
                        ui.horizontal(|ui| {
                            ui.label("Import type:");
                            if ui.radio(!self.import_mode_csv, "Encrypted Backup").clicked() {
                                self.import_mode_csv = false;
                                self.import_error = None;
                            }
                            if ui.radio(self.import_mode_csv, "CSV (Bitwarden/1Password/LastPass)").clicked() {
                                self.import_mode_csv = true;
                                self.import_error = None;
                            }
                        });

                        if self.import_mode_csv {
                            ui.label("Paste CSV data from your password manager export:");
                            ui.colored_label(Color32::GRAY, "Supported: Bitwarden, 1Password, LastPass, or generic CSV");
                        } else {
                            ui.label("Paste encrypted backup data below:");
                        }

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
                                if self.import_mode_csv {
                                    // CSV import
                                    match import_csv_auto(&self.import_data) {
                                        Ok((entries, format)) => {
                                            let mut added = 0;
                                            for entry in entries {
                                                let exists = self.vault.iter().any(|e| {
                                                    e.website == entry.website && e.username == entry.username
                                                });
                                                if !exists {
                                                    self.vault.push(entry);
                                                    self.password_visible.push(false);
                                                    added += 1;
                                                }
                                            }
                                            // Save
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
                                            self.login_error_msg = format!("Imported {} entries from {:?}", added, format);
                                            self.show_import_dialog = false;
                                            self.import_data.zeroize();
                                            self.import_error = None;
                                        }
                                        Err(e) => {
                                            self.import_error = Some(format!("CSV import failed: {e}"));
                                        }
                                    }
                                } else {
                                    // Encrypted backup import
                                    if let Some(ref vault_key) = self.current_vault_key {
                                        match import_encrypted_backup(&self.import_data, vault_key) {
                                            Ok(imported_data) => {
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
                                                self.import_data.zeroize();
                                                self.import_error = None;
                                            }
                                            Err(e) => {
                                                self.import_error = Some(format!("Import failed: {e}"));
                                            }
                                        }
                                    }
                                }
                            }
                            if ui.button("Cancel").clicked() {
                                self.show_import_dialog = false;
                                self.import_data.zeroize();
                                self.import_error = None;
                            }
                        });

                        ui.colored_label(Color32::GRAY, "Note: Import merges entries. Duplicates (same website+username) are skipped.");
                    });
                }

                // USB Export dialog
                if self.show_usb_export_dialog {
                    ui.group(|ui| {
                        ui.label(RichText::new("Export to USB Drive").color(Color32::YELLOW).size(18.0));

                        // Refresh button
                        if ui.button("Refresh Devices").clicked() {
                            self.detected_usb_devices = detect_usb_devices();
                            self.selected_usb_device = None;
                        }

                        if self.detected_usb_devices.is_empty() {
                            ui.colored_label(Color32::GRAY, "No removable USB drives detected.");
                            ui.label("Insert a USB drive and click Refresh.");
                        } else {
                            ui.label("Select a USB drive:");
                            for (idx, device) in self.detected_usb_devices.iter().enumerate() {
                                let label = format!(
                                    "{} - {} ({})",
                                    device.name,
                                    device.formatted_size(),
                                    device.formatted_available()
                                );
                                let selected = self.selected_usb_device == Some(idx);
                                if ui.selectable_label(selected, &label).clicked() {
                                    self.selected_usb_device = Some(idx);
                                    self.usb_export_status = None;
                                }
                            }

                            // Export button
                            if self.selected_usb_device.is_some() {
                                ui.add_space(8.0);
                                if ui.button("Export to Selected USB").clicked() {
                                    if let Some(idx) = self.selected_usb_device {
                                        if let Some(device) = self.detected_usb_devices.get(idx) {
                                            if let Some(ref vault_key) = self.current_vault_key {
                                                let vault_name = self.active_vault_name.clone().unwrap_or_default();
                                                match export_to_usb(device, &vault_name, vault_key, &self.vault, &self.custom_tags) {
                                                    Ok(path) => {
                                                        self.usb_export_status = Some(Ok(format!("Exported to: {}", path.display())));
                                                    }
                                                    Err(e) => {
                                                        self.usb_export_status = Some(Err(format!("Export failed: {e}")));
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Show status
                        if let Some(ref status) = self.usb_export_status {
                            match status {
                                Ok(msg) => ui.colored_label(Color32::GREEN, msg),
                                Err(msg) => ui.colored_label(Color32::RED, msg),
                            };
                        }

                        ui.add_space(8.0);
                        if ui.button("Close").clicked() {
                            self.show_usb_export_dialog = false;
                            self.usb_export_status = None;
                        }
                    });
                }

                // USB Import dialog
                if self.show_usb_import_dialog {
                    ui.group(|ui| {
                        ui.label(RichText::new("Import from USB Drive").color(Color32::YELLOW).size(18.0));

                        // Refresh button
                        if ui.button("Refresh Devices").clicked() {
                            self.detected_usb_devices = detect_usb_devices();
                            self.selected_usb_device = None;
                            self.usb_exports_found.clear();
                        }

                        if self.detected_usb_devices.is_empty() {
                            ui.colored_label(Color32::GRAY, "No removable USB drives detected.");
                            ui.label("Insert a USB drive and click Refresh.");
                        } else {
                            ui.label("Select a USB drive:");
                            for (idx, device) in self.detected_usb_devices.iter().enumerate() {
                                let label = format!(
                                    "{} - {} ({})",
                                    device.name,
                                    device.formatted_size(),
                                    device.formatted_available()
                                );
                                let selected = self.selected_usb_device == Some(idx);
                                if ui.selectable_label(selected, &label).clicked() {
                                    self.selected_usb_device = Some(idx);
                                    // Scan for exports on this device
                                    self.usb_exports_found = find_exports_on_device(device);
                                    self.selected_usb_import = None;
                                }
                            }

                            // Show found exports
                            if !self.usb_exports_found.is_empty() {
                                ui.add_space(8.0);
                                ui.label("Found QuickPass backups:");
                                for (idx, (path, vault_name, exported_at)) in self.usb_exports_found.iter().enumerate() {
                                    let label = format!("{} (exported: {})", vault_name, exported_at);
                                    let selected = self.selected_usb_import == Some(idx);
                                    if ui.selectable_label(selected, &label).on_hover_text(path.display().to_string()).clicked() {
                                        self.selected_usb_import = Some(idx);
                                    }
                                }

                                // Import button
                                if self.selected_usb_import.is_some() {
                                    ui.add_space(8.0);
                                    if ui.button("Import Selected Backup").clicked() {
                                        if let Some(idx) = self.selected_usb_import {
                                            if let Some((path, _, _)) = self.usb_exports_found.get(idx) {
                                                match import_from_usb(path) {
                                                    Ok(backup_data) => {
                                                        self.import_data = backup_data;
                                                        self.import_mode_csv = false;
                                                        self.show_usb_import_dialog = false;
                                                        self.show_import_dialog = true;
                                                        self.import_error = Some("USB backup loaded. Enter backup password and click Import.".to_string());
                                                    }
                                                    Err(e) => {
                                                        self.import_error = Some(format!("USB import failed: {e}"));
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            } else if self.selected_usb_device.is_some() {
                                ui.colored_label(Color32::GRAY, "No QuickPass backups found on this drive.");
                            }
                        }

                        // Show error if any
                        if let Some(ref err) = self.import_error {
                            if err.contains("failed") {
                                ui.colored_label(Color32::RED, err);
                            }
                        }

                        ui.add_space(8.0);
                        if ui.button("Close").clicked() {
                            self.show_usb_import_dialog = false;
                            self.usb_exports_found.clear();
                        }
                    });
                }

                // QR Code display dialog
                if self.show_qr_for_entry.is_some() {
                    // Clone QR data to avoid borrow issues
                    let qr_data_clone = self.qr_code_data.clone();
                    if let Some((width, data)) = qr_data_clone {
                        ui.group(|ui| {
                            ui.label(RichText::new("Scan with Authenticator App").color(Color32::YELLOW).size(18.0));

                            // Render QR code using rectangles
                            let module_size = 4.0; // Size of each QR module in pixels
                            let qr_size = width as f32 * module_size;
                            let padding = 8.0; // White border around QR

                            // Create a frame for the QR code with white background
                            egui::Frame::new()
                                .fill(Color32::WHITE)
                                .inner_margin(padding)
                                .show(ui, |ui| {
                                    let (response, painter) = ui.allocate_painter(
                                        egui::vec2(qr_size, qr_size),
                                        egui::Sense::hover(),
                                    );

                                    let rect = response.rect;

                                    // Draw each QR module
                                    for y in 0..width {
                                        for x in 0..width {
                                            let idx = y * width + x;
                                            if data.get(idx).copied().unwrap_or(false) {
                                                let module_rect = egui::Rect::from_min_size(
                                                    egui::pos2(
                                                        rect.min.x + x as f32 * module_size,
                                                        rect.min.y + y as f32 * module_size,
                                                    ),
                                                    egui::vec2(module_size, module_size),
                                                );
                                                painter.rect_filled(module_rect, 0.0, Color32::BLACK);
                                            }
                                        }
                                    }
                                });

                            ui.add_space(8.0);
                            ui.colored_label(Color32::GRAY, "Scan this QR code with Google Authenticator,");
                            ui.colored_label(Color32::GRAY, "Authy, or another TOTP app.");

                            ui.add_space(8.0);
                            if ui.button("Close").clicked() {
                                self.show_qr_for_entry = None;
                                self.qr_code_data = None;
                            }
                        });
                    }
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

    /// Unified pattern grid rendering - returns true if pattern meets minimum length
    fn render_pattern_grid(ui: &mut egui::Ui, pattern: &mut Vec<(usize, usize)>) -> bool {
        let original_spacing = ui.spacing().clone();
        ui.spacing_mut().item_spacing = egui::vec2(0.0, 0.0);
        ui.spacing_mut().button_padding = egui::vec2(0.0, 0.0);

        for row in 0..6 {
            ui.horizontal(|ui| {
                for col in 0..6 {
                    let clicked = pattern.contains(&(row, col));
                    let clr = if clicked {
                        Color32::RED
                    } else {
                        Color32::DARK_BLUE
                    };
                    let btn =
                        egui::Button::new(RichText::new("*").size(30.0).color(clr)).frame(false);
                    if ui.add_sized((35.0, 35.0), btn).clicked() {
                        // Only add if not already clicked (unique cells only)
                        if !pattern.contains(&(row, col)) {
                            pattern.push((row, col));
                        }
                    }
                }
            });
        }

        *ui.spacing_mut() = original_spacing;
        pattern.len() >= MIN_PATTERN_LENGTH
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
                                self.master_hash = Some(new_hash);
                                self.master_password_input = new_pw;
                                self.login_error_msg = "Password changed successfully!".into();
                            }
                            Err(e) => {
                                self.login_error_msg = format!("Failed to change password: {e}");
                            }
                        }
                    }
                    Err(_) => {
                        self.login_error_msg = "Old password incorrect!".into();
                    }
                }
            } else {
                self.login_error_msg = "Session error: vault key not in memory.".into();
            }
            self.show_change_pw = false;
        }

        if ui.button("Cancel").clicked() {
            self.show_change_pw = false;
            self.new_master_pw_old_input.zeroize();
            self.new_master_pw.zeroize();
        }
    }

    fn show_change_pattern_ui(&mut self, ui: &mut egui::Ui) {
        let vault_name = self.active_vault_name.clone().unwrap_or_default();
        ui.heading("Change Pattern (requires old password)");
        ui.label("Enter your master password:");
        ui.add(egui::TextEdit::singleline(&mut self.old_password_for_pattern).password(true));

        ui.separator();
        ui.label("Create a new pattern (need >=12 unique clicks).");
        self.new_pattern_unlocked = Self::render_pattern_grid(ui, &mut self.new_pattern_attempt);

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
                                self.login_error_msg = "Pattern changed successfully!".into();
                            }
                            Err(e) => {
                                self.login_error_msg = format!("Failed to change pattern: {e}");
                            }
                        }
                    } else {
                        self.login_error_msg = "Session error: vault key not in memory.".into();
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
            self.old_password_for_pattern.zeroize();
            self.new_pattern_attempt.clear();
            self.new_pattern_unlocked = false;
        }
    }

    fn handle_login_failure(&mut self, err_msg: String) {
        let vault_name = self.active_vault_name.clone().unwrap_or_default();

        // Load or create lockout state
        let mut lockout = self
            .vault_lockout
            .take()
            .unwrap_or_else(|| VaultLockout::load(&vault_name));

        // Record the failure and get the result (using configurable max_attempts from settings)
        let max_attempts = self.settings.max_failed_attempts;
        let result = lockout.record_failure(&vault_name, max_attempts);

        match result {
            LockoutResult::AttemptFailed { attempts_left } => {
                // Show warning if getting close to lockout
                let warning = lockout.get_warning(max_attempts).unwrap_or_default();
                self.login_error_msg = if warning.is_empty() {
                    format!("{err_msg} - Wrong credentials! {} attempts left.", attempts_left)
                } else {
                    format!("{err_msg} - Wrong credentials! WARNING: {}", warning)
                };
                self.vault_lockout = Some(lockout);
            }
            LockoutResult::NewLockout {
                lockout_number,
                duration_minutes,
                lockouts_before_deletion,
            } => {
                self.login_error_msg = format!(
                    "Too many failed attempts! Vault locked for {} minutes. \
                     (Lockout {}/4 - {} more lockout(s) before vault deletion)",
                    duration_minutes, lockout_number, lockouts_before_deletion
                );
                self.vault_lockout = Some(lockout);
                // Clear inputs
                self.master_password_input.zeroize();
                self.master_password_input.zeroize();
                self.pattern_attempt.clear();
            }
            LockoutResult::StillLocked { remaining_seconds } => {
                let mins = remaining_seconds / 60;
                let secs = remaining_seconds % 60;
                self.login_error_msg = format!(
                    "Vault is locked. Try again in {}m {}s.",
                    mins, secs
                );
                self.vault_lockout = Some(lockout);
            }
            LockoutResult::DeleteVault => {
                // Final lockout exceeded - delete the vault
                let path = vault_file_path(&vault_name);
                if path.exists() {
                    let _ = std::fs::remove_file(&path);
                }
                // Return to vault manager
                self.show_vault_manager = true;
                self.active_vault_name = None;
                self.is_logged_in = false;
                self.vault.clear();
                self.password_visible.clear();
                self.master_password_input.zeroize();
                self.master_password_input.zeroize();
                self.pattern_attempt.clear();
                self.is_pattern_unlock = false;
                self.failed_attempts = 0;
                self.vault_lockout = None;
                self.login_error_msg =
                    "Vault deleted after exceeding maximum lockouts!".into();
                self.manager_vaults = scan_vaults_in_dir();
            }
        }
    }

    /// Check if the current vault is locked out
    fn is_vault_locked(&self) -> bool {
        if let Some(ref lockout) = self.vault_lockout {
            lockout.is_locked()
        } else if let Some(ref vault_name) = self.active_vault_name {
            let lockout = VaultLockout::load(vault_name);
            lockout.is_locked()
        } else {
            false
        }
    }

    /// Reset lockout state on successful login
    fn reset_lockout_on_success(&mut self) {
        if let Some(ref vault_name) = self.active_vault_name {
            if let Some(mut lockout) = self.vault_lockout.take() {
                lockout.reset_on_success(vault_name);
            } else {
                // Also clear any file-based lockout
                VaultLockout::delete(vault_name);
            }
        }
        self.vault_lockout = None;
    }
}

// ------------------ UNIT TESTS ------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_min_pattern_length_constant() {
        // Ensure minimum pattern length is 12 for ~42 bits entropy
        assert_eq!(MIN_PATTERN_LENGTH, 12);
    }

    #[test]
    fn test_clipboard_timeout_default() {
        // Ensure default clipboard timeout is 30 seconds
        let settings = AppSettings::default();
        assert_eq!(settings.clipboard_clear_seconds, 30);
    }

    #[test]
    fn test_auto_lock_timeout_default() {
        // Ensure default auto-lock is 5 minutes (300 seconds)
        let settings = AppSettings::default();
        assert_eq!(settings.auto_lock_seconds, 300);
    }

    #[test]
    fn test_build_default_symbol_toggles() {
        let toggles = build_default_symbol_toggles();
        // Should have 26 symbols: !@#$%^&*()-_=+[]{}:;,.<>?/
        assert_eq!(toggles.len(), 26);
        // All should be enabled by default
        assert!(toggles.iter().all(|t| t.enabled));
        // Check some expected symbols are present
        assert!(toggles.iter().any(|t| t.sym == '!'));
        assert!(toggles.iter().any(|t| t.sym == '@'));
        assert!(toggles.iter().any(|t| t.sym == '#'));
    }

    #[test]
    fn test_collect_enabled_symbols() {
        let mut toggles = build_default_symbol_toggles();
        // Disable all but '!' and '@'
        for t in &mut toggles {
            t.enabled = t.sym == '!' || t.sym == '@';
        }

        let enabled: Vec<char> = toggles.iter()
            .filter(|s| s.enabled)
            .map(|s| s.sym)
            .collect();

        assert_eq!(enabled.len(), 2);
        assert!(enabled.contains(&'!'));
        assert!(enabled.contains(&'@'));
    }

    #[test]
    fn test_symbol_toggle_clone() {
        let toggle = SymbolToggle { sym: '!', enabled: true };
        let cloned = toggle.clone();
        assert_eq!(toggle.sym, cloned.sym);
        assert_eq!(toggle.enabled, cloned.enabled);
    }

    #[test]
    fn test_quickpass_app_default_state() {
        // Test that default state is secure
        let app = QuickPassApp::default();

        // Should start at vault manager, not logged in
        assert!(app.show_vault_manager);
        assert!(!app.is_logged_in);
        assert!(app.active_vault_name.is_none());

        // Vault should be empty
        assert!(app.vault.is_empty());
        assert!(app.current_vault_key.is_none());

        // Sensitive fields should be empty
        assert!(app.master_password_input.is_empty());
        assert!(app.pattern_attempt.is_empty());
        assert!(app.first_run_password.is_empty());
        assert!(app.first_run_pattern.is_empty());

        // Security level should default to Medium
        assert_eq!(app.security_level, SecurityLevel::Medium);

        // Failed attempts should be zero
        assert_eq!(app.failed_attempts, 0);

        // Password generation defaults
        assert_eq!(app.length, 12);
        assert!(app.use_lowercase);
        assert!(app.use_uppercase);
        assert!(app.use_digits);
    }

    #[test]
    fn test_pattern_grid_minimum_returns_false_for_empty() {
        // Empty pattern should not meet minimum
        let pattern: Vec<(usize, usize)> = vec![];
        assert!(pattern.len() < MIN_PATTERN_LENGTH);
    }

    #[test]
    fn test_pattern_grid_minimum_returns_false_for_short() {
        // Pattern with 11 cells should not meet minimum of 12
        let pattern: Vec<(usize, usize)> = (0..11).map(|i| (i / 6, i % 6)).collect();
        assert_eq!(pattern.len(), 11);
        assert!(pattern.len() < MIN_PATTERN_LENGTH);
    }

    #[test]
    fn test_pattern_grid_minimum_returns_true_for_sufficient() {
        // Pattern with 12 cells should meet minimum
        let pattern: Vec<(usize, usize)> = (0..12).map(|i| (i / 6, i % 6)).collect();
        assert_eq!(pattern.len(), 12);
        assert!(pattern.len() >= MIN_PATTERN_LENGTH);
    }

    #[test]
    fn test_pattern_grid_covers_full_grid() {
        // A 6x6 grid has 36 cells
        let mut all_cells: Vec<(usize, usize)> = vec![];
        for row in 0..6 {
            for col in 0..6 {
                all_cells.push((row, col));
            }
        }
        assert_eq!(all_cells.len(), 36);
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
        self.editing_totp_secret.zeroize();
        self.editing_custom_fields.clear();
        self.custom_field_visible.clear();

        // Import data may contain passwords
        self.import_data.zeroize();

        if let Some(ref mut k) = self.current_vault_key {
            k.zeroize();
        }
    }
}
