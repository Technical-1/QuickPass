mod password;

use eframe::{egui, App, Frame, NativeOptions};
use eframe::CreationContext;
use egui::{Color32, RichText};

use password::generate_password;

#[derive(Clone)]
struct VaultEntry {
    website: String,
    username: String,
    password: String,
}

fn main() -> eframe::Result<()> {
    let native_options = NativeOptions::default();
    eframe::run_native(
        "QuickPass",
        native_options,
        Box::new(|_cc: &CreationContext| {
            // Keep OK wrapper if your eframe version expects a Result
            Ok(Box::new(QuickPassApp::default()))
        }),
    )
}

/// Main application state
struct QuickPassApp {
    // Login state
    master_password_input: String,
    is_logged_in: bool,

    // Password generation options
    length: usize,
    use_lowercase: bool,
    use_uppercase: bool,
    use_digits: bool,
    use_symbols: bool,

    // Generated password
    generated_password: String,

    // Pattern lock fields
    pattern_attempt: Vec<(usize, usize)>,
    is_pattern_unlock: bool,

    // Vault
    vault: Vec<VaultEntry>,
    new_website: String,
    new_username: String,
}

impl Default for QuickPassApp {
    fn default() -> Self {
        Self {
            master_password_input: String::new(),
            is_logged_in: false,
            length: 12,
            use_lowercase: true,
            use_uppercase: true,
            use_digits: true,
            use_symbols: true,
            generated_password: String::new(),

            // Pattern lock defaults
            pattern_attempt: Vec::new(),
            is_pattern_unlock: false,

            // Vault defaults
            vault: Vec::new(),
            new_website: String::new(),
            new_username: String::new(),
        }
    }
}

impl App for QuickPassApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            if self.is_logged_in {
                self.show_main_ui(ui);
            } else {
                self.show_login_ui(ui);
            }
        });
    }
}

impl QuickPassApp {
    /// Login screen
    fn show_login_ui(&mut self, ui: &mut egui::Ui) {
        // Heading
        ui.heading(RichText::new("Welcome to QuickPass").size(30.0).color(Color32::GRAY));

        // Label
        ui.label(RichText::new("Enter your master password:").size(20.0).color(Color32::GRAY));

        ui.add(egui::TextEdit::singleline(&mut self.master_password_input).password(true));

        if ui.button("Login").clicked() {
            if self.master_password_input == "secret" {
                self.is_logged_in = true;
            } else {
                self.master_password_input.clear();
            }
        }

        // Pattern lock circles under the master password
        ui.separator();
        ui.label(
            RichText::new("Pattern Lock").size(20.0).color(Color32::GRAY),
        );

        // Show the pattern lock grid
        self.show_pattern_lock(ui);

        // If they've completed the pattern, show an option to enter
        if self.is_pattern_unlock {
            ui.colored_label(Color32::GREEN, "Pattern unlocked!");
            if ui.button("Enter with Pattern").clicked() {
                self.is_logged_in = true;
            }
        } else {
            ui.colored_label(Color32::RED, "Pattern locked");
        }

        // Reset attempt
        if ui.button("Reset Pattern").clicked() {
            self.pattern_attempt.clear();
            self.is_pattern_unlock = false;
        }
    }

    /// Pattern lock that looks like a 3x3 grid of circles
    fn show_pattern_lock(&mut self, ui: &mut egui::Ui) {
        // Hardcoded "correct" pattern for demo
        let correct_pattern: Vec<(usize, usize)> = vec![(0, 0), (0, 1), (1, 1), (2, 2)];

        // We'll do a 3x3 grid of clickable "circles"
        for row in 0..3 {
            ui.horizontal(|ui| {
                for col in 0..3 {
                    // CHECK IF (row, col) IS ALREADY CLICKED:
                    let already_clicked = self.pattern_attempt.contains(&(row, col));

                    // If clicked, color circle differently (e.g., RED); else dark blue
                    let circle_color = if already_clicked {
                        Color32::RED
                    } else {
                        Color32::DARK_BLUE
                    };

                    let circle_label = egui::Button::new(
                        RichText::new("●")
                            .size(40.0)
                            .color(circle_color),
                    )
                    .frame(false);

                    if ui.add(circle_label).clicked() {
                        // Record this attempt
                        self.pattern_attempt.push((row, col));

                        // Check if user completed correct pattern
                        if self.pattern_attempt == correct_pattern {
                            self.is_pattern_unlock = true;
                        } else if self.pattern_attempt.len() >= correct_pattern.len() {
                            // If they overshoot, reset
                            self.pattern_attempt.clear();
                        }
                    }
                }
            });
        }
    }

    /// Main password generation
    fn show_main_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading(RichText::new("QuickPass Password Value").size(30.0).color(Color32::GRAY));

        // Slider for length
        ui.horizontal(|ui| {
            ui.label("Length:");
            ui.add(egui::Slider::new(&mut self.length, 1..=128).text("characters"));
        });

        // Toggles for character sets
        ui.checkbox(&mut self.use_lowercase, "Lowercase (a-z)");
        ui.checkbox(&mut self.use_uppercase, "Uppercase (A-Z)");
        ui.checkbox(&mut self.use_digits, "Digits (0-9)");
        ui.checkbox(&mut self.use_symbols, "Symbols (!@#...)");

        // Generate button
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
        ui.label(RichText::new("Generated Password:").size(16.0));
        ui.monospace(&self.generated_password);

        ui.separator();
        // Show vault after we generate or at any time
        self.show_vault_ui(ui);

        ui.separator();
        // A simple logout button
        if ui.button("Logout").clicked() {
            self.is_logged_in = false;
            self.master_password_input.clear();
            self.generated_password.clear();
            self.pattern_attempt.clear();
            self.is_pattern_unlock = false;
        }
    }

    /// Vault UI (minimal approach)
    fn show_vault_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading(RichText::new("Vault").size(20.0).color(Color32::DARK_GRAY));

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

                // Clear fields
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
}
