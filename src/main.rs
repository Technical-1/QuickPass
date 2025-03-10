mod password;

use eframe::{egui, App, Frame, NativeOptions};
use eframe::CreationContext;
use password::generate_password;

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
        ui.heading("Welcome to QuickPass");
        ui.label("Enter your master password:");

        ui.add(egui::TextEdit::singleline(&mut self.master_password_input).password(true));

        if ui.button("Login").clicked() {
            if self.master_password_input == "secret" {
                self.is_logged_in = true;
            } else {
                self.master_password_input.clear();
            }
        }
    }

    /// Mmain password-gen
    fn show_main_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("QuickPass Password Generator");

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
        ui.label("Generated Password:");
        ui.monospace(&self.generated_password);

        ui.separator();
        // A simple logout button
        if ui.button("Logout").clicked() {
            self.is_logged_in = false;
            self.master_password_input.clear();
            self.generated_password.clear();
        }
    }
}
