mod app;
mod manager;
mod password;
mod security;
mod vault;
use eframe::egui::{self};

fn main() {
    // Define the desired window constraints
    let max_size = [1000.0, 900.0];
    let min_size = [780.0, 800.0]; // for example, a minimum of 320x240
    let initial_size = [780.0, 800.0]; // start in between min and max for demonstration

    // Configure eframe native window options with size constraints
    let native_options = eframe::NativeOptions {
        // Use the viewport builder to set initial, min, and max inner size
        viewport: egui::ViewportBuilder::default()
            .with_inner_size(initial_size)
            .with_min_inner_size(min_size)
            .with_max_inner_size(max_size)
            .with_resizable(true), // allow resizing within min/max bounds
        ..Default::default()
    };

    // Run the eframe application with these options
    eframe::run_native(
        "QuickPass",
        native_options,
        Box::new(|_cc| Ok(Box::new(app::QuickPassApp::default()))),
    )
    .expect("Failed to launch eframe application");
}
