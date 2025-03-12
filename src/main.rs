use eframe::NativeOptions;

mod app;
mod manager;
mod password;
mod security;
mod vault;

fn main() -> eframe::Result<()> {
    let native_options = NativeOptions::default();
    eframe::run_native(
        "QuickPass",
        native_options,
        Box::new(|_cc| Ok(Box::new(app::QuickPassApp::default()))),
    )
}
