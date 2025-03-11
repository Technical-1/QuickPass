// build.rs
fn main() {
    #[cfg(target_os = "windows")]
    {
        let mut res = winres::WindowsResource::new();
        // Path to your .ico file
        res.set_icon(".github/workflows/icon.ico");
        // Compile the resource into the .exe
        res.compile().expect("Failed to embed icon!");
    }
}
