use directories::ProjectDirs;
use std::fs;
use std::path::PathBuf;

/// Returns the base data directory for storing QuickPass vault files.
pub fn data_dir() -> PathBuf {
    if let Some(proj_dirs) = ProjectDirs::from("com", "KANFER", "QuickPass") {
        let dir = proj_dirs.data_dir();
        let _ = fs::create_dir_all(dir);
        dir.to_path_buf()
    } else {
        PathBuf::from(".")
    }
}

/// Builds the full vault file path for a given vault name.
pub fn vault_file_path(vault_name: &str) -> PathBuf {
    data_dir().join(format!("encrypted_vault_{vault_name}.json"))
}

/// Scans the data directory to find existing vault names.
pub fn scan_vaults_in_dir() -> Vec<String> {
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
