use argon2::{Algorithm, Argon2, Params, Version, password_hash::SaltString};
use once_cell::sync::Lazy;

/// Different Argon2 "cost" levels to strengthen key derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SecurityLevel {
    Low,
    Medium,
    High,
}

/// Produces an Argon2 object configured for the specified security level.
pub fn argon2_for_level(level: SecurityLevel) -> Argon2<'static> {
    let algorithm = Algorithm::Argon2id;
    let version = Version::V0x13;
    // Memory in KiB, number of iterations, parallelism
    let (mem_kib, iters, par) = match level {
        SecurityLevel::Low => (16 * 1024, 2, 2),    // ~16MB
        SecurityLevel::Medium => (32 * 1024, 3, 4), // ~32MB
        SecurityLevel::High => (64 * 1024, 4, 4),   // ~64MB
    };
    let params = Params::new(mem_kib, iters, par, Some(32)).expect("Invalid Argon2 params");
    Argon2::new(algorithm, version, params)
}

// Global salt for Argon2 hashing
pub static GLOBAL_SALT: Lazy<SaltString> =
    Lazy::new(|| SaltString::encode_b64(b"MY_APP_STATIC_SALT").unwrap());

/// Returns a reference to the global salt for password hashing.
pub fn global_salt() -> &'static SaltString {
    &GLOBAL_SALT
}