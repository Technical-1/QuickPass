use argon2::{Algorithm, Argon2, Params, Version, password_hash::SaltString};
use argon2::password_hash::rand_core::OsRng;

/// Different Argon2 "cost" levels to strengthen key derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SecurityLevel {
    Low,
    Medium,
    High,
}

/// Produces an Argon2 object configured for the specified security level.
///
/// All levels meet or exceed OWASP Argon2id recommendations:
/// - Minimum: 19 MiB memory, 2 iterations, 1 parallelism
///
/// Parameters chosen to balance security and usability on modern hardware.
pub fn argon2_for_level(level: SecurityLevel) -> Argon2<'static> {
    let algorithm = Algorithm::Argon2id;
    let version = Version::V0x13;
    // Memory in KiB, number of iterations, parallelism
    // OWASP minimum: 19 MiB, 2 iterations - all levels exceed this
    let (mem_kib, iters, par) = match level {
        SecurityLevel::Low => (19 * 1024, 3, 2),    // ~19MB, 3 iterations - Fast unlock
        SecurityLevel::Medium => (47 * 1024, 3, 4), // ~47MB, 3 iterations - Balanced
        SecurityLevel::High => (64 * 1024, 4, 4),   // ~64MB, 4 iterations - Maximum security
    };
    let params = Params::new(mem_kib, iters, par, Some(32)).expect("Invalid Argon2 params");
    Argon2::new(algorithm, version, params)
}

/// Generates a cryptographically secure random salt for a new vault.
/// Returns a SaltString that can be used with Argon2 password hashing.
pub fn generate_random_salt() -> SaltString {
    SaltString::generate(&mut OsRng)
}

// ------------------ TESTS ------------------
#[cfg(test)]
mod tests {
    use super::*;
    use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier};

    #[test]
    fn test_security_levels_exist() {
        // Verify all security levels can be created
        let _low = SecurityLevel::Low;
        let _medium = SecurityLevel::Medium;
        let _high = SecurityLevel::High;
    }

    #[test]
    fn test_argon2_for_level_low() {
        let argon2 = argon2_for_level(SecurityLevel::Low);
        let salt = generate_random_salt();
        let hash = argon2.hash_password(b"testpassword", &salt);
        assert!(hash.is_ok());
    }

    #[test]
    fn test_argon2_for_level_medium() {
        let argon2 = argon2_for_level(SecurityLevel::Medium);
        let salt = generate_random_salt();
        let hash = argon2.hash_password(b"testpassword", &salt);
        assert!(hash.is_ok());
    }

    #[test]
    fn test_argon2_for_level_high() {
        let argon2 = argon2_for_level(SecurityLevel::High);
        let salt = generate_random_salt();
        let hash = argon2.hash_password(b"testpassword", &salt);
        assert!(hash.is_ok());
    }

    #[test]
    fn test_password_hash_verification() {
        let password = b"SecureP@ssw0rd!";
        let argon2 = argon2_for_level(SecurityLevel::Medium);
        let salt = generate_random_salt();

        // Hash the password
        let hash = argon2.hash_password(password, &salt).unwrap();
        let hash_str = hash.to_string();

        // Verify the password matches
        let parsed_hash = PasswordHash::new(&hash_str).unwrap();
        assert!(argon2.verify_password(password, &parsed_hash).is_ok());
    }

    #[test]
    fn test_wrong_password_fails_verification() {
        let password = b"CorrectPassword1";
        let wrong_password = b"WrongPassword1";
        let argon2 = argon2_for_level(SecurityLevel::Medium);
        let salt = generate_random_salt();

        // Hash the correct password
        let hash = argon2.hash_password(password, &salt).unwrap();
        let hash_str = hash.to_string();

        // Verify wrong password fails
        let parsed_hash = PasswordHash::new(&hash_str).unwrap();
        assert!(argon2.verify_password(wrong_password, &parsed_hash).is_err());
    }

    #[test]
    fn test_generate_random_salt_uniqueness() {
        // Generate multiple salts and ensure they're different
        let salt1 = generate_random_salt();
        let salt2 = generate_random_salt();
        let salt3 = generate_random_salt();

        assert_ne!(salt1.to_string(), salt2.to_string());
        assert_ne!(salt2.to_string(), salt3.to_string());
        assert_ne!(salt1.to_string(), salt3.to_string());
    }

    #[test]
    fn test_different_security_levels_produce_different_hashes() {
        let password = b"TestPassword123";

        let salt = generate_random_salt();
        let argon2_low = argon2_for_level(SecurityLevel::Low);
        let argon2_high = argon2_for_level(SecurityLevel::High);

        let hash_low = argon2_low.hash_password(password, &salt).unwrap().to_string();
        let hash_high = argon2_high.hash_password(password, &salt).unwrap().to_string();

        // The hashes should be different due to different params
        assert_ne!(hash_low, hash_high);
    }

    #[test]
    fn test_security_level_serialization() {
        // Test that SecurityLevel can be serialized/deserialized
        let level = SecurityLevel::Medium;
        let json = serde_json::to_string(&level).unwrap();
        let restored: SecurityLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(level, restored);
    }
}
