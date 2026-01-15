use rand::Rng;

/// Validates master password strength requirements.
/// Returns Ok(()) if valid, or Err with a list of requirements not met.
pub fn validate_master_password(password: &str) -> Result<(), Vec<&'static str>> {
    let mut errors = Vec::new();

    if password.len() < 8 {
        errors.push("Must be at least 8 characters");
    }

    let has_lowercase = password.chars().any(|c| c.is_ascii_lowercase());
    let has_uppercase = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());

    if !has_lowercase {
        errors.push("Must contain a lowercase letter");
    }
    if !has_uppercase {
        errors.push("Must contain an uppercase letter");
    }
    if !has_digit {
        errors.push("Must contain a digit");
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Generates a password with options for lowercase, uppercase, digits,
/// and a user-provided list of symbols (user_symbols).
///
/// If `use_lowercase`, `use_uppercase`, and `use_digits` are all false
/// and `user_symbols` is empty, we'll fallback to a default alphanumeric set.
/// A rough approximation of password entropy (in bits).
/// We'll treat each character set used as a separate factor, or fallback to length-based approach.
pub fn estimate_entropy(pwd: &str) -> f64 {
    if pwd.is_empty() {
        return 0.0;
    }
    // We'll do a naive approach:
    // 1) Identify which categories are present: lowercase, uppercase, digits, symbols
    // 2) Sum up their possible char sets
    // 3) bits = length * log2(character_set_size).
    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_symbol = false;

    for c in pwd.chars() {
        if c.is_ascii_lowercase() {
            has_lower = true;
        } else if c.is_ascii_uppercase() {
            has_upper = true;
        } else if c.is_ascii_digit() {
            has_digit = true;
        } else {
            has_symbol = true;
        }
    }

    let mut char_space = 0;
    if has_lower {
        char_space += 26;
    }
    if has_upper {
        char_space += 26;
    }
    if has_digit {
        char_space += 10;
    }
    if has_symbol {
        // We'll guess a ~30 typical symbol set
        char_space += 30;
    }
    // If we didn't identify a category, fallback to the "unique chars in the password" approach
    if char_space == 0 {
        // fallback to unique chars
        use std::collections::HashSet;
        let unique: HashSet<char> = pwd.chars().collect();
        char_space = unique.len();
        // if it is still 0 or 1, fallback to 1 => 1 bit or so
        if char_space < 2 {
            char_space = 2;
        }
    }

    let length = pwd.chars().count() as f64;
    let space = char_space as f64;
    // entropy in bits = length * log2(space)
    length * space.log2()
}

pub fn generate_password(
    length: usize,
    use_lowercase: bool,
    use_uppercase: bool,
    use_digits: bool,
    user_symbols: &[char],
) -> String {
    let mut charset = String::new();

    // Add optional character sets
    if use_lowercase {
        charset.push_str("abcdefghijklmnopqrstuvwxyz");
    }
    if use_uppercase {
        charset.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }
    if use_digits {
        charset.push_str("0123456789");
    }

    // Add user-provided symbols
    if !user_symbols.is_empty() {
        for &sym in user_symbols {
            charset.push(sym);
        }
    }

    // Fallback if user disabled everything
    if charset.is_empty() {
        charset.push_str("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
    }

    // Convert to vector for indexing
    let chars: Vec<char> = charset.chars().collect();

    // Use rand::rng() in rand 0.9.x
    let mut rng = rand::rng();

    (0..length)
        .map(|_| {
            // We can now call gen_range because we imported Rng
            let idx = rng.random_range(0..chars.len());
            chars[idx]
        })
        .collect()
}

// ------------------ TESTS ------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_password_min_length() {
        let pwd = generate_password(1, true, false, false, &[]);
        assert_eq!(pwd.len(), 1);
    }

    #[test]
    fn test_generate_password_all_options_no_symbols() {
        let pwd = generate_password(16, true, true, true, &[]);
        assert_eq!(pwd.len(), 16);
    }

    #[test]
    fn test_generate_password_with_symbols() {
        let pwd = generate_password(10, false, false, false, &['!', '@', '#']);
        assert_eq!(pwd.len(), 10);
        // We won't test exact content, just length
    }

    #[test]
    fn test_generate_password_empty_fallback() {
        // No booleans set, empty symbols => fallback
        let pwd = generate_password(10, false, false, false, &[]);
        assert_eq!(pwd.len(), 10);
        assert!(!pwd.is_empty());
    }
}
