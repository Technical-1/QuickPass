use rand::Rng;

/// Generates a password with options for lowercase, uppercase, digits,
/// and a user-provided list of symbols (user_symbols).
///
/// If `use_lowercase`, `use_uppercase`, and `use_digits` are all false
/// and `user_symbols` is empty, we'll fallback to a default alphanumeric set.
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
