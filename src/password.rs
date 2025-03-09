use rand::Rng;

pub fn generate_password(
    length: usize,
    use_lowercase: bool,
    use_uppercase: bool,
    use_digits: bool,
    use_symbols: bool,
) -> String {
    let mut charset = String::new();

    if use_lowercase {
        charset.push_str("abcdefghijklmnopqrstuvwxyz");
    }
    if use_uppercase {
        charset.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }
    if use_digits {
        charset.push_str("0123456789");
    }
    if use_symbols {
        charset.push_str("!@#$%^&*()-_=+[]{};:,.<>?");
    }

    if charset.is_empty() {
        charset.push_str("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
    }

    let chars: Vec<char> = charset.chars().collect();

    let mut rng = rand::rng();

    (0..length)
        .map(|_| {
            let idx = rng.random_range(0..chars.len());
            chars[idx]
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_password_min_length() {
        let pwd = generate_password(1, true, false, false, false);
        assert_eq!(pwd.len(), 1);
    }

    #[test]
    fn test_generate_password_all_options() {
        let pwd = generate_password(16, true, true, true, true);
        assert_eq!(pwd.len(), 16);
    }

    #[test]
    fn test_generate_password_no_options() {
        let pwd = generate_password(10, false, false, false, false);
        assert_eq!(pwd.len(), 10);
    }
}
