mod password;

fn main() {
    let pwd = password::generate_password(
        12,
        true,
        true,
        true,
        true,
    );

    println!("Generated Password: {}", pwd);
}
