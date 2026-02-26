fn main() {
    println!("Hello, world!");
    println!("Architecture: {}", std::env::consts::ARCH);
    println!("OS: {}", std::env::consts::OS);
}
