fn key() -> String {
    std::env::var("ENCRYPTION_KEY").expect("ENCRYPTION_KEY is required")
}
