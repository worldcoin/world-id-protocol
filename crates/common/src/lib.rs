pub fn greeting(name: &str) -> String {
    format!("Hello, {name}!")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greeting_formats_name() {
        assert_eq!(greeting("World"), "Hello, World!");
    }
}

