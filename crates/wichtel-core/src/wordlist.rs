//! Fixed word list for the fingerprint (Spec §5): 256 German nouns, ASCII, one per line.

/// Raw list; line k is the word for byte value k.
pub const RAW: &str = include_str!("../data/wortliste.txt");

/// Word for byte value `b`.
pub fn word(b: u8) -> &'static str {
    RAW.lines().nth(b as usize).unwrap_or("?")
}

#[cfg(test)]
mod tests {
    #[test]
    fn has_256_unique_words() {
        let words: Vec<&str> = super::RAW.lines().collect();
        assert_eq!(words.len(), 256);
        let mut lower: Vec<String> = words.iter().map(|w| w.to_lowercase()).collect();
        lower.sort();
        lower.dedup();
        assert_eq!(lower.len(), 256);
    }
}
