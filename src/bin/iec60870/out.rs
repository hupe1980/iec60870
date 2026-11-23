//! Escape untrusted diagnostic text while keeping ordinary Unicode readable.
use std::{borrow::Cow, fmt::Write};

pub fn unsafe_character(c: char) -> bool {
    c.is_control() || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

pub fn clean(text: &str) -> Cow<'_, str> {
    if !text.contains(unsafe_character) {
        return Cow::Borrowed(text);
    }
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        if unsafe_character(c) {
            let _ = write!(escaped, "{}", c.escape_unicode());
        } else {
            escaped.push(c);
        }
    }
    Cow::Owned(escaped)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn escape_untrusted_line_breaks_terminal_and_direction_controls() {
        assert!(matches!(clean("Bay café"), Cow::Borrowed(_)));
        assert_eq!(clean("a\n\x1b\u{200f}\u{061c}\u{202e}b"), r"a\u{a}\u{1b}\u{200f}\u{61c}\u{202e}b");
    }
}
