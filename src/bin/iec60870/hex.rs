//! Bounded hexadecimal input for the offline decoder.
use std::io::{self, BufRead, Read};

pub const LIMIT: usize = 64 * 1024;

/// Retain at most the allowed text plus CRLF. Keep the oversized prefix as an
/// error sentinel for the parser and drain the rest before the next call.
pub fn read_line(reader: &mut impl BufRead, line: &mut Vec<u8>) -> io::Result<bool> {
    line.clear();
    let n = reader.take((LIMIT + 2) as u64).read_until(b'\n', line)?;
    if line.last() == Some(&b'\n') {
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
    } else if n == LIMIT + 2 {
        reader.skip_until(b'\n')?;
    }
    Ok(n != 0)
}

pub fn parse(line: &[u8]) -> Result<Vec<u8>, String> {
    if line.len() > LIMIT {
        return Err("hex input exceeds 64 KiB".into());
    }
    let mut bytes = Vec::new();
    let input = line.split(|b| *b == b'#').next().unwrap_or_default();
    let mut offset = 0;
    for token in input.split(|b| b.is_ascii_whitespace() || matches!(b, b':' | b'-' | b',')) {
        let digits = token.strip_prefix(b"0x").or_else(|| token.strip_prefix(b"0X")).unwrap_or(token);
        if digits.is_empty() && !token.is_empty() {
            return Err(format!("missing digits after hex prefix at column {}", offset + 1));
        }
        let start = offset + token.len() - digits.len();
        let mut high = None;
        for (i, &b) in digits.iter().enumerate() {
            let digit = char::from(b).to_digit(16).ok_or_else(|| format!("invalid hex byte {} at column {}", b.escape_ascii(), start + i + 1))? as u8;
            if let Some(hi) = high.take() {
                bytes.push(hi << 4 | digit);
            } else {
                high = Some(digit);
            }
        }
        if high.is_some() {
            return Err(format!("unpaired hex digit at column {}", start + digits.len()));
        }
        offset += token.len() + 1;
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pasted_notation_and_error_columns() {
        assert_eq!(parse(b"0x68 : 0X0e-0a,Ff # note"), Ok(vec![0x68, 14, 10, 255]));
        assert_eq!(parse(b"0x68:0xf"), Err("unpaired hex digit at column 8".into()));
        assert_eq!(parse(b"68:0x"), Err("missing digits after hex prefix at column 4".into()));
        assert!(matches!(parse(b"68:\x1b"),Err(e) if e.contains("column 4")));
    }
}
