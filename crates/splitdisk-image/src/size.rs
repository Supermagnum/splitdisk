//! Parse human image sizes (`512MiB`, `1GiB`, bytes).

use crate::error::{Error, Result};

/// Parse sizes like `512MiB`, `1GiB`, `65536`, `64M`.
pub fn parse_size(s: &str) -> Result<u64> {
    let s = s.trim();
    if s.is_empty() {
        return Err(Error::InvalidParameter("empty size".into()));
    }
    let (num, mult) = if let Some(rest) = s.strip_suffix("GiB") {
        (rest, 1024u64 * 1024 * 1024)
    } else if let Some(rest) = s.strip_suffix("MiB") {
        (rest, 1024u64 * 1024)
    } else if let Some(rest) = s.strip_suffix("KiB") {
        (rest, 1024u64)
    } else if let Some(rest) = s.strip_suffix('G') {
        (rest, 1024u64 * 1024 * 1024)
    } else if let Some(rest) = s.strip_suffix('M') {
        (rest, 1024u64 * 1024)
    } else if let Some(rest) = s.strip_suffix('K') {
        (rest, 1024u64)
    } else {
        (s, 1u64)
    };
    let n: u64 = num
        .trim()
        .parse()
        .map_err(|_| Error::InvalidParameter(format!("invalid size number in '{s}'")))?;
    n.checked_mul(mult)
        .ok_or_else(|| Error::InvalidParameter("size overflow".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mib() {
        assert_eq!(parse_size("512MiB").unwrap(), 512 * 1024 * 1024);
        assert_eq!(parse_size("64M").unwrap(), 64 * 1024 * 1024);
    }
}
