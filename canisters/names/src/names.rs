//! Name syntax. A scoped name is `<handle>/<label>` (DESIGN.md section 4).
//!
//! Handles and labels share one grammar: 1 to 63 bytes of lowercase ASCII
//! letters, digits and hyphens, starting and ending with a letter or digit.
//! That is the DNS label grammar, so every scoped name can later become a
//! path segment or a DNS label without escaping (section 6).

pub const MAX_SEGMENT: usize = 63;
pub const MAX_TEXT_KEY: usize = 32;
pub const MAX_TEXT_VALUE: usize = 512;
pub const MAX_TEXT_RECORDS: usize = 32;

/// Validate one segment (a handle or a label).
pub fn check_segment(what: &str, s: &str) -> Result<(), String> {
    if s.is_empty() {
        return Err(format!("{what} is empty"));
    }
    if s.len() > MAX_SEGMENT {
        return Err(format!("{what} longer than {MAX_SEGMENT} bytes"));
    }
    let bytes = s.as_bytes();
    if !bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
    {
        return Err(format!("{what} may only contain a-z, 0-9 and '-'"));
    }
    if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
        return Err(format!("{what} may not start or end with '-'"));
    }
    Ok(())
}

/// Split and validate a scoped name into (handle, label).
pub fn split(name: &str) -> Result<(&str, &str), String> {
    let (handle, label) = name
        .split_once('/')
        .ok_or_else(|| "name must be <handle>/<label>".to_string())?;
    if label.contains('/') {
        return Err("name must have exactly one '/'".to_string());
    }
    check_segment("handle", handle)?;
    check_segment("label", label)?;
    Ok((handle, label))
}

/// Text record keys: 1 to 32 bytes of lowercase letters, digits, '_', '.'
/// and '-'.
pub fn check_text_key(key: &str) -> Result<(), String> {
    if key.is_empty() || key.len() > MAX_TEXT_KEY {
        return Err(format!("text key must be 1 to {MAX_TEXT_KEY} bytes"));
    }
    let ok = key.bytes().all(|b| {
        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.' || b == b'-'
    });
    if !ok {
        return Err("text key may only contain a-z, 0-9, '_', '.' and '-'".to_string());
    }
    Ok(())
}

/// Text record values: at most 512 bytes, no control characters. The
/// certified canonical form (store.rs) is line-oriented, so a newline in a
/// value would let one record forge the shape of another.
pub fn check_text_value(value: &str) -> Result<(), String> {
    if value.len() > MAX_TEXT_VALUE {
        return Err(format!("text value longer than {MAX_TEXT_VALUE} bytes"));
    }
    if value.chars().any(|c| c.is_control()) {
        return Err("text value may not contain control characters".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segments() {
        assert!(check_segment("handle", "alice").is_ok());
        assert!(check_segment("handle", "ic-git").is_ok());
        assert!(check_segment("handle", "a").is_ok());
        assert!(check_segment("handle", "").is_err());
        assert!(check_segment("handle", "-a").is_err());
        assert!(check_segment("handle", "a-").is_err());
        assert!(check_segment("handle", "Alice").is_err());
        assert!(check_segment("handle", "a_b").is_err());
        assert!(check_segment("handle", &"a".repeat(64)).is_err());
        assert!(check_segment("handle", &"a".repeat(63)).is_ok());
    }

    #[test]
    fn scoped_names() {
        assert_eq!(split("alice/ic-git").unwrap(), ("alice", "ic-git"));
        assert!(split("ic-git").is_err());
        assert!(split("alice/").is_err());
        assert!(split("/ic-git").is_err());
        assert!(split("alice/ic/git").is_err());
    }

    #[test]
    fn text() {
        assert!(check_text_key("description").is_ok());
        assert!(check_text_key("module.hash").is_ok());
        assert!(check_text_key("").is_err());
        assert!(check_text_key("Desc").is_err());
        assert!(check_text_value("a git remote on a canister").is_ok());
        assert!(check_text_value("two\nlines").is_err());
        assert!(check_text_value(&"x".repeat(513)).is_err());
    }
}
