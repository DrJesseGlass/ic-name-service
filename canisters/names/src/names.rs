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

pub const MAX_TAGS: usize = 16;

/// The "tags" text record: comma separated, no spaces, each tag in the
/// segment grammar, at most 16, no duplicates. Returns the tags.
pub fn check_tags(value: &str) -> Result<Vec<String>, String> {
    let mut tags: Vec<String> = Vec::new();
    for tag in value.split(',') {
        check_segment("tag", tag)?;
        if tags.iter().any(|t| t == tag) {
            return Err(format!("duplicate tag '{tag}'"));
        }
        tags.push(tag.to_string());
    }
    if tags.len() > MAX_TAGS {
        return Err(format!("at most {MAX_TAGS} tags"));
    }
    Ok(tags)
}

/// Lowercase hex of exactly one of the given byte lengths (a git commit is
/// 20 bytes, a module hash 32).
pub fn check_hex(what: &str, s: &str, byte_lens: &[usize]) -> Result<(), String> {
    if !s.len().is_multiple_of(2) || !byte_lens.contains(&(s.len() / 2)) {
        let want: Vec<String> = byte_lens.iter().map(|n| (n * 2).to_string()).collect();
        return Err(format!(
            "{what} must be {} hex characters",
            want.join(" or ")
        ));
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(format!("{what} must be lowercase hex"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags() {
        assert_eq!(check_tags("git,deploy").unwrap(), vec!["git", "deploy"]);
        assert_eq!(check_tags("git").unwrap(), vec!["git"]);
        assert!(check_tags("").is_err());
        assert!(check_tags("git, deploy").is_err());
        assert!(check_tags("git,git").is_err());
        assert!(check_tags("Git").is_err());
        assert!(check_tags(
            &(0..16)
                .map(|i| format!("t{i}"))
                .collect::<Vec<_>>()
                .join(",")
        )
        .is_ok());
        assert!(check_tags(
            &(0..17)
                .map(|i| format!("t{i}"))
                .collect::<Vec<_>>()
                .join(",")
        )
        .is_err());
    }

    #[test]
    fn hex() {
        assert!(check_hex("commit", &"ab".repeat(20), &[20]).is_ok());
        assert!(check_hex("hash", &"ab".repeat(32), &[20, 32]).is_ok());
        assert!(check_hex("hash", &"AB".repeat(32), &[32]).is_err());
        assert!(check_hex("hash", &"ab".repeat(31), &[32]).is_err());
        assert!(check_hex("hash", "abc", &[32]).is_err());
    }

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
