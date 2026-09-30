use sha2::{Digest, Sha256};

pub fn digest_id(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

pub fn short_hash(sha256: &str) -> String {
    sha256.chars().take(12).collect()
}

pub fn redact_text(text: &str, secrets: &[&str]) -> String {
    let mut output = String::new();
    for (index, line) in text.lines().enumerate() {
        if index > 0 {
            output.push('\n');
        }
        output.push_str(&redact_line(line, secrets));
    }
    if text.ends_with('\n') {
        output.push('\n');
    }
    const LIMIT: usize = 4000;
    if output.chars().count() > LIMIT {
        output = output.chars().take(LIMIT).collect();
        output.push_str("…");
    }
    output
}

fn redact_line(line: &str, secrets: &[&str]) -> String {
    let mut redacted = line.to_string();
    for secret in secrets {
        if secret.len() >= 4 {
            redacted = redacted.replace(secret, "[redacted]");
        }
    }
    let mut output = String::new();
    let bytes = redacted.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index..].starts_with(b"https://") || bytes[index..].starts_with(b"http://") {
            let start = index;
            index += if bytes[index..].starts_with(b"https://") { 8 } else { 7 };
            while index < bytes.len() && !bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            output.push_str(&strip_url_query(&redacted[start..index]));
        } else {
            let ch = redacted[index..].chars().next().unwrap();
            output.push(ch);
            index += ch.len_utf8();
        }
    }
    output
}

fn strip_url_query(url: &str) -> String {
    url.split(['?', '#']).next().unwrap_or(url).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_signed_query_and_device_id() {
        let text = "download https://pkg.example/a.hap?signature=secret device ABC12345";
        let redacted = redact_text(text, &["ABC12345"]);
        assert!(!redacted.contains("signature=secret"));
        assert!(redacted.contains("https://pkg.example/a.hap"));
        assert!(!redacted.contains("ABC12345"));
        assert!(redacted.contains("[redacted]"));
    }
}
