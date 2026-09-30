use crate::error::{ErrorCode, InstallError};
use crate::policy::DomainPolicy;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadKind {
    Manifest,
    Hap,
    HtmlPage,
}

pub fn download_host(raw: &str) -> String {
    let raw = raw.trim();
    let Some((_, rest)) = raw.split_once("://") else {
        return String::new();
    };
    let host_and_path = rest.split(['?', '#']).next().unwrap_or(rest);
    let host_port = host_and_path.split(['/', '@']).next().unwrap_or("");
    host_port.split(':').next().unwrap_or("").to_ascii_lowercase()
}

pub fn check_download_url(raw: &str, domains: &DomainPolicy, enforce: bool) -> Result<String, InstallError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(InstallError::new(ErrorCode::SourceInvalid, "链接为空"));
    }
    let Some((scheme, rest)) = raw.split_once("://") else {
        return Err(InstallError::new(ErrorCode::SourceInvalid, "链接缺少协议"));
    };
    if !scheme.eq_ignore_ascii_case("https") {
        return Err(InstallError::new(
            ErrorCode::DomainNotAllowed,
            "只允许 HTTPS",
        ));
    }
    let host_and_path = rest.split(['?', '#']).next().unwrap_or(rest);
    if host_and_path.contains('@') {
        return Err(InstallError::new(ErrorCode::DomainNotAllowed, "链接里不能带账号信息"));
    }
    let host_port = host_and_path.split('/').next().unwrap_or("");
    let host = host_port.split(':').next().unwrap_or("").to_ascii_lowercase();
    if host.is_empty() {
        return Err(InstallError::new(ErrorCode::DomainNotAllowed, "链接没有主机名"));
    }
    if enforce && domains.allowed_domains.is_empty() {
        return Err(InstallError::new(
            ErrorCode::DomainNotAllowed,
            "已开启来源校验，请先在高级设置填写允许的下载域名",
        ));
    }
    if enforce && !domains.allowed_domains.iter().any(|item| item.eq_ignore_ascii_case(&host)) {
        return Err(InstallError::new(ErrorCode::DomainNotAllowed, host));
    }
    Ok(raw.to_string())
}

pub fn classify_payload(content_type: &str, body_prefix: &[u8]) -> PayloadKind {
    let content_type = content_type.to_ascii_lowercase();
    if content_type.contains("text/html") || body_prefix.starts_with(b"<") || body_prefix.starts_with(b"<!DOCTYPE")
    {
        return PayloadKind::HtmlPage;
    }
    if content_type.contains("application/json") || body_prefix.starts_with(b"{") {
        return PayloadKind::Manifest;
    }
    PayloadKind::Hap
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domains(items: &[&str]) -> DomainPolicy {
        DomainPolicy {
            schema_version: 1,
            https_only: true,
            allowed_domains: items.iter().map(|item| item.to_string()).collect(),
        }
    }

    #[test]
    fn rejects_non_https_and_unknown_host() {
        let policy = domains(&["download.example"]);
        assert_eq!(
            check_download_url("http://download.example/a.hap", &policy, true)
                .unwrap_err()
                .code,
            ErrorCode::DomainNotAllowed
        );
        assert_eq!(
            check_download_url("file:///tmp/a.hap", &policy, true).unwrap_err().code,
            ErrorCode::DomainNotAllowed
        );
        assert_eq!(
            check_download_url("https://evil.example/a.hap", &policy, true)
                .unwrap_err()
                .code,
            ErrorCode::DomainNotAllowed
        );
        assert_eq!(
            check_download_url("https://evil.example/a.hap", &policy, false).unwrap(),
            "https://evil.example/a.hap"
        );
        assert_eq!(download_host("https://Apps.Example/a.hap?token=1"), "apps.example");
    }

    #[test]
    fn classifies_html_manifest_and_hap() {
        assert_eq!(classify_payload("text/html", b"<html>"), PayloadKind::HtmlPage);
        assert_eq!(classify_payload("application/json", b"{\"schemaVersion\":1}"), PayloadKind::Manifest);
        assert_eq!(classify_payload("application/octet-stream", b"PK\x03\x04"), PayloadKind::Hap);
    }
}
