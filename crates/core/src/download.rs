use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::{ErrorCode, InstallError};
use crate::policy::DomainPolicy;
use crate::source::{check_download_url, classify_payload, PayloadKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestDoc {
    pub task_id: String,
    pub file_name: String,
    pub file_size: u64,
    pub sha256: String,
    pub bundle_name: String,
    pub version_name: String,
    pub version_code: u32,
    pub download_url: String,
    pub expires_at: Option<String>,
}

#[derive(Debug)]
pub enum Downloaded {
    Hap { bytes_path: PathBuf, file_name: String, source_url: String },
    Manifest(ManifestDoc),
    HtmlPage { url: String },
}

pub fn download_url(url: &str, domains: &DomainPolicy, dest: &Path, enforce: bool) -> Result<Downloaded, InstallError> {
    let url = check_download_url(url, domains, enforce)?;
    let response = fetch(&url, domains, enforce)?;
    match classify_payload(&response.content_type, &response.body) {
        PayloadKind::HtmlPage => Ok(Downloaded::HtmlPage { url }),
        PayloadKind::Manifest => {
            let manifest = parse_manifest(&response.body)?;
            if let Some(expires_at) = &manifest.expires_at {
                if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(expires_at) {
                    if expiry < chrono::Utc::now() {
                        return Err(InstallError::new(ErrorCode::LinkExpired, ""));
                    }
                }
            }
            if !manifest.artifact_is_hap() {
                return Err(InstallError::new(ErrorCode::SourceInvalid, "manifest 不是 HAP"));
            }
            Ok(Downloaded::Manifest(manifest))
        }
        PayloadKind::Hap => {
            if response.file_name.ends_with(".app") {
                return Err(InstallError::new(ErrorCode::SourceInvalid, "不接受 APP Pack"));
            }
            fs::write(dest, &response.body).map_err(|err| InstallError::new(ErrorCode::DownloadFailed, err.to_string()))?;
            let file_name = if response.file_name.ends_with(".hap") {
                response.file_name
            } else {
                "artifact.hap".to_string()
            };
            Ok(Downloaded::Hap {
                bytes_path: dest.to_path_buf(),
                file_name,
                source_url: response.final_url,
            })
        }
    }
}

impl ManifestDoc {
    fn artifact_is_hap(&self) -> bool {
        true
    }
}

struct RawResponse {
    content_type: String,
    file_name: String,
    final_url: String,
    body: Vec<u8>,
}

fn fetch(start: &str, domains: &DomainPolicy, enforce: bool) -> Result<RawResponse, InstallError> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(15))
        .timeout_read(Duration::from_secs(120))
        .redirects(0)
        .build();
    let mut url = start.to_string();
    for _ in 0..4 {
        let response = agent
            .get(&url)
            .set("User-Agent", "harmony-hap-installer")
            .call();
        let response = match response {
            Ok(response) => response,
            Err(ureq::Error::Status(status, response)) => {
                if matches!(status, 301 | 302 | 303 | 307 | 308) {
                    let location = response.header("location").unwrap_or("").to_string();
                    url = resolve_location(&url, &location);
                    url = check_download_url(&url, domains, enforce)?;
                    continue;
                }
                if status == 410 || status == 401 || status == 403 {
                    let mut body = String::new();
                    let _ = response.into_reader().take(512).read_to_string(&mut body);
                    if status == 410 || body.to_ascii_lowercase().contains("expire") {
                        return Err(InstallError::new(ErrorCode::LinkExpired, ""));
                    }
                }
                return Err(InstallError::new(ErrorCode::DownloadFailed, format!("HTTP {status}")));
            }
            Err(err) => return Err(InstallError::new(ErrorCode::DownloadFailed, err.to_string())),
        };
        let content_type = response.header("content-type").unwrap_or("").to_string();
        let disposition = response.header("content-disposition").unwrap_or("").to_string();
        let mut body = Vec::new();
        response
            .into_reader()
            .take(1024 * 1024 * 1024)
            .read_to_end(&mut body)
            .map_err(|err| InstallError::new(ErrorCode::DownloadFailed, err.to_string()))?;
        return Ok(RawResponse {
            content_type,
            file_name: file_name_from_disposition(&disposition).unwrap_or_else(|| file_name_from_url(&url)),
            final_url: url,
            body,
        });
    }
    Err(InstallError::new(ErrorCode::DownloadFailed, "重定向次数过多"))
}

pub fn download_exact(
    url: &str,
    domains: &DomainPolicy,
    dest: &Path,
    expected_size: Option<u64>,
    enforce: bool,
) -> Result<(), InstallError> {
    download_once(url, domains, dest, expected_size, true, enforce)
}

fn download_once(
    url: &str,
    domains: &DomainPolicy,
    dest: &Path,
    expected_size: Option<u64>,
    allow_retry: bool,
    enforce: bool,
) -> Result<(), InstallError> {
    match download_url(url, domains, dest, enforce)? {
        Downloaded::Hap { .. } => {
            let size = fs::metadata(dest).map(|meta| meta.len()).unwrap_or(0);
            if let Some(expected) = expected_size {
                if size != expected {
                    let _ = fs::remove_file(dest);
                    if allow_retry {
                        return download_once(url, domains, dest, expected_size, false, enforce);
                    }
                    return Err(InstallError::new(ErrorCode::SizeMismatch, format!("实际 {size}，预期 {expected}")));
                }
            }
            Ok(())
        }
        Downloaded::HtmlPage { .. } => Err(InstallError::new(ErrorCode::SourceInvalid, "下载地址返回的是网页")),
        Downloaded::Manifest(_) => Err(InstallError::new(ErrorCode::SourceInvalid, "下载地址返回的不是 HAP")),
    }
}

fn parse_manifest(body: &[u8]) -> Result<ManifestDoc, InstallError> {
    let value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|_| InstallError::new(ErrorCode::SourceInvalid, "manifest 无法解析"))?;
    if value.get("artifactType").and_then(|item| item.as_str()) != Some("HAP") {
        return Err(InstallError::new(ErrorCode::SourceInvalid, "manifest 的 artifactType 必须是 HAP"));
    }
    let text = |key: &str| value.get(key).and_then(|item| item.as_str()).unwrap_or("").to_string();
    let file_size = value.get("fileSize").and_then(|item| item.as_u64()).unwrap_or(0);
    let version_code = value.get("versionCode").and_then(|item| item.as_u64()).unwrap_or(0) as u32;
    let download_url = text("downloadUrl");
    if download_url.is_empty() || text("sha256").is_empty() || file_size == 0 {
        return Err(InstallError::new(ErrorCode::SourceInvalid, "manifest 缺少文件大小、SHA-256 或下载地址"));
    }
    Ok(ManifestDoc {
        task_id: text("taskId"),
        file_name: if text("fileName").ends_with(".hap") { text("fileName") } else { "artifact.hap".into() },
        file_size,
        sha256: text("sha256"),
        bundle_name: text("bundleName"),
        version_name: text("versionName"),
        version_code,
        download_url,
        expires_at: value.get("expiresAt").and_then(|item| item.as_str()).map(str::to_string),
    })
}

fn file_name_from_disposition(value: &str) -> Option<String> {
    let marker = "filename=";
    let index = value.to_ascii_lowercase().find(marker)?;
    let raw = value[index + marker.len()..].trim_matches(|ch| ch == '"' || ch == ';').trim();
    let name = Path::new(raw).file_name()?.to_str()?.to_string();
    if name.contains("..") { None } else { Some(name) }
}

fn file_name_from_url(url: &str) -> String {
    url.split(['?', '#']).next().unwrap_or(url).rsplit('/').next().unwrap_or("artifact.hap").to_string()
}

fn resolve_location(base: &str, location: &str) -> String {
    if location.starts_with("https://") || location.starts_with("http://") {
        return location.to_string();
    }
    let root = base.split(['?', '#']).next().unwrap_or(base);
    let scheme_end = root.find("://").unwrap_or(0);
    if location.starts_with('/') {
        let host_end = root[scheme_end + 3..].find('/').map(|index| scheme_end + 3 + index).unwrap_or(root.len());
        return format!("{}{}", &root[..host_end], location);
    }
    let slash = root.rfind('/').unwrap_or(root.len());
    format!("{}/{location}", &root[..slash])
}

