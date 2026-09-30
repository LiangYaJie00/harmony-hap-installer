use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

const DOMAINS_FILE: &str = "domains.json";
const HDC_POLICY_FILE: &str = "hdc-policy.json";
const SIGNING_FILE: &str = "dev-signing.json";
const BUNDLES_FILE: &str = "bundles.json";

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("找不到配置目录，预期包含 {DOMAINS_FILE}")]
    NotFound,
    #[error("读取 {path} 失败: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("解析 {path} 失败: {source}")]
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyGap {
    DomainAllowListEmpty,
    SigningCertificatesEmpty,
    BundleAllowListEmpty,
    HdcSha256NotPinned,
}

impl PolicyGap {
    pub fn message(&self) -> &'static str {
        match self {
            Self::DomainAllowListEmpty => "已开启来源校验，但下载域名为空。请在高级设置填写允许的 HTTPS 域名",
            Self::SigningCertificatesEmpty => "已开启来源校验，但证书指纹为空。请在高级设置填写指纹和到期日",
            Self::BundleAllowListEmpty => "允许的包名为空。请在高级设置填写 bundleName",
            Self::HdcSha256NotPinned => "HDC 版本尚未校验 SHA-256，正式分发前需要锁定二进制哈希",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyReport {
    pub gaps: Vec<PolicyGap>,
}

impl PolicyReport {
    pub fn ready_for_install(&self) -> bool {
        self.gaps.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySet {
    pub domains: DomainPolicy,
    pub hdc: HdcPolicy,
    pub signing: SigningPolicy,
    pub bundles: BundlePolicy,
}

impl PolicySet {
    pub fn report(&self) -> PolicyReport {
        let mut gaps = Vec::new();
        if !self.hdc.redistribute_hdc
            || !self.hdc.enforce_sha256
            || self.hdc.bundles.is_empty()
            || self.hdc.bundles.iter().any(|bundle| bundle.sha256.is_empty())
        {
            gaps.push(PolicyGap::HdcSha256NotPinned);
        }
        PolicyReport { gaps }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DomainPolicy {
    pub schema_version: u32,
    pub https_only: bool,
    pub allowed_domains: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HdcPolicy {
    pub schema_version: u32,
    pub redistribute_hdc: bool,
    pub enforce_sha256: bool,
    pub bundles: Vec<BundledHdc>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BundledHdc {
    pub platform: String,
    pub version: String,
    pub file_name: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SigningPolicy {
    pub schema_version: u32,
    pub certificates: Vec<SigningCertificate>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SigningCertificate {
    pub fingerprint_sha256: String,
    pub not_after: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct IdentityPolicy {
    pub enforce: bool,
    pub allowed_domains: Vec<String>,
    pub allowed_bundle_names: Vec<String>,
    pub certificates: Vec<SigningCertificate>,
}

impl Default for IdentityPolicy {
    fn default() -> Self {
        Self {
            enforce: false,
            allowed_domains: Vec::new(),
            allowed_bundle_names: Vec::new(),
            certificates: Vec::new(),
        }
    }
}

impl IdentityPolicy {
    pub fn gaps(&self) -> Vec<PolicyGap> {
        if !self.enforce {
            return Vec::new();
        }
        let mut gaps = Vec::new();
        if self.allowed_domains.is_empty() {
            gaps.push(PolicyGap::DomainAllowListEmpty);
        }
        if self.certificates.is_empty() {
            gaps.push(PolicyGap::SigningCertificatesEmpty);
        }
        if self.allowed_bundle_names.is_empty() {
            gaps.push(PolicyGap::BundleAllowListEmpty);
        }
        gaps
    }

    pub fn domain_policy(&self) -> DomainPolicy {
        DomainPolicy {
            schema_version: 1,
            https_only: true,
            allowed_domains: self.allowed_domains.clone(),
        }
    }

    pub fn bundle_policy(&self) -> BundlePolicy {
        BundlePolicy {
            schema_version: 1,
            allowed_bundle_names: self.allowed_bundle_names.clone(),
        }
    }

    pub fn signing_policy(&self) -> SigningPolicy {
        SigningPolicy {
            schema_version: 1,
            certificates: self.certificates.clone(),
        }
    }
}

pub fn normalize_identity(policy: IdentityPolicy) -> Result<IdentityPolicy, String> {
    let allowed_domains = policy
        .allowed_domains
        .into_iter()
        .map(|item| item.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>();
    if allowed_domains.iter().any(|item| item.contains('/') || item.contains(':') || item.contains(' ')) {
        return Err("下载域名只填写主机名，例如 apps.example.com".into());
    }
    let allowed_bundle_names = policy
        .allowed_bundle_names
        .into_iter()
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>();
    if allowed_bundle_names.iter().any(|item| item.contains(' ') || item.contains('/')) {
        return Err("包名每行一个，不要包含空格".into());
    }
    let mut certificates = Vec::new();
    for cert in policy.certificates {
        let fingerprint_sha256 = cert.fingerprint_sha256.trim().to_ascii_lowercase();
        if fingerprint_sha256.len() != 64 || !fingerprint_sha256.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Err("证书指纹必须是 64 位 SHA-256 十六进制".into());
        }
        if chrono::NaiveDate::parse_from_str(cert.not_after.trim(), "%Y-%m-%d").is_err() {
            return Err("证书到期日使用 YYYY-MM-DD".into());
        }
        certificates.push(SigningCertificate {
            fingerprint_sha256,
            not_after: cert.not_after.trim().to_string(),
        });
    }
    Ok(IdentityPolicy {
        enforce: policy.enforce,
        allowed_domains,
        allowed_bundle_names,
        certificates,
    })
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BundlePolicy {
    pub schema_version: u32,
    pub allowed_bundle_names: Vec<String>,
}

pub fn load_policies(dir: &Path) -> Result<PolicySet, PolicyError> {
    if !dir.join(DOMAINS_FILE).is_file() {
        return Err(PolicyError::NotFound);
    }
    Ok(PolicySet {
        domains: read_json(dir.join(DOMAINS_FILE))?,
        hdc: read_json(dir.join(HDC_POLICY_FILE))?,
        signing: read_json(dir.join(SIGNING_FILE))?,
        bundles: read_json(dir.join(BUNDLES_FILE))?,
    })
}

fn read_json<T: for<'de> Deserialize<'de>>(path: PathBuf) -> Result<T, PolicyError> {
    let text = fs::read_to_string(&path).map_err(|source| PolicyError::Read {
        path: path.clone(),
        source,
    })?;
    serde_json::from_str(&text).map_err(|source| PolicyError::Parse { path, source })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_config() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config")
    }

    #[test]
    fn committed_config_leaves_identity_open() {
        let policies = load_policies(&repo_config()).expect("config should parse");
        assert!(policies.domains.https_only);
        assert!(policies.domains.allowed_domains.is_empty());
        assert!(policies.signing.certificates.is_empty());
        assert!(policies.bundles.allowed_bundle_names.is_empty());
        assert!(policies.hdc.redistribute_hdc);
        assert!(policies.hdc.enforce_sha256);
        assert!(policies
            .hdc
            .bundles
            .iter()
            .any(|bundle| bundle.platform == "macos-aarch64" && !bundle.sha256.is_empty()));
        let report = policies.report();
        assert!(report.ready_for_install());
        assert!(!report.gaps.contains(&PolicyGap::HdcSha256NotPinned));
        let mut identity = IdentityPolicy::default();
        assert!(identity.gaps().is_empty());
        identity.enforce = true;
        assert!(identity.gaps().contains(&PolicyGap::DomainAllowListEmpty));
        assert!(identity.gaps().contains(&PolicyGap::SigningCertificatesEmpty));
        assert!(identity.gaps().contains(&PolicyGap::BundleAllowListEmpty));
    }
}
