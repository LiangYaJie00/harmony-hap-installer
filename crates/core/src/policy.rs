use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
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
            Self::DomainAllowListEmpty => "下载域名白名单为空，安装前必须写入允许的 HTTPS 域名",
            Self::SigningCertificatesEmpty => "DEV 证书指纹为空，安装前必须写入允许的证书指纹",
            Self::BundleAllowListEmpty => "允许的包名为空，安装前必须写入 bundleName",
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
        if self.domains.allowed_domains.is_empty() {
            gaps.push(PolicyGap::DomainAllowListEmpty);
        }
        if self.signing.certificates.is_empty() {
            gaps.push(PolicyGap::SigningCertificatesEmpty);
        }
        if self.bundles.allowed_bundle_names.is_empty() {
            gaps.push(PolicyGap::BundleAllowListEmpty);
        }
        if !self.hdc.enforce_sha256
            || self
                .hdc
                .allowed_versions
                .iter()
                .any(|version| version.sha256.is_none())
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
    pub selection_priority: Vec<String>,
    pub allowed_versions: Vec<HdcAllowedVersion>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HdcAllowedVersion {
    pub version: String,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SigningPolicy {
    pub schema_version: u32,
    pub certificates: Vec<SigningCertificate>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SigningCertificate {
    pub fingerprint_sha256: String,
    pub not_after: String,
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
    fn committed_config_parses_and_is_not_ready() {
        let policies = load_policies(&repo_config()).expect("config should parse");
        assert!(policies.domains.https_only);
        assert!(policies.domains.allowed_domains.is_empty());
        assert!(!policies.hdc.redistribute_hdc);
        assert_eq!(
            policies.hdc.selection_priority,
            ["managed", "commandLineTools", "devEcoStudio"]
        );
        assert!(policies.signing.certificates.is_empty());
        assert!(policies.bundles.allowed_bundle_names.is_empty());
        let report = policies.report();
        assert!(!report.ready_for_install());
        assert!(report.gaps.contains(&PolicyGap::DomainAllowListEmpty));
        assert!(report.gaps.contains(&PolicyGap::SigningCertificatesEmpty));
        assert!(report.gaps.contains(&PolicyGap::BundleAllowListEmpty));
        assert!(report.gaps.contains(&PolicyGap::HdcSha256NotPinned));
    }
}
