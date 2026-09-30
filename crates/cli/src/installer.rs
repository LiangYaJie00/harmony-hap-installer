use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use harmony_hap_core::{
    check_download_url, digest_id, download_exact, download_host, download_url, load_policies, normalize_identity,
    redact_text, short_hash, transition, verify_hap, Downloaded, ErrorCode, HapTrust, IdentityPolicy, InstallError, Phase,
    PolicySet, VerifyRequest,
};
use harmony_hap_hdc::{classify_install_failure, BundleSnapshot, DeviceState, HdcClient};
use harmony_hap_qrcode::decode_qr_bytes;
use harmony_hap_storage::{append_history, append_log, cleanup, read_history, read_log, DeviceLock, HistoryItem, Layout};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DoctorView {
    pub config_dir: String,
    pub data_dir: String,
    pub hdc_path: String,
    pub hdc_version: String,
    pub gaps: Vec<String>,
    pub ready: bool,
    pub identity_note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactView {
    pub file_name: String,
    pub sha256: String,
    pub sha_short: String,
    pub size: u64,
    pub bundle_name: String,
    pub version_name: String,
    pub version_code: u32,
    pub ability_name: Option<String>,
    pub task_id: String,
    pub hash_trusted: bool,
    pub hash_note: String,
    pub local_path: String,
    pub source_host: String,
    pub certificate_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolveOutcome {
    pub artifact: Option<ArtifactView>,
    pub landing_url: Option<String>,
    pub landing_message: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceView {
    pub id: String,
    pub masked_id: String,
    pub transport: String,
    pub state: String,
    pub model_name: String,
    pub selected: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicesView {
    pub devices: Vec<DeviceView>,
    pub requires_choice: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallView {
    pub phase: String,
    pub bundle_name: String,
    pub version_name: String,
    pub version_code: u32,
    pub device_masked: String,
    pub mode: String,
    pub message: String,
}

pub struct Installer {
    policies: PolicySet,
    identity: IdentityPolicy,
    config_dir: PathBuf,
    layout: Layout,
    hdc: HdcClient,
    pub install_timeout: Duration,
    pub verify_window: Duration,
}

impl Installer {
    pub fn open_at(config_dir: &Path, vendor_dir: &Path, data_dir: &Path) -> Result<Self, InstallError> {
        let policies = load_policies(config_dir).map_err(|err| InstallError::new(ErrorCode::SourceInvalid, err.to_string()))?;
        let layout = Layout::from_root(data_dir.to_path_buf());
        layout.ensure()?;
        let hdc = HdcClient::ensure_managed(&policies.hdc, vendor_dir, data_dir)?;
        let identity = read_identity(&layout.root.join("identity-policy.json"))?;
        Ok(Self {
            policies,
            identity,
            config_dir: config_dir.to_path_buf(),
            layout,
            hdc,
            install_timeout: Duration::from_secs(180),
            verify_window: Duration::from_secs(10),
        })
    }

    pub fn doctor(&self) -> DoctorView {
        let mut gaps: Vec<String> = self.policies.report().gaps.iter().map(|gap| gap.message().to_string()).collect();
        gaps.extend(self.identity.gaps().iter().map(|gap| gap.message().to_string()));
        let identity_note = if !self.identity.enforce {
            "来源校验已关闭，任意 HAP 都可以安装".to_string()
        } else if self.identity.gaps().is_empty() {
            "来源校验已开启".to_string()
        } else {
            "来源校验已开启，名单未填完".to_string()
        };
        DoctorView {
            config_dir: self.config_dir.display().to_string(),
            data_dir: self.layout.root.display().to_string(),
            hdc_path: self.hdc.path().display().to_string(),
            hdc_version: self.hdc.version().to_string(),
            ready: gaps.is_empty(),
            gaps,
            identity_note,
        }
    }

    pub fn identity(&self) -> IdentityPolicy {
        self.identity.clone()
    }

    pub fn save_identity(&mut self, policy: IdentityPolicy) -> Result<IdentityPolicy, InstallError> {
        let policy = normalize_identity(policy).map_err(|err| InstallError::new(ErrorCode::SourceInvalid, err))?;
        let path = self.layout.root.join("identity-policy.json");
        let text = serde_json::to_string_pretty(&policy)
            .map_err(|err| InstallError::new(ErrorCode::SourceInvalid, err.to_string()))?;
        fs::write(&path, text).map_err(|err| InstallError::new(ErrorCode::SourceInvalid, err.to_string()))?;
        self.identity = policy.clone();
        Ok(policy)
    }

    pub fn resolve_url(&self, url: &str) -> Result<ResolveOutcome, InstallError> {
        let mut phase = Phase::Created;
        phase = step(phase, Phase::ResolvingSource)?;
        let temp = self.layout.temp_hap();
        phase = step(phase, Phase::Downloading)?;
        let domains = self.identity.domain_policy();
        match download_url(url, &domains, &temp, self.identity.enforce)? {
            Downloaded::HtmlPage { url } => Ok(ResolveOutcome {
                artifact: None,
                landing_url: Some(url),
                landing_message: Some("这个链接是下载页。请在浏览器完成下载后，使用「选择本地 HAP」继续安装。".into()),
            }),
            Downloaded::Manifest(manifest) => {
                check_download_url(&manifest.download_url, &domains, self.identity.enforce)?;
                let staged = self.layout.root.join("temp").join("manifest-artifact.hap");
                download_exact(
                    &manifest.download_url,
                    &domains,
                    &staged,
                    Some(manifest.file_size),
                    self.identity.enforce,
                )?;
                phase = step(phase, Phase::HashChecking)?;
                let view = self.store_verified(
                    &staged,
                    &manifest.file_name,
                    Some(manifest.file_size),
                    Some(&manifest.sha256),
                    Some(&manifest.bundle_name),
                    Some(&manifest.version_name),
                    Some(manifest.version_code),
                    &manifest.task_id,
                    &download_host(&manifest.download_url),
                )?;
                let _ = phase;
                Ok(ResolveOutcome { artifact: Some(view), landing_url: None, landing_message: None })
            }
            Downloaded::Hap { bytes_path, file_name, source_url } => {
                let staged = ensure_hap_name(&bytes_path, &file_name)?;
                phase = step(phase, Phase::HashChecking)?;
                let view = self.store_verified(&staged, &file_name, None, None, None, None, None, "", &download_host(&source_url))?;
                let _ = phase;
                Ok(ResolveOutcome { artifact: Some(view), landing_url: None, landing_message: None })
            }
        }
    }

    pub fn resolve_qr(&self, bytes: &[u8]) -> Result<ResolveOutcome, InstallError> {
        let text = decode_qr_bytes(bytes)?;
        self.resolve_url(text.trim())
    }

    pub fn resolve_local_bytes(&self, file_name: &str, bytes: &[u8]) -> Result<ArtifactView, InstallError> {
        let dest = self.layout.root.join("temp").join(safe_hap_name(file_name));
        fs::write(&dest, bytes).map_err(|err| InstallError::new(ErrorCode::SourceInvalid, err.to_string()))?;
        self.resolve_local(&dest)
    }

    pub fn resolve_local(&self, path: &Path) -> Result<ArtifactView, InstallError> {
        let mut phase = Phase::Created;
        phase = step(phase, Phase::ResolvingSource)?;
        phase = step(phase, Phase::HashChecking)?;
        let file_name = path.file_name().and_then(|name| name.to_str()).unwrap_or("artifact.hap").to_string();
        let view = self.store_verified(path, &file_name, None, None, None, None, None, "", "本地文件")?;
        let _ = phase;
        Ok(view)
    }

    pub fn devices(&self) -> Result<DevicesView, InstallError> {
        let records = self.hdc.list_devices()?;
        let connected: Vec<_> = records.iter().filter(|item| item.state == DeviceState::Connected).collect();
        let requires_choice = connected.len() != 1;
        let selected = if connected.len() == 1 { connected[0].id.as_str() } else { "" };
        let devices = records
            .iter()
            .map(|item| DeviceView {
                model_name: if item.state == DeviceState::Connected {
                    self.hdc.product_name(&item.id).ok().flatten().unwrap_or_default()
                } else {
                    String::new()
                },
                masked_id: mask_id(&item.id),
                selected: item.id == selected,
                state: match item.state {
                    DeviceState::Connected => "在线",
                    DeviceState::Unauthorized => "未授权",
                    DeviceState::Offline => "离线",
                    DeviceState::Unknown => "未知",
                }
                .into(),
                transport: item.transport.clone(),
                id: item.id.clone(),
            })
            .collect();
        Ok(DevicesView { devices, requires_choice })
    }

    pub fn install(&self, sha256: &str, device_id: &str, confirm: bool) -> Result<InstallView, InstallError> {
        if !confirm {
            return Err(InstallError::new(ErrorCode::InstallFailed, "请先在确认页确认安装"));
        }
        let hap_path = self.layout.cache_hap(sha256)?;
        if !hap_path.is_file() {
            return Err(InstallError::new(ErrorCode::SourceInvalid, "本地没有已校验的 HAP，请重新解析来源"));
        }
        let (info, trust) = self.verify_path(&hap_path, None, None, None, None, None)?;
        if hash_file(&hap_path)? != info.sha256 {
            return Err(InstallError::new(ErrorCode::HashMismatch, "缓存文件已变化"));
        }
        let _ = trust;
        let devices = self.hdc.list_devices()?;
        let device = devices.iter().find(|item| item.id == device_id);
        let Some(device) = device else {
            let connected = devices.iter().filter(|item| item.state == DeviceState::Connected).count();
            if connected > 1 {
                return Err(InstallError::new(ErrorCode::MultipleDevices, ""));
            }
            if devices.iter().any(|item| item.state == DeviceState::Unauthorized) {
                return Err(InstallError::new(ErrorCode::DeviceUnauthorized, ""));
            }
            if devices.iter().any(|item| item.state == DeviceState::Offline) {
                return Err(InstallError::new(ErrorCode::DeviceOffline, ""));
            }
            return Err(InstallError::new(ErrorCode::NoDevice, ""));
        };
        if device.state != DeviceState::Connected {
            return Err(match device.state {
                DeviceState::Unauthorized => InstallError::new(ErrorCode::DeviceUnauthorized, ""),
                DeviceState::Offline => InstallError::new(ErrorCode::DeviceOffline, ""),
                _ => InstallError::new(ErrorCode::NoDevice, ""),
            });
        }
        let _lock = DeviceLock::acquire(&self.layout, &digest_id(device_id))?;
        if let Some(required) = info.compatible_api {
            if let Some(actual) = self.hdc.api_level(device_id)? {
                if actual <= 100 && actual < required {
                    return Err(InstallError::new(ErrorCode::SdkIncompatible, format!("设备 API {actual}，包要求 {required}")));
                }
            }
        }
        if let Some(free) = self.hdc.free_bytes(device_id)? {
            if free < info.size.saturating_mul(2) {
                return Err(InstallError::new(ErrorCode::InsufficientStorage, ""));
            }
        }
        let snapshot = self.hdc.query_bundle(device_id, &info.bundle_name)?;
        let mode = match &snapshot {
            BundleSnapshot::Missing => "首次安装",
            BundleSnapshot::Present { version_code, .. } if *version_code < info.version_code => "升级",
            BundleSnapshot::Present { version_code, .. } if *version_code == info.version_code => "同版本覆盖",
            BundleSnapshot::Present { .. } => {
                return Err(InstallError::new(ErrorCode::InstallFailed, "设备上已有更高版本，已阻断降级"));
            }
            BundleSnapshot::Unknown => "版本未知，按确认结果安装",
        };
        let mut phase = Phase::ReadyToInstall;
        phase = step(phase, Phase::Installing)?;
        let output = self.hdc.install_hap(device_id, &hap_path, self.install_timeout)?;
        if output.timed_out || output.status != Some(0) {
            phase = step(phase, Phase::Verifying)?;
            return self.reconcile_after_failure(phase, &info, device_id, mode, &output);
        }
        phase = step(phase, Phase::Verifying)?;
        self.confirm_installed(phase, &info, device_id, mode)
    }

    pub fn installed_version(&self, device_id: &str, bundle_name: &str) -> Result<String, InstallError> {
        match self.hdc.query_bundle(device_id, bundle_name)? {
            harmony_hap_hdc::BundleSnapshot::Present { version_name, version_code } => {
                Ok(format!("{bundle_name} {version_name} ({version_code})"))
            }
            harmony_hap_hdc::BundleSnapshot::Missing => Err(InstallError::new(ErrorCode::VerifyFailed, "设备上没有这个包")),
            harmony_hap_hdc::BundleSnapshot::Unknown => Err(InstallError::new(ErrorCode::VerifyFailed, "无法确认设备上的版本")),
        }
    }

    pub fn launch(&self, device_id: &str, bundle_name: &str, ability: &str) -> Result<(), InstallError> {
        self.hdc.start_app(device_id, bundle_name, ability)
    }

    pub fn history(&self) -> Result<Vec<HistoryItem>, InstallError> {
        read_history(&self.layout)
    }

    pub fn cleanup(&self) -> Result<(), InstallError> {
        cleanup(&self.layout, std::time::SystemTime::now())
    }

    pub fn diagnostics(&self) -> Result<String, InstallError> {
        let log = read_log(&self.layout)?;
        Ok(redact_text(&log, &[]))
    }

    fn reconcile_after_failure(
        &self,
        phase: Phase,
        info: &harmony_hap_core::HapInfo,
        device_id: &str,
        mode: &str,
        output: &harmony_hap_hdc::CommandOutput,
    ) -> Result<InstallView, InstallError> {
        match self.hdc.query_bundle(device_id, &info.bundle_name)? {
            BundleSnapshot::Present { version_name, version_code }
                if version_name == info.version_name && version_code == info.version_code =>
            {
                self.finish_success(phase, info, device_id, mode, "安装命令超时或返回失败，但设备上的版本已经一致")
            }
            BundleSnapshot::Missing => {
                let error = classify_install_failure(output);
                self.record(info, device_id, "FAILED", Some(error.code))?;
                Err(error)
            }
            _ => {
                let error = InstallError::new(ErrorCode::VerifyFailed, "安装结果未知，请不要立刻再次安装")
                    .with_diagnostic(format!("{}{}", output.stdout, output.stderr));
                self.record(info, device_id, "UNKNOWN", Some(error.code))?;
                let _ = phase;
                Err(error)
            }
        }
    }

    fn confirm_installed(&self, mut phase: Phase, info: &harmony_hap_core::HapInfo, device_id: &str, mode: &str) -> Result<InstallView, InstallError> {
        let deadline = Instant::now() + self.verify_window;
        let mut seen = String::new();
        loop {
            match self.hdc.query_bundle(device_id, &info.bundle_name)? {
                BundleSnapshot::Present { version_name, version_code }
                    if version_name == info.version_name && version_code == info.version_code =>
                {
                    phase = step(phase, Phase::Installed)?;
                    return self.finish_success(phase, info, device_id, mode, "安装成功");
                }
                BundleSnapshot::Present { version_name, version_code } => {
                    seen = format!("设备上是 {version_name} ({version_code})");
                }
                BundleSnapshot::Missing => seen = "设备上没有这个包".into(),
                BundleSnapshot::Unknown => seen = "没有读到版本".into(),
            }
            if Instant::now() >= deadline {
                if seen.is_empty() {
                    seen = "没有读到版本".into();
                }
                let error = InstallError::new(
                    ErrorCode::VerifyFailed,
                    format!("10 秒内没有核对到一致的包名和版本，{seen}"),
                );
                self.record(info, device_id, "VERIFY_FAILED", Some(error.code))?;
                return Err(error);
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn finish_success(&self, phase: Phase, info: &harmony_hap_core::HapInfo, device_id: &str, mode: &str, message: &str) -> Result<InstallView, InstallError> {
        self.record(info, device_id, "INSTALLED", None)?;
        Ok(InstallView {
            phase: format!("{phase:?}"),
            bundle_name: info.bundle_name.clone(),
            version_name: info.version_name.clone(),
            version_code: info.version_code,
            device_masked: mask_id(device_id),
            mode: mode.to_string(),
            message: message.to_string(),
        })
    }

    fn record(&self, info: &harmony_hap_core::HapInfo, device_id: &str, result: &str, code: Option<ErrorCode>) -> Result<(), InstallError> {
        let item = HistoryItem {
            at: chrono_now(),
            bundle_name: info.bundle_name.clone(),
            version_name: info.version_name.clone(),
            version_code: info.version_code,
            sha256: info.sha256.clone(),
            device_digest: digest_id(device_id),
            result: result.to_string(),
            error_code: code.map(|item| format!("{item:?}")),
        };
        append_history(&self.layout, item)?;
        let line = redact_text(&format!("{result} {} {}", short_hash(&info.sha256), digest_id(device_id)), &[device_id]);
        append_log(&self.layout, &line)
    }

    fn store_verified(
        &self,
        path: &Path,
        file_name: &str,
        expected_size: Option<u64>,
        expected_sha256: Option<&str>,
        expected_bundle: Option<&str>,
        expected_version_name: Option<&str>,
        expected_version_code: Option<u32>,
        task_id: &str,
        source_host: &str,
    ) -> Result<ArtifactView, InstallError> {
        let staged_name = self.layout.root.join("temp").join(safe_hap_name(file_name));
        if path != staged_name {
            fs::copy(path, &staged_name).map_err(|err| InstallError::new(ErrorCode::SourceInvalid, err.to_string()))?;
        }
        let (info, trust) = self.verify_path(&staged_name, expected_size, expected_sha256, expected_bundle, expected_version_name, expected_version_code)?;
        let cached = self.layout.cache_hap(&info.sha256)?;
        fs::copy(&staged_name, &cached).map_err(|err| InstallError::new(ErrorCode::InstallFailed, err.to_string()))?;
        let actual = hash_file(&cached)?;
        if actual != info.sha256 {
            let _ = fs::remove_file(&cached);
            return Err(InstallError::new(ErrorCode::HashMismatch, ""));
        }
        Ok(ArtifactView {
            file_name: "artifact.hap".into(),
            sha_short: short_hash(&info.sha256),
            hash_trusted: trust == HapTrust::PlatformHash,
            hash_note: if trust == HapTrust::PlatformHash {
                "已对照平台 SHA-256".into()
            } else {
                "只有本地哈希，不能证明文件就是平台原始产物".into()
            },
            local_path: cached.display().to_string(),
            task_id: task_id.to_string(),
            sha256: info.sha256,
            size: info.size,
            bundle_name: info.bundle_name,
            version_name: info.version_name,
            version_code: info.version_code,
            ability_name: info.ability_name,
            source_host: source_host.to_string(),
            certificate_sha256: info.certificate_sha256,
        })
    }

    fn verify_path(
        &self,
        path: &Path,
        expected_size: Option<u64>,
        expected_sha256: Option<&str>,
        expected_bundle: Option<&str>,
        expected_version_name: Option<&str>,
        expected_version_code: Option<u32>,
    ) -> Result<(harmony_hap_core::HapInfo, HapTrust), InstallError> {
        let bundles = self.identity.bundle_policy();
        let signing = self.identity.signing_policy();
        verify_hap(
            path,
            &VerifyRequest {
                expected_size,
                expected_sha256,
                expected_bundle,
                expected_version_name,
                expected_version_code,
                bundles: &bundles,
                signing: &signing,
                enforce_identity: self.identity.enforce,
            },
        )
    }
}

fn read_identity(path: &Path) -> Result<IdentityPolicy, InstallError> {
    if !path.is_file() {
        return Ok(IdentityPolicy::default());
    }
    let text = fs::read_to_string(path).map_err(|err| InstallError::new(ErrorCode::SourceInvalid, err.to_string()))?;
    let parsed = serde_json::from_str(&text).map_err(|err| InstallError::new(ErrorCode::SourceInvalid, err.to_string()))?;
    normalize_identity(parsed).map_err(|err| InstallError::new(ErrorCode::SourceInvalid, err))
}

fn step(current: Phase, next: Phase) -> Result<Phase, InstallError> {
    transition(current, next).map_err(|_| InstallError::new(ErrorCode::InstallFailed, "安装状态不能这样跳转"))
}

fn safe_hap_name(file_name: &str) -> String {
    let name = Path::new(file_name).file_name().and_then(|name| name.to_str()).unwrap_or("artifact.hap");
    if name.ends_with(".hap") && !name.contains("..") { name.to_string() } else { "artifact.hap".into() }
}

fn ensure_hap_name(path: &Path, file_name: &str) -> Result<PathBuf, InstallError> {
    if path.extension().and_then(|ext| ext.to_str()) == Some("hap") {
        return Ok(path.to_path_buf());
    }
    let dest = path.with_file_name(safe_hap_name(file_name));
    fs::rename(path, &dest).map_err(|err| InstallError::new(ErrorCode::DownloadFailed, err.to_string()))?;
    Ok(dest)
}

fn hash_file(path: &Path) -> Result<String, InstallError> {
    let bytes = fs::read(path).map_err(|err| InstallError::new(ErrorCode::SourceInvalid, err.to_string()))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn mask_id(id: &str) -> String {
    let tail: String = id.chars().rev().take(4).collect::<String>().chars().rev().collect();
    format!("****{tail}")
}

fn chrono_now() -> String {
    chrono::Utc::now().to_rfc3339()
}

pub fn find_vendor_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("HARMONY_HAP_VENDOR_HDC") {
        return PathBuf::from(path);
    }
    if let Some(path) = bundled_resource_dir("vendor/hdc") {
        return path;
    }
    walk_for("vendor/hdc", "hdc")
}

pub fn find_config_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("HARMONY_HAP_INSTALLER_CONFIG") {
        return PathBuf::from(path);
    }
    if let Some(path) = bundled_resource_dir("config") {
        return path;
    }
    walk_for("config", "domains.json")
}

fn bundled_resource_dir(relative: &str) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let resources = exe.parent()?.parent()?.join("Resources");
    let bundled = resources.join("_up_").join("_up_").join(relative);
    if bundled.exists() {
        return Some(bundled);
    }
    let direct = resources.join(relative);
    direct.exists().then_some(direct)
}

fn walk_for(relative: &str, marker: &str) -> PathBuf {
    let mut cursor = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    for _ in 0..6 {
        let candidate = cursor.join(relative);
        if candidate.join(marker).exists() || candidate.is_dir() && marker == "hdc" {
            return candidate;
        }
        if !cursor.pop() {
            break;
        }
    }
    PathBuf::from(relative)
}
