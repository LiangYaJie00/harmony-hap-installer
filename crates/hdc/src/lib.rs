use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use harmony_hap_core::{digest_id, BundledHdc, ErrorCode, HdcPolicy, InstallError};
use sha2::{Digest, Sha256};
use wait_timeout::ChildExt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRecord {
    pub id: String,
    pub id_digest: String,
    pub transport: String,
    pub state: DeviceState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceState {
    Connected,
    Unauthorized,
    Offline,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleSnapshot {
    Missing,
    Present { version_name: String, version_code: u32 },
    Unknown,
}

#[derive(Debug, Clone)]
pub struct HdcClient {
    path: PathBuf,
    version: String,
}

impl HdcClient {
    pub fn ensure_managed(policy: &HdcPolicy, vendor_dir: &Path, data_dir: &Path) -> Result<Self, InstallError> {
        let platform = current_platform();
        let bundle = policy
            .bundles
            .iter()
            .find(|item| item.platform == platform)
            .ok_or_else(|| InstallError::new(ErrorCode::HdcNotFound, platform))?;
        let source_dir = vendor_dir.join(&bundle.platform);
        let source = source_dir.join(&bundle.file_name);
        if !source.is_file() {
            return Err(InstallError::new(ErrorCode::HdcNotFound, source.display().to_string()));
        }
        let dest_dir = data_dir.join("hdc");
        fs::create_dir_all(&dest_dir).map_err(|err| InstallError::new(ErrorCode::HdcNotFound, err.to_string()))?;
        let dest = dest_dir.join(&bundle.file_name);
        if managed_copy_needed(&source_dir, &dest_dir, &dest, &bundle.sha256)? {
            copy_platform_dir(&source_dir, &dest_dir)?;
        }
        if policy.enforce_sha256 && hash_file(&dest)? != bundle.sha256.to_ascii_lowercase() {
            return Err(InstallError::new(ErrorCode::HashMismatch, "内置 HDC 哈希不一致"));
        }
        let client = Self::from_executable(dest)?;
        if client.version != bundle.version {
            return Err(InstallError::new(
                ErrorCode::HdcVersionUnsupported,
                format!("实际 {}，策略 {}", client.version, bundle.version),
            ));
        }
        Ok(client)
    }

    pub fn from_executable(path: PathBuf) -> Result<Self, InstallError> {
        let output = run(&path, &["-v"], Duration::from_secs(10))?;
        if output.timed_out {
            return Err(InstallError::new(ErrorCode::HdcNotFound, "hdc -v 超时"));
        }
        let combined = format!("{}{}", output.stdout, output.stderr);
        if is_conflict(&combined) {
            return Err(InstallError::new(ErrorCode::HdcConflict, "").with_diagnostic(combined));
        }
        let version = parse_version(&combined).ok_or_else(|| {
            InstallError::new(ErrorCode::HdcNotFound, "无法读取 HDC 版本").with_diagnostic(combined)
        })?;
        Ok(Self { path, version })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn list_devices(&self) -> Result<Vec<DeviceRecord>, InstallError> {
        let output = self.run(&["list", "targets", "-v"], Duration::from_secs(15))?;
        parse_devices(&output)
    }

    pub fn install_hap(&self, device_id: &str, hap: &Path, timeout: Duration) -> Result<CommandOutput, InstallError> {
        let id = checked_id(device_id)?;
        self.run(&["-t", &id, "install", "-r", &hap.display().to_string()], timeout)
    }

    pub fn query_bundle(&self, device_id: &str, bundle_name: &str) -> Result<BundleSnapshot, InstallError> {
        let id = checked_id(device_id)?;
        let output = self.run(&["-t", &id, "shell", "bm", "dump", "-n", bundle_name], Duration::from_secs(20))?;
        Ok(parse_bundle_dump(&output.stdout, &output.stderr))
    }

    pub fn product_name(&self, device_id: &str) -> Result<Option<String>, InstallError> {
        let id = checked_id(device_id)?;
        let output = self.run(
            &["-t", &id, "shell", "param", "get", "const.product.name"],
            Duration::from_secs(8),
        )?;
        if output.timed_out {
            return Ok(None);
        }
        Ok(parse_product_name(&output.stdout))
    }

    pub fn api_level(&self, device_id: &str) -> Result<Option<u32>, InstallError> {
        let id = checked_id(device_id)?;
        let output = self.run(
            &["-t", &id, "shell", "param", "get", "const.ohos.apiversion"],
            Duration::from_secs(15),
        )?;
        Ok(output.stdout.split_whitespace().next().and_then(|text| text.parse().ok()))
    }

    pub fn free_bytes(&self, device_id: &str) -> Result<Option<u64>, InstallError> {
        let id = checked_id(device_id)?;
        let output = self.run(&["-t", &id, "shell", "df", "/data"], Duration::from_secs(15))?;
        Ok(parse_free_kib(&output.stdout).map(|kib| kib.saturating_mul(1024)))
    }

    pub fn start_app(&self, device_id: &str, bundle_name: &str, ability: &str) -> Result<(), InstallError> {
        let id = checked_id(device_id)?;
        let output = self.run(
            &["-t", &id, "shell", "aa", "start", "-b", bundle_name, "-a", ability],
            Duration::from_secs(20),
        )?;
        if output.status == Some(0) {
            Ok(())
        } else {
            Err(InstallError::new(ErrorCode::InstallFailed, "无法打开应用").with_diagnostic(format!("{}{}", output.stdout, output.stderr)))
        }
    }

    fn run(&self, args: &[&str], timeout: Duration) -> Result<CommandOutput, InstallError> {
        run(&self.path, args, timeout)
    }
}

pub fn current_platform() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "macos-aarch64",
        ("macos", "x86_64") => "macos-x64",
        ("windows", "x86_64") => "windows-x64",
        _ => "unsupported",
    }
}

pub fn bundle_for<'a>(policy: &'a HdcPolicy, platform: &str) -> Option<&'a BundledHdc> {
    policy.bundles.iter().find(|item| item.platform == platform)
}

fn run(path: &Path, args: &[&str], timeout: Duration) -> Result<CommandOutput, InstallError> {
    let mut child = Command::new(path)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| InstallError::new(ErrorCode::HdcNotFound, err.to_string()))?;
    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();
    let stdout_task = thread::spawn(move || read_pipe(stdout_pipe));
    let stderr_task = thread::spawn(move || read_pipe(stderr_pipe));
    let finished = child
        .wait_timeout(timeout)
        .map_err(|err| InstallError::new(ErrorCode::InstallFailed, err.to_string()))?;
    let timed_out = finished.is_none();
    if timed_out {
        let _ = child.kill();
        let _ = child.wait();
    }
    let stdout = stdout_task.join().unwrap_or_default();
    let stderr = stderr_task.join().unwrap_or_default();
    Ok(CommandOutput {
        status: finished.and_then(|status| status.code()),
        stdout,
        stderr,
        timed_out,
    })
}

fn read_pipe(pipe: Option<impl Read>) -> String {
    let Some(mut pipe) = pipe else {
        return String::new();
    };
    let mut text = String::new();
    let _ = pipe.read_to_string(&mut text);
    text
}

fn managed_copy_needed(source_dir: &Path, dest_dir: &Path, dest_hdc: &Path, expected_sha: &str) -> Result<bool, InstallError> {
    if !dest_hdc.is_file() || hash_file(dest_hdc)? != expected_sha.to_ascii_lowercase() {
        return Ok(true);
    }
    let entries = fs::read_dir(source_dir).map_err(|err| InstallError::new(ErrorCode::HdcNotFound, err.to_string()))?;
    for entry in entries {
        let entry = entry.map_err(|err| InstallError::new(ErrorCode::HdcNotFound, err.to_string()))?;
        if !dest_dir.join(entry.file_name()).is_file() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn copy_platform_dir(source_dir: &Path, dest_dir: &Path) -> Result<(), InstallError> {
    let entries = fs::read_dir(source_dir).map_err(|err| InstallError::new(ErrorCode::HdcNotFound, err.to_string()))?;
    for entry in entries {
        let entry = entry.map_err(|err| InstallError::new(ErrorCode::HdcNotFound, err.to_string()))?;
        if !entry.file_type().map(|kind| kind.is_file()).unwrap_or(false) {
            continue;
        }
        let dest = dest_dir.join(entry.file_name());
        fs::copy(entry.path(), &dest).map_err(|err| InstallError::new(ErrorCode::HdcNotFound, err.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&dest)
                .map_err(|err| InstallError::new(ErrorCode::HdcNotFound, err.to_string()))?
                .permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&dest, permissions).map_err(|err| InstallError::new(ErrorCode::HdcNotFound, err.to_string()))?;
        }
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<String, InstallError> {
    let bytes = fs::read(path).map_err(|err| InstallError::new(ErrorCode::HdcNotFound, err.to_string()))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn parse_version(text: &str) -> Option<String> {
    let mut tokens = text.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "Ver:" {
            return tokens.next().map(str::to_string);
        }
        if let Some(version) = token.strip_prefix("Ver:") {
            if !version.is_empty() {
                return Some(version.to_string());
            }
        }
    }
    None
}

fn is_conflict(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("version") && (lower.contains("not match") || lower.contains("mismatch") || lower.contains("conflict"))
}

pub fn parse_devices(output: &CommandOutput) -> Result<Vec<DeviceRecord>, InstallError> {
    let combined = format!("{}{}", output.stdout, output.stderr);
    if is_conflict(&combined) {
        return Err(InstallError::new(ErrorCode::HdcConflict, "").with_diagnostic(combined));
    }
    let mut devices = Vec::new();
    for line in output.stdout.lines() {
        let line = line.trim();
        if line.is_empty() || line.eq_ignore_ascii_case("[Empty]") || line.starts_with("Connect") {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(id) = parts.next() else { continue };
        if id.eq_ignore_ascii_case("list") {
            continue;
        }
        let transport = parts.next().unwrap_or("").to_string();
        let state_text = parts.next().unwrap_or("");
        let state = match state_text.to_ascii_lowercase().as_str() {
            "connected" => DeviceState::Connected,
            "unauthorized" | "unauthorized." => DeviceState::Unauthorized,
            "offline" => DeviceState::Offline,
            _ => DeviceState::Unknown,
        };
        devices.push(DeviceRecord { id_digest: digest_id(id), id: id.to_string(), transport, state });
    }
    Ok(devices)
}

pub fn parse_bundle_dump(stdout: &str, stderr: &str) -> BundleSnapshot {
    let Some(start) = stdout.find('{') else {
        let combined = format!("{stdout}\n{stderr}").to_ascii_lowercase();
        if combined.trim().is_empty() {
            return BundleSnapshot::Unknown;
        }
        if combined.contains("not found") || combined.contains("not exist") || combined.contains("permission denied") {
            return BundleSnapshot::Missing;
        }
        return BundleSnapshot::Missing;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&stdout[start..]) else {
        return BundleSnapshot::Unknown;
    };
    let version_name = value.get("versionName").and_then(|item| item.as_str()).unwrap_or("");
    let version_code = value.get("versionCode").and_then(|item| item.as_u64()).unwrap_or(0) as u32;
    if version_name.is_empty() || version_code == 0 {
        BundleSnapshot::Missing
    } else {
        BundleSnapshot::Present { version_name: version_name.to_string(), version_code }
    }
}

pub fn parse_product_name(stdout: &str) -> Option<String> {
    let name = stdout.lines().next()?.trim();
    if name.is_empty() || name.to_ascii_lowercase().contains("fail") {
        None
    } else {
        Some(name.to_string())
    }
}

fn parse_free_kib(stdout: &str) -> Option<u64> {
    let line = stdout.lines().rev().find(|line| line.split_whitespace().count() >= 4)?;
    let parts: Vec<_> = line.split_whitespace().collect();
    parts.get(3)?.parse().ok()
}

fn checked_id(device_id: &str) -> Result<String, InstallError> {
    if device_id.is_empty()
        || device_id.len() > 128
        || !device_id.chars().all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, ':' | '.' | '_' | '-'))
    {
        return Err(InstallError::new(ErrorCode::SourceInvalid, "设备标识不合法"));
    }
    Ok(device_id.to_string())
}

pub fn classify_install_failure(output: &CommandOutput) -> InstallError {
    if output.timed_out {
        return InstallError::new(ErrorCode::InstallTimeout, "");
    }
    let text = format!("{}{}", output.stdout, output.stderr);
    let lower = text.to_ascii_lowercase();
    let code = if lower.contains("signature") || lower.contains("9568322") || lower.contains("9568332") {
        ErrorCode::SignatureConflict
    } else if lower.contains("no space") || lower.contains("storage") || lower.contains("not enough") {
        ErrorCode::InsufficientStorage
    } else if is_conflict(&lower) {
        ErrorCode::HdcConflict
    } else {
        ErrorCode::InstallFailed
    };
    InstallError::new(code, "").with_diagnostic(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_market_name_and_ignores_missing_parameter() {
        assert_eq!(parse_product_name("HUAWEI Mate 70 \n").as_deref(), Some("HUAWEI Mate 70"));
        assert_eq!(parse_product_name("Get parameter \"const.product.name\" fail! errNum is:106!\n"), None);
    }

    #[test]
    fn parses_connected_device_line() {
        let output = CommandOutput {
            status: Some(0),
            stdout: "DEVICE000000000001\tUSB\tConnected\tlocalhost\n".into(),
            stderr: String::new(),
            timed_out: false,
        };
        let devices = parse_devices(&output).unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].state, DeviceState::Connected);
        assert!(!devices[0].id_digest.is_empty());
    }

    #[test]
    fn reads_stdout_larger_than_the_pipe() {
        let output = run(
            Path::new("/usr/bin/python3"),
            &["-c", "print('x'*200000, end='')"],
            Duration::from_secs(5),
        )
        .unwrap();
        assert!(!output.timed_out);
        assert!(output.stdout.len() > 100_000);
    }

    #[test]
    fn write_permission_does_not_hide_installed_version() {
        let stdout = "com.example.app:\n{\"versionCode\":99,\"versionName\":\"3.0.14\",\"writePermission\":\"\"}";
        match parse_bundle_dump(stdout, "") {
            BundleSnapshot::Present { version_code, version_name } => {
                assert_eq!(version_code, 99);
                assert_eq!(version_name, "3.0.14");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parses_top_level_bundle_version() {
        let stdout = "com.example.app:\n{\"versionCode\":99,\"versionName\":\"3.0.14\"}";
        match parse_bundle_dump(stdout, "") {
            BundleSnapshot::Present { version_code, version_name } => {
                assert_eq!(version_code, 99);
                assert_eq!(version_name, "3.0.14");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn managed_copy_rejects_wrong_hash() {
        let root = std::env::temp_dir().join(format!("hdc-hash-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let vendor = root.join("vendor");
        fs::create_dir_all(vendor.join("macos-aarch64")).unwrap();
        fs::write(vendor.join("macos-aarch64/hdc"), b"not-hdc").unwrap();
        let policy = HdcPolicy {
            schema_version: 1,
            redistribute_hdc: true,
            enforce_sha256: true,
            bundles: vec![BundledHdc {
                platform: current_platform().into(),
                version: "9.9.9".into(),
                file_name: "hdc".into(),
                sha256: "abc".into(),
            }],
        };
        let error = HdcClient::ensure_managed(&policy, &vendor, &root.join("data")).unwrap_err();
        assert_eq!(error.code, ErrorCode::HashMismatch);
        let _ = fs::remove_dir_all(&root);
    }
}
