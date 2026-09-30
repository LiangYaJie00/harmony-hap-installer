use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use fs2::FileExt;
use harmony_hap_core::{ErrorCode, InstallError};
use serde::{Deserialize, Serialize};

pub const DATA_DIR_NAME: &str = "HarmonyHapInstaller";

#[derive(Debug, Clone)]
pub struct Layout {
    pub root: PathBuf,
}

impl Layout {
    pub fn from_root(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn system_default() -> Self {
        Self { root: default_root() }
    }

    pub fn ensure(&self) -> Result<(), InstallError> {
        for name in ["cache", "temp", "logs", "history", "hdc", "locks"] {
            fs::create_dir_all(self.root.join(name))
                .map_err(|err| InstallError::new(ErrorCode::InstallFailed, err.to_string()))?;
        }
        Ok(())
    }

    pub fn cache_hap(&self, sha256: &str) -> Result<PathBuf, InstallError> {
        if sha256.len() != 64 || !sha256.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Err(InstallError::new(ErrorCode::HashMismatch, "缓存键无效"));
        }
        let path = self.root.join("cache").join(sha256).join("artifact.hap");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|err| InstallError::new(ErrorCode::InstallFailed, err.to_string()))?;
        }
        let root = self.root.canonicalize().unwrap_or_else(|_| self.root.clone());
        if let Some(parent) = path.parent() {
            let parent = parent.canonicalize().unwrap_or(parent.to_path_buf());
            if !parent.starts_with(&root) {
                return Err(InstallError::new(ErrorCode::SourceInvalid, "缓存路径越界"));
            }
        }
        Ok(path)
    }

    pub fn temp_hap(&self) -> PathBuf {
        self.root.join("temp").join(format!("download-{}.hap", std::process::id()))
    }
}

pub struct DeviceLock {
    _file: File,
}

impl DeviceLock {
    pub fn acquire(layout: &Layout, device_digest: &str) -> Result<Self, InstallError> {
        layout.ensure()?;
        let path = layout.root.join("locks").join(format!("{device_digest}.lock"));
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(path)
            .map_err(|err| InstallError::new(ErrorCode::InstallFailed, err.to_string()))?;
        file.try_lock_exclusive()
            .map_err(|_| InstallError::new(ErrorCode::InstallFailed, "这台设备已经有一个安装在进行"))?;
        Ok(Self { _file: file })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HistoryItem {
    pub at: String,
    pub bundle_name: String,
    pub version_name: String,
    pub version_code: u32,
    pub sha256: String,
    pub device_digest: String,
    pub result: String,
    pub error_code: Option<String>,
}

pub fn append_history(layout: &Layout, item: HistoryItem) -> Result<(), InstallError> {
    layout.ensure()?;
    let mut items = read_history(layout)?;
    items.push(item);
    write_history(layout, &items)
}

pub fn read_history(layout: &Layout) -> Result<Vec<HistoryItem>, InstallError> {
    let path = layout.root.join("history").join("history.json");
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(path).map_err(|err| InstallError::new(ErrorCode::InstallFailed, err.to_string()))?;
    serde_json::from_str(&text).map_err(|err| InstallError::new(ErrorCode::InstallFailed, err.to_string()))
}

fn write_history(layout: &Layout, items: &[HistoryItem]) -> Result<(), InstallError> {
    let path = layout.root.join("history").join("history.json");
    fs::write(path, serde_json::to_vec_pretty(items).unwrap_or_default())
        .map_err(|err| InstallError::new(ErrorCode::InstallFailed, err.to_string()))
}

pub fn append_log(layout: &Layout, line: &str) -> Result<(), InstallError> {
    layout.ensure()?;
    let path = layout.root.join("logs").join("installer.log");
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|err| InstallError::new(ErrorCode::InstallFailed, err.to_string()))?;
    writeln!(file, "{line}").map_err(|err| InstallError::new(ErrorCode::InstallFailed, err.to_string()))?;
    Ok(())
}

pub fn read_log(layout: &Layout) -> Result<String, InstallError> {
    let path = layout.root.join("logs").join("installer.log");
    if !path.is_file() {
        return Ok(String::new());
    }
    let mut text = String::new();
    File::open(path)
        .and_then(|mut file| file.read_to_string(&mut text))
        .map_err(|err| InstallError::new(ErrorCode::InstallFailed, err.to_string()))?;
    Ok(text)
}

pub fn cleanup(layout: &Layout, now: SystemTime) -> Result<(), InstallError> {
    layout.ensure()?;
    let cache_limit = now.checked_sub(Duration::from_secs(24 * 60 * 60)).unwrap_or(now);
    let log_limit = now.checked_sub(Duration::from_secs(14 * 24 * 60 * 60)).unwrap_or(now);
    let history_limit = now.checked_sub(Duration::from_secs(30 * 24 * 60 * 60)).unwrap_or(now);
    remove_older(&layout.root.join("cache"), cache_limit)?;
    remove_older(&layout.root.join("temp"), cache_limit)?;
    remove_older(&layout.root.join("logs"), log_limit)?;
    let mut history = read_history(layout)?;
    history.retain(|item| parse_time(&item.at).map(|time| time >= history_limit).unwrap_or(true));
    if history.len() > 100 {
        let skip = history.len() - 100;
        history = history.split_off(skip);
    }
    write_history(layout, &history)
}

fn remove_older(dir: &Path, limit: SystemTime) -> Result<(), InstallError> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir).map_err(|err| InstallError::new(ErrorCode::InstallFailed, err.to_string()))? {
        let entry = entry.map_err(|err| InstallError::new(ErrorCode::InstallFailed, err.to_string()))?;
        let modified = entry.metadata().and_then(|meta| meta.modified()).unwrap_or(SystemTime::now());
        if modified < limit {
            let path = entry.path();
            if path.is_dir() {
                let _ = fs::remove_dir_all(path);
            } else {
                let _ = fs::remove_file(path);
            }
        }
    }
    Ok(())
}

fn parse_time(value: &str) -> Option<SystemTime> {
    let date = chrono_lite(value)?;
    Some(date)
}

fn chrono_lite(value: &str) -> Option<SystemTime> {
    let parsed = chrono::DateTime::parse_from_rfc3339(value).ok()?;
    Some(SystemTime::UNIX_EPOCH + Duration::from_secs(parsed.timestamp().max(0) as u64))
}

fn default_root() -> PathBuf {
    if let Some(root) = std::env::var_os("HARMONY_HAP_DATA_DIR") {
        return PathBuf::from(root);
    }
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
        return home.join("Library/Application Support").join(DATA_DIR_NAME);
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(local) = std::env::var_os("LOCALAPPDATA") {
            return PathBuf::from(local).join(DATA_DIR_NAME);
        }
        return PathBuf::from(DATA_DIR_NAME);
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
        home.join(".local").join("share").join(DATA_DIR_NAME)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_path_stays_inside_root() {
        let root = std::env::temp_dir().join(format!("hap-cache-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let layout = Layout::from_root(root.clone());
        layout.ensure().unwrap();
        let sha = "ab".repeat(32);
        let path = layout.cache_hap(&sha).unwrap();
        assert!(path.ends_with("artifact.hap"));
        assert!(path.starts_with(&root));
        assert!(layout.cache_hap("../evil").is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn second_lock_fails() {
        let root = std::env::temp_dir().join(format!("hap-lock-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let layout = Layout::from_root(root.clone());
        let first = DeviceLock::acquire(&layout, "abc").unwrap();
        assert!(DeviceLock::acquire(&layout, "abc").is_err());
        drop(first);
        assert!(DeviceLock::acquire(&layout, "abc").is_ok());
        let _ = fs::remove_dir_all(&root);
    }
}
