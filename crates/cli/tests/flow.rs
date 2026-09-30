#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use harmony_hap_cli::Installer;
use harmony_hap_core::ErrorCode;
use harmony_hap_hdc::current_platform;
use sha2::{Digest, Sha256};

#[test]
fn fake_hdc_covers_choice_conflict_and_timeout_reconcile() {
    let root = std::env::temp_dir().join(format!("hap-flow-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let config = root.join("config");
    let vendor = root.join("vendor");
    let data = root.join("data");
    let platform = current_platform();
    fs::create_dir_all(vendor.join(platform)).unwrap();
    fs::create_dir_all(&config).unwrap();
    let script = vendor.join(platform).join("hdc");
    fs::write(
        &script,
        r#"#!/bin/sh
if [ "$1" = "-v" ]; then echo "Ver: 9.9.9-test"; exit 0; fi
printf '%s\n' "$*" >> "$FAKE_HDC_LOG"
case "$*" in
  *"list targets"*) printf '%s\n' "$FAKE_HDC_DEVICES" ;;
  *install*)
    if [ "$FAKE_HDC_INSTALL" = "timeout" ]; then sleep 3; exit 0; fi
    if [ "$FAKE_HDC_INSTALL" = "conflict" ]; then echo "signature inconsistent" >&2; exit 1; fi
    echo "install bundle successfully." ;;
  *"bm dump"*) printf '%s\n' "$FAKE_HDC_DUMP" ;;
  *apiversion*) echo 20 ;;
  *df*) echo "Filesystem 1K-blocks Used Available Use% Mounted"; echo "/data 100 1 900000 1% /data" ;;
esac
exit 0
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&script, permissions).unwrap();
    let sha = hex::encode(Sha256::digest(fs::read(&script).unwrap()));
    let der = cert_der();
    let fingerprint = hex::encode(Sha256::digest(&der));
    fs::write(config.join("domains.json"), r#"{"schemaVersion":1,"httpsOnly":true,"allowedDomains":["download.example"]}"#).unwrap();
    fs::write(
        config.join("hdc-policy.json"),
        format!(
            r#"{{"schemaVersion":1,"redistributeHdc":true,"enforceSha256":true,"bundles":[{{"platform":"{platform}","version":"9.9.9-test","fileName":"hdc","sha256":"{sha}"}}]}}"#
        ),
    )
    .unwrap();
    fs::write(
        config.join("dev-signing.json"),
        format!(r#"{{"schemaVersion":1,"certificates":[{{"fingerprintSha256":"{fingerprint}","notAfter":"2099-01-01"}}]}}"#),
    )
    .unwrap();
    fs::write(config.join("bundles.json"), r#"{"schemaVersion":1,"allowedBundleNames":["com.example.app"]}"#).unwrap();
    let log = root.join("hdc.log");
    std::env::set_var("FAKE_HDC_LOG", &log);
    std::env::set_var("FAKE_HDC_DEVICES", "device-1 USB Connected localhost");
    std::env::set_var("FAKE_HDC_DUMP", r#"{"versionName":"1.0.0","versionCode":7}"#);
    std::env::set_var("FAKE_HDC_INSTALL", "ok");
    let mut installer = Installer::open_at(&config, &vendor, &data).unwrap();
    installer.install_timeout = Duration::from_secs(1);
    installer.verify_window = Duration::from_millis(500);
    let devices = installer.devices().unwrap();
    assert!(!devices.requires_choice);
    assert!(devices.devices[0].selected);
    std::env::set_var("FAKE_HDC_DEVICES", "device-1 USB Connected localhost\ndevice-2 USB Connected localhost");
    let devices = installer.devices().unwrap();
    assert!(devices.requires_choice);
    assert!(devices.devices.iter().all(|device| !device.selected));
    let hap = signed_hap(&root, &der);
    let artifact = installer.resolve_local(&hap).unwrap();
    assert!(!artifact.hash_trusted);
    let error = installer.install(&artifact.sha256, "", false).unwrap_err();
    assert_eq!(error.code, ErrorCode::InstallFailed);
    let error = installer.install(&artifact.sha256, "missing-device", true).unwrap_err();
    assert_eq!(error.code, ErrorCode::MultipleDevices);
    std::env::set_var("FAKE_HDC_DEVICES", "device-1 USB Connected localhost");
    std::env::set_var("FAKE_HDC_INSTALL", "conflict");
    std::env::set_var("FAKE_HDC_DUMP", "bundle not found");
    let error = installer.install(&artifact.sha256, "device-1", true).unwrap_err();
    assert_eq!(error.code, ErrorCode::SignatureConflict);
    let log_text = fs::read_to_string(&log).unwrap_or_default();
    assert!(!log_text.contains("uninstall"));
    assert!(!log_text.contains("bm uninstall"));
    std::env::set_var("FAKE_HDC_INSTALL", "timeout");
    std::env::set_var("FAKE_HDC_DUMP", r#"{"versionName":"1.0.0","versionCode":7}"#);
    let view = installer.install(&artifact.sha256, "device-1", true).unwrap();
    assert_eq!(view.version_code, 7);
    let history = fs::read_to_string(data.join("history/history.json")).unwrap();
    assert!(!history.contains("device-1"));
    let _ = fs::remove_dir_all(&root);
}

fn cert_der() -> Vec<u8> {
    let key = rcgen::KeyPair::generate().unwrap();
    rcgen::CertificateParams::new(vec!["dev.example".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap()
        .der()
        .to_vec()
}

fn signed_hap(dir: &Path, cert: &[u8]) -> std::path::PathBuf {
    let path = dir.join("app.hap");
    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut cursor);
        let options = zip::write::SimpleFileOptions::default();
        writer.start_file("pack.info", options).unwrap();
        writer
            .write_all(br#"{"summary":{"app":{"bundleName":"com.example.app","version":{"name":"1.0.0","code":7}},"modules":[{"mainAbility":"EntryAbility"}]}}"#)
            .unwrap();
        writer.finish().unwrap();
    }
    fs::write(&path, inject_signature(&cursor.into_inner(), cert)).unwrap();
    path
}

fn inject_signature(zip_bytes: &[u8], cert: &[u8]) -> Vec<u8> {
    let eocd = zip_bytes.windows(4).rposition(|mark| mark == [0x50, 0x4b, 0x05, 0x06]).unwrap();
    let cd_offset = u32::from_le_bytes(zip_bytes[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
    let pair_len = (4 + cert.len()) as u64;
    let mut pairs = Vec::new();
    pairs.extend_from_slice(&pair_len.to_le_bytes());
    pairs.extend_from_slice(&0x7109_871a_u32.to_le_bytes());
    pairs.extend_from_slice(cert);
    let block_size = (pairs.len() + 8 + 16) as u64;
    let mut block = Vec::new();
    block.extend_from_slice(&block_size.to_le_bytes());
    block.extend_from_slice(&pairs);
    block.extend_from_slice(&block_size.to_le_bytes());
    block.extend_from_slice(b"Hap Sig Block 42");
    let mut output = Vec::new();
    output.extend_from_slice(&zip_bytes[..cd_offset]);
    output.extend_from_slice(&block);
    output.extend_from_slice(&zip_bytes[cd_offset..eocd]);
    let mut eocd_bytes = zip_bytes[eocd..].to_vec();
    eocd_bytes[16..20].copy_from_slice(&((cd_offset + block.len()) as u32).to_le_bytes());
    output.extend_from_slice(&eocd_bytes);
    output
}
