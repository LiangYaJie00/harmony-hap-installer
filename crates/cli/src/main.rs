use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use harmony_hap_cli::{find_config_dir, find_vendor_dir, Installer};
use harmony_hap_storage::Layout;

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        None | Some("help") | Some("--help") | Some("-h") => {
            print_usage();
            ExitCode::SUCCESS
        }
        Some("doctor") => show(open().map(|installer| format!("{:#?}", debug_doctor(&installer)))),
        Some("resolve") => show(resolve(args)),
        Some("devices") => show(open().and_then(|installer| Ok(format!("{:#?}", installer.devices()?)))),
        Some("install") => show(install(args)),
        Some("verify-installed") => show(verify_installed(args)),
        Some("cleanup") => show(open().and_then(|installer| installer.cleanup().map(|_| "已按策略清理缓存、历史和日志".to_string()))),
        Some(other) => {
            eprintln!("未知命令: {other}");
            print_usage();
            ExitCode::from(2)
        }
    }
}

fn print_usage() {
    println!(
        "\
HHI {version}

用法:
  installer doctor
  installer resolve --url <download-url>
  installer resolve --qr-image <image-file>
  installer devices
  installer install --artifact <local-hap> --target <device-id> --confirm
  installer verify-installed --target <device-id> --bundle <bundle-name>
  installer cleanup",
        version = env!("CARGO_PKG_VERSION")
    );
}

fn open() -> Result<Installer, harmony_hap_core::InstallError> {
    let data = env::var_os("HARMONY_HAP_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| Layout::system_default().root);
    Installer::open_at(&find_config_dir(), &find_vendor_dir(), &data)
}

fn debug_doctor(installer: &Installer) -> harmony_hap_cli::DoctorView {
    installer.doctor()
}

fn resolve(mut args: impl Iterator<Item = String>) -> Result<String, harmony_hap_core::InstallError> {
    let installer = open()?;
    let flag = args.next().unwrap_or_default();
    let value = args.next().unwrap_or_default();
    let outcome = match flag.as_str() {
        "--url" => installer.resolve_url(&value)?,
        "--qr-image" => installer.resolve_qr(&std::fs::read(&value).map_err(|err| harmony_hap_core::InstallError::new(harmony_hap_core::ErrorCode::SourceInvalid, err.to_string()))?)?,
        "--local" => {
            return Ok(format!("{:#?}", installer.resolve_local(std::path::Path::new(&value))?));
        }
        _ => return Err(harmony_hap_core::InstallError::new(harmony_hap_core::ErrorCode::SourceInvalid, "请使用 --url、--qr-image 或 --local")),
    };
    Ok(format!("{outcome:#?}"))
}

fn install(args: impl Iterator<Item = String>) -> Result<String, harmony_hap_core::InstallError> {
    let mut artifact = None;
    let mut target = None;
    let mut confirm = false;
    let mut tokens = args.peekable();
    while let Some(token) = tokens.next() {
        match token.as_str() {
            "--artifact" => artifact = tokens.next(),
            "--target" => target = tokens.next(),
            "--confirm" => confirm = true,
            other => return Err(harmony_hap_core::InstallError::new(harmony_hap_core::ErrorCode::SourceInvalid, other)),
        }
    }
    let installer = open()?;
    let artifact = artifact.ok_or_else(|| harmony_hap_core::InstallError::new(harmony_hap_core::ErrorCode::SourceInvalid, "缺少 --artifact"))?;
    let target = target.ok_or_else(|| harmony_hap_core::InstallError::new(harmony_hap_core::ErrorCode::SourceInvalid, "缺少 --target"))?;
    let view = installer.resolve_local(std::path::Path::new(&artifact))?;
    let result = installer.install(&view.sha256, &target, confirm)?;
    Ok(format!("{result:#?}"))
}

fn verify_installed(args: impl Iterator<Item = String>) -> Result<String, harmony_hap_core::InstallError> {
    let mut target = None;
    let mut bundle = None;
    let mut tokens = args.peekable();
    while let Some(token) = tokens.next() {
        match token.as_str() {
            "--target" => target = tokens.next(),
            "--bundle" => bundle = tokens.next(),
            other => return Err(harmony_hap_core::InstallError::new(harmony_hap_core::ErrorCode::SourceInvalid, other)),
        }
    }
    let installer = open()?;
    let target = target.unwrap_or_default();
    let bundle = bundle.unwrap_or_default();
    installer.installed_version(&target, &bundle)
}

fn show(result: Result<String, harmony_hap_core::InstallError>) -> ExitCode {
    match result {
        Ok(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            if !error.diagnostic.is_empty() {
                eprintln!("{}", error.diagnostic);
            }
            ExitCode::from(1)
        }
    }
}
