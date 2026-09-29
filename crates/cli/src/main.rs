use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use harmony_hap_core::{load_policies, PolicyError};

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        None | Some("help") | Some("--help") | Some("-h") => {
            print_usage();
            ExitCode::SUCCESS
        }
        Some("doctor") => doctor(),
        Some("resolve" | "devices" | "install" | "verify-installed") => {
            eprintln!("该命令尚未实现");
            ExitCode::from(3)
        }
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
harmony-hap-installer {version}

用法:
  installer doctor
  installer resolve
  installer devices
  installer install
  installer verify-installed",
        version = env!("CARGO_PKG_VERSION")
    );
}

fn doctor() -> ExitCode {
    let dir = config_dir();
    let policies = match load_policies(&dir) {
        Ok(policies) => policies,
        Err(PolicyError::NotFound) => {
            eprintln!("找不到配置目录: {}", dir.display());
            return ExitCode::from(1);
        }
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    let report = policies.report();
    println!("配置目录: {}", dir.display());
    println!("HDC 随包分发: {}", policies.hdc.redistribute_hdc);
    println!(
        "允许的 HDC 版本: {}",
        policies
            .hdc
            .allowed_versions
            .iter()
            .map(|version| version.version.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    if report.gaps.is_empty() {
        println!("安装策略: 已齐备");
        return ExitCode::SUCCESS;
    }
    println!("安装策略: 尚未齐备");
    for gap in &report.gaps {
        println!("- {}", gap.message());
    }
    ExitCode::SUCCESS
}

fn config_dir() -> PathBuf {
    if let Some(dir) = env::var_os("HARMONY_HAP_INSTALLER_CONFIG") {
        return PathBuf::from(dir);
    }
    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let direct = cwd.join("config");
    if direct.join("domains.json").is_file() {
        return direct;
    }
    cwd.join("config")
}
