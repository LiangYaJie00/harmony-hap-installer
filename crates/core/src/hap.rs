use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use sha2::{Digest, Sha256};
use zip::ZipArchive;

use crate::error::{ErrorCode, InstallError};
use crate::policy::{BundlePolicy, SigningPolicy};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HapInfo {
    pub bundle_name: String,
    pub version_name: String,
    pub version_code: u32,
    pub ability_name: Option<String>,
    pub compatible_api: Option<u32>,
    pub sha256: String,
    pub size: u64,
    pub certificate_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HapTrust {
    PlatformHash,
    LocalHashOnly,
}

pub struct VerifyRequest<'a> {
    pub expected_size: Option<u64>,
    pub expected_sha256: Option<&'a str>,
    pub expected_bundle: Option<&'a str>,
    pub expected_version_name: Option<&'a str>,
    pub expected_version_code: Option<u32>,
    pub bundles: &'a BundlePolicy,
    pub signing: &'a SigningPolicy,
    pub enforce_identity: bool,
}

pub fn verify_hap(path: &Path, request: &VerifyRequest<'_>) -> Result<(HapInfo, HapTrust), InstallError> {
    if path.extension().and_then(|ext| ext.to_str()) != Some("hap") {
        return Err(InstallError::new(ErrorCode::SourceInvalid, "只接受 .hap 文件"));
    }
    let file_name = path.file_name().and_then(|name| name.to_str()).unwrap_or("");
    if file_name.contains('/') || file_name.contains('\\') || file_name.contains("..") {
        return Err(InstallError::new(ErrorCode::SourceInvalid, "文件名不合法"));
    }
    let size = std::fs::metadata(path)
        .map_err(|err| InstallError::new(ErrorCode::SourceInvalid, err.to_string()))?
        .len();
    if let Some(expected) = request.expected_size {
        if size != expected {
            return Err(InstallError::new(
                ErrorCode::SizeMismatch,
                format!("实际 {size}，预期 {expected}"),
            ));
        }
    }
    let sha256 = hash_file(path)?;
    let trust = match request.expected_sha256 {
        Some(expected) if !expected.eq_ignore_ascii_case(&sha256) => {
            return Err(InstallError::new(ErrorCode::HashMismatch, ""));
        }
        Some(_) => HapTrust::PlatformHash,
        None => HapTrust::LocalHashOnly,
    };
    let mut parsed = parse_hap(path)?;
    if let Some(bundle) = request.expected_bundle {
        if parsed.bundle_name != bundle {
            return Err(InstallError::new(ErrorCode::SourceInvalid, "包名和 manifest 不一致"));
        }
    }
    if let Some(version_name) = request.expected_version_name {
        if parsed.version_name != version_name {
            return Err(InstallError::new(ErrorCode::SourceInvalid, "版本名和 manifest 不一致"));
        }
    }
    if let Some(version_code) = request.expected_version_code {
        if parsed.version_code != version_code {
            return Err(InstallError::new(ErrorCode::SourceInvalid, "版本号和 manifest 不一致"));
        }
    }
    if request.enforce_identity {
        if request.bundles.allowed_bundle_names.is_empty() {
            return Err(InstallError::new(
                ErrorCode::SourceInvalid,
                "已开启来源校验，请先在高级设置填写允许的包名",
            ));
        }
        if !request.bundles.allowed_bundle_names.iter().any(|name| name == &parsed.bundle_name) {
            return Err(InstallError::new(
                ErrorCode::SourceInvalid,
                format!("包名 {} 不在允许列表", parsed.bundle_name),
            ));
        }
        if request.signing.certificates.is_empty() {
            return Err(InstallError::new(
                ErrorCode::SignatureInvalid,
                "已开启来源校验，请先在高级设置填写证书指纹和到期日",
            ));
        }
        let now = chrono::Utc::now().date_naive();
        let fingerprints = certificate_fingerprints(path)?;
        let matched = request.signing.certificates.iter().find(|cert| {
            fingerprints
                .iter()
                .any(|fingerprint| cert.fingerprint_sha256.eq_ignore_ascii_case(fingerprint))
                && chrono::NaiveDate::parse_from_str(&cert.not_after, "%Y-%m-%d")
                    .map(|date| date >= now)
                    .unwrap_or(false)
        });
        let Some(cert) = matched else {
            return Err(InstallError::new(ErrorCode::SignatureInvalid, ""));
        };
        parsed.certificate_sha256 = cert.fingerprint_sha256.to_ascii_lowercase();
    }
    Ok((
        HapInfo {
            sha256,
            size,
            ..parsed
        },
        trust,
    ))
}

fn hash_file(path: &Path) -> Result<String, InstallError> {
    let mut file = File::open(path).map_err(|err| InstallError::new(ErrorCode::SourceInvalid, err.to_string()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|err| InstallError::new(ErrorCode::SourceInvalid, err.to_string()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn parse_hap(path: &Path) -> Result<HapInfo, InstallError> {
    let file = File::open(path).map_err(|err| InstallError::new(ErrorCode::SourceInvalid, err.to_string()))?;
    let mut archive = ZipArchive::new(file).map_err(|_| InstallError::new(ErrorCode::SourceInvalid, "文件不是 HAP"))?;
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|_| InstallError::new(ErrorCode::SourceInvalid, "无法读取 HAP"))?;
        if entry.name().ends_with(".hap") || entry.name().ends_with(".app") {
            return Err(InstallError::new(ErrorCode::SourceInvalid, "这是 APP Pack，不能用本工具安装"));
        }
    }
    let mut pack = archive
        .by_name("pack.info")
        .map_err(|_| InstallError::new(ErrorCode::SourceInvalid, "HAP 里没有 pack.info"))?;
    let mut text = String::new();
    pack.read_to_string(&mut text)
        .map_err(|_| InstallError::new(ErrorCode::SourceInvalid, "无法读取 pack.info"))?;
    drop(pack);
    let json: serde_json::Value = serde_json::from_str(&text)
        .map_err(|_| InstallError::new(ErrorCode::SourceInvalid, "pack.info 不是 JSON"))?;
    let app = json
        .pointer("/summary/app")
        .ok_or_else(|| InstallError::new(ErrorCode::SourceInvalid, "pack.info 缺少应用信息"))?;
    let bundle_name = app
        .get("bundleName")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string();
    let version_name = app
        .pointer("/version/name")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string();
    let version_code = app
        .pointer("/version/code")
        .and_then(|value| value.as_u64())
        .unwrap_or(0) as u32;
    if bundle_name.is_empty() || version_name.is_empty() || version_code == 0 {
        return Err(InstallError::new(
            ErrorCode::SourceInvalid,
            "无法从 HAP 读取包名或版本，请改用带 manifest 的平台链接",
        ));
    }
    let ability_name = json
        .pointer("/summary/modules/0/mainAbility")
        .and_then(|value| value.as_str())
        .map(str::to_string);
    let compatible_api = app
        .pointer("/apiVersion/compatible")
        .or_else(|| app.get("compatibleSdkVersion"))
        .and_then(|value| value.as_u64())
        .filter(|value| *value <= 100)
        .map(|value| value as u32);
    let certificate_sha256 = certificate_fingerprint(path).unwrap_or_default();
    Ok(HapInfo {
        bundle_name,
        version_name,
        version_code,
        ability_name,
        compatible_api,
        sha256: String::new(),
        size: 0,
        certificate_sha256,
    })
}

fn certificate_fingerprint(path: &Path) -> Result<String, InstallError> {
    certificate_fingerprints(path)?
        .into_iter()
        .next_back()
        .ok_or_else(|| InstallError::new(ErrorCode::SignatureInvalid, "签名块里没有证书"))
}

fn certificate_fingerprints(path: &Path) -> Result<Vec<String>, InstallError> {
    let mut file = File::open(path).map_err(|err| InstallError::new(ErrorCode::SignatureInvalid, err.to_string()))?;
    let length = file
        .seek(SeekFrom::End(0))
        .map_err(|err| InstallError::new(ErrorCode::SignatureInvalid, err.to_string()))?;
    let eocd = find_eocd(&mut file, length)?;
    let cd_offset = eocd.cd_offset as u64;
    if cd_offset >= 20 {
        file.seek(SeekFrom::Start(cd_offset - 20))
            .map_err(|err| InstallError::new(ErrorCode::SignatureInvalid, err.to_string()))?;
        let mut prefix = [0_u8; 16];
        file.read_exact(&mut prefix)
            .map_err(|_| InstallError::new(ErrorCode::SignatureInvalid, "无法读取签名块"))?;
        if &prefix == b"<hap sign block>" {
            return fingerprints_from_profile_block(&mut file, cd_offset);
        }
    }
    legacy_certificate_fingerprints(&mut file, cd_offset)
}

fn fingerprints_from_profile_block(file: &mut File, cd_offset: u64) -> Result<Vec<String>, InstallError> {
    if cd_offset < 28 {
        return Err(InstallError::new(ErrorCode::SignatureInvalid, "签名块长度无效"));
    }
    file.seek(SeekFrom::Start(cd_offset - 28))
        .map_err(|err| InstallError::new(ErrorCode::SignatureInvalid, err.to_string()))?;
    let mut size_buf = [0_u8; 8];
    file.read_exact(&mut size_buf)
        .map_err(|_| InstallError::new(ErrorCode::SignatureInvalid, "签名块长度无效"))?;
    let block_size = u64::from_le_bytes(size_buf) as usize;
    if block_size == 0 || block_size > 8 * 1024 * 1024 || cd_offset < 28 + block_size as u64 {
        return Err(InstallError::new(ErrorCode::SignatureInvalid, "签名块长度无效"));
    }
    file.seek(SeekFrom::Start(cd_offset - 28 - block_size as u64))
        .map_err(|err| InstallError::new(ErrorCode::SignatureInvalid, err.to_string()))?;
    let mut chunk = vec![0_u8; block_size];
    file.read_exact(&mut chunk)
        .map_err(|_| InstallError::new(ErrorCode::SignatureInvalid, "无法读取签名块"))?;
    let fingerprints = pem_fingerprints(&chunk);
    if fingerprints.is_empty() {
        return Err(InstallError::new(ErrorCode::SignatureInvalid, "签名块里没有证书"));
    }
    Ok(fingerprints)
}

fn pem_fingerprints(bytes: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(bytes).replace("\\n", "\n");
    let mut fingerprints = Vec::new();
    let mut rest = text.as_str();
    let begin = "-----BEGIN CERTIFICATE-----";
    let end_mark = "-----END CERTIFICATE-----";
    while let Some(start) = rest.find(begin) {
        rest = &rest[start + begin.len()..];
        let Some(end) = rest.find(end_mark) else {
            break;
        };
        let body: String = rest[..end]
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '+' || *ch == '/' || *ch == '=')
            .collect();
        if let Some(der) = decode_base64(&body) {
            fingerprints.push(hex::encode(Sha256::digest(der)));
        }
        rest = &rest[end..];
    }
    fingerprints
}

fn decode_base64(input: &str) -> Option<Vec<u8>> {
    fn value(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes = input.as_bytes();
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return None;
    }
    let mut output = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let a = value(chunk[0])?;
        let b = value(chunk[1])?;
        output.push((a << 2) | (b >> 4));
        if chunk[2] != b'=' {
            let c = value(chunk[2])?;
            output.push((b << 4) | (c >> 2));
            if chunk[3] != b'=' {
                let d = value(chunk[3])?;
                output.push((c << 6) | d);
            }
        }
    }
    Some(output)
}

fn legacy_certificate_fingerprints(file: &mut File, cd_offset: u64) -> Result<Vec<String>, InstallError> {
    if cd_offset < 32 {
        return Err(InstallError::new(ErrorCode::SignatureInvalid, "没有签名块"));
    }
    file.seek(SeekFrom::Start(cd_offset - 16))
        .map_err(|err| InstallError::new(ErrorCode::SignatureInvalid, err.to_string()))?;
    let mut magic = [0_u8; 16];
    file.read_exact(&mut magic)
        .map_err(|_| InstallError::new(ErrorCode::SignatureInvalid, "无法读取签名块"))?;
    if &magic != b"Hap Sig Block 42" && &magic != b"APK Sig Block 42" {
        return Err(InstallError::new(ErrorCode::SignatureInvalid, "签名块无效"));
    }
    file.seek(SeekFrom::Start(cd_offset - 24))
        .map_err(|err| InstallError::new(ErrorCode::SignatureInvalid, err.to_string()))?;
    let mut size_buf = [0_u8; 8];
    file.read_exact(&mut size_buf)
        .map_err(|_| InstallError::new(ErrorCode::SignatureInvalid, "签名块长度无效"))?;
    let block_size = u64::from_le_bytes(size_buf);
    if block_size < 24 || cd_offset < block_size + 8 {
        return Err(InstallError::new(ErrorCode::SignatureInvalid, "签名块长度无效"));
    }
    let block_start = cd_offset - block_size - 8;
    let pairs_len = (block_size - 24) as usize;
    file.seek(SeekFrom::Start(block_start + 8))
        .map_err(|err| InstallError::new(ErrorCode::SignatureInvalid, err.to_string()))?;
    let mut pairs = vec![0_u8; pairs_len];
    file.read_exact(&mut pairs)
        .map_err(|_| InstallError::new(ErrorCode::SignatureInvalid, "无法读取签名块"))?;
    let cert = first_certificate(&pairs).ok_or_else(|| InstallError::new(ErrorCode::SignatureInvalid, "签名块里没有证书"))?;
    Ok(vec![hex::encode(Sha256::digest(cert))])
}

struct Eocd {
    cd_offset: u32,
}

fn find_eocd(file: &mut File, length: u64) -> Result<Eocd, InstallError> {
    let scan = length.min(65_557);
    file.seek(SeekFrom::Start(length - scan))
        .map_err(|err| InstallError::new(ErrorCode::SignatureInvalid, err.to_string()))?;
    let mut tail = vec![0_u8; scan as usize];
    file.read_exact(&mut tail)
        .map_err(|_| InstallError::new(ErrorCode::SignatureInvalid, "无法读取 ZIP 目录"))?;
    let mut offset = None;
    for index in (0..tail.len().saturating_sub(21)).rev() {
        if tail[index..index + 4] == [0x50, 0x4b, 0x05, 0x06] {
            offset = Some(index);
            break;
        }
    }
    let index = offset.ok_or_else(|| InstallError::new(ErrorCode::SignatureInvalid, "不是有效的 HAP"))?;
    let cd_offset = u32::from_le_bytes(tail[index + 16..index + 20].try_into().unwrap());
    Ok(Eocd { cd_offset })
}

fn first_certificate(pairs: &[u8]) -> Option<&[u8]> {
    let mut cursor = 0;
    while cursor + 12 <= pairs.len() {
        let pair_len = u64::from_le_bytes(pairs[cursor..cursor + 8].try_into().ok()?) as usize;
        if pair_len < 4 || cursor + 8 + pair_len > pairs.len() {
            break;
        }
        let value = &pairs[cursor + 12..cursor + 8 + pair_len];
        if let Some(cert) = find_der_certificate(value) {
            return Some(cert);
        }
        cursor += 8 + pair_len;
    }
    find_der_certificate(pairs)
}

fn find_der_certificate(bytes: &[u8]) -> Option<&[u8]> {
    let mut index = 0;
    while index + 4 < bytes.len() {
        if bytes[index] == 0x30 && bytes[index + 1] == 0x82 {
            let len = u16::from_be_bytes([bytes[index + 2], bytes[index + 3]]) as usize;
            let end = index + 4 + len;
            if end <= bytes.len() && len > 64 {
                return Some(&bytes[index..end]);
            }
        }
        index += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn cert_der() -> Vec<u8> {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["dev.example".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        cert.der().to_vec()
    }

    fn hap_with_cert(dir: &Path, name: &str, cert: &[u8], extra_entry: Option<&str>) -> std::path::PathBuf {
        let path = dir.join(name);
        let mut cursor = std::io::Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut cursor);
            let options = zip::write::SimpleFileOptions::default();
            writer.start_file("pack.info", options).unwrap();
            writer
                .write_all(
                    br#"{"summary":{"app":{"bundleName":"com.example.app","version":{"name":"1.0.0","code":7},"apiVersion":{"compatible":14}},"modules":[{"mainAbility":"EntryAbility"}]}}"#,
                )
                .unwrap();
            if let Some(entry) = extra_entry {
                writer.start_file(entry, options).unwrap();
                writer.write_all(b"pk").unwrap();
            }
            writer.finish().unwrap();
        }
        let bytes = cursor.into_inner();
        std::fs::write(&path, inject_signature(&bytes, cert)).unwrap();
        path
    }

    fn inject_signature(zip_bytes: &[u8], cert: &[u8]) -> Vec<u8> {
        let eocd = zip_bytes.windows(4).rposition(|mark| mark == [0x50, 0x4b, 0x05, 0x06]).unwrap();
        let cd_offset = u32::from_le_bytes(zip_bytes[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
        let mut value = Vec::new();
        value.extend_from_slice(cert);
        let pair_len = (4 + value.len()) as u64;
        let mut pairs = Vec::new();
        pairs.extend_from_slice(&pair_len.to_le_bytes());
        pairs.extend_from_slice(&0x7109_871a_u32.to_le_bytes());
        pairs.extend_from_slice(&value);
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
        let new_offset = (cd_offset + block.len()) as u32;
        eocd_bytes[16..20].copy_from_slice(&new_offset.to_le_bytes());
        output.extend_from_slice(&eocd_bytes);
        output
    }

    #[test]
    fn accepts_signed_hap_and_rejects_app_pack() {
        let dir = std::env::temp_dir().join(format!("hap-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let der = cert_der();
        let fingerprint = hex::encode(sha2::Sha256::digest(&der));
        let hap = hap_with_cert(&dir, "app.hap", &der, None);
        let signing = SigningPolicy {
            schema_version: 1,
            certificates: vec![crate::policy::SigningCertificate {
                fingerprint_sha256: fingerprint,
                not_after: "2099-01-01".into(),
            }],
        };
        let bundles = BundlePolicy {
            schema_version: 1,
            allowed_bundle_names: vec!["com.example.app".into()],
        };
        let (info, trust) = verify_hap(
            &hap,
            &VerifyRequest {
                expected_size: None,
                expected_sha256: None,
                expected_bundle: None,
                expected_version_name: None,
                expected_version_code: None,
                bundles: &bundles,
                signing: &signing,
                enforce_identity: true,
            },
        )
        .unwrap();
        assert_eq!(info.version_code, 7);
        assert_eq!(info.ability_name.as_deref(), Some("EntryAbility"));
        assert_eq!(trust, HapTrust::LocalHashOnly);
        let app = hap_with_cert(&dir, "pack.hap", &der, Some("entry.hap"));
        assert_eq!(
            verify_hap(
                &app,
                &VerifyRequest {
                    expected_size: None,
                    expected_sha256: None,
                    expected_bundle: None,
                    expected_version_name: None,
                    expected_version_code: None,
                    bundles: &bundles,
                    signing: &signing,
                    enforce_identity: true,
                },
            )
            .unwrap_err()
            .code,
            ErrorCode::SourceInvalid
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn accepts_hap_sign_block_profile_certificate() {
        let dir = std::env::temp_dir().join(format!("hap-sign-block-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let der = cert_der();
        let fingerprint = hex::encode(sha2::Sha256::digest(&der));
        let pem_body = encode_base64(&der);
        let escaped = pem_body
            .as_bytes()
            .chunks(64)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<_>>()
            .join("\\n");
        let profile = format!(r#"{{"distribution-certificate":"-----BEGIN CERTIFICATE-----\\n{escaped}\\n-----END CERTIFICATE-----"}}"#);
        let path = dir.join("profile.hap");
        std::fs::write(&path, inject_profile_block(&profile)).unwrap();
        let signing = SigningPolicy {
            schema_version: 1,
            certificates: vec![crate::policy::SigningCertificate {
                fingerprint_sha256: fingerprint.clone(),
                not_after: "2099-01-01".into(),
            }],
        };
        let bundles = BundlePolicy {
            schema_version: 1,
            allowed_bundle_names: vec!["com.example.app".into()],
        };
        let (info, _) = verify_hap(
            &path,
            &VerifyRequest {
                expected_size: None,
                expected_sha256: None,
                expected_bundle: None,
                expected_version_name: None,
                expected_version_code: None,
                bundles: &bundles,
                signing: &signing,
                enforce_identity: true,
            },
        )
        .unwrap();
        assert_eq!(info.certificate_sha256, fingerprint);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn skips_identity_lists_when_enforcement_is_off() {
        let dir = std::env::temp_dir().join(format!("hap-open-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let hap = hap_with_cert(&dir, "open.hap", &cert_der(), None);
        let signing = SigningPolicy { schema_version: 1, certificates: vec![] };
        let bundles = BundlePolicy { schema_version: 1, allowed_bundle_names: vec![] };
        let request = VerifyRequest {
            expected_size: None,
            expected_sha256: None,
            expected_bundle: None,
            expected_version_name: None,
            expected_version_code: None,
            bundles: &bundles,
            signing: &signing,
            enforce_identity: false,
        };
        let (info, _) = verify_hap(&hap, &request).unwrap();
        assert_eq!(info.bundle_name, "com.example.app");
        assert!(!info.certificate_sha256.is_empty());
        let error = verify_hap(
            &hap,
            &VerifyRequest {
                enforce_identity: true,
                ..request
            },
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::SourceInvalid);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn encode_base64(input: &[u8]) -> String {
        const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in input.chunks(3) {
            let a = chunk[0] as u32;
            let b = chunk.get(1).copied().unwrap_or(0) as u32;
            let c = chunk.get(2).copied().unwrap_or(0) as u32;
            let triple = (a << 16) | (b << 8) | c;
            out.push(TABLE[((triple >> 18) & 63) as usize] as char);
            out.push(TABLE[((triple >> 12) & 63) as usize] as char);
            if chunk.len() > 1 {
                out.push(TABLE[((triple >> 6) & 63) as usize] as char);
            } else {
                out.push('=');
            }
            if chunk.len() > 2 {
                out.push(TABLE[(triple & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
        out
    }

    fn inject_profile_block(profile: &str) -> Vec<u8> {
        let mut cursor = std::io::Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut cursor);
            let options = zip::write::SimpleFileOptions::default();
            writer.start_file("pack.info", options).unwrap();
            writer
                .write_all(
                    br#"{"summary":{"app":{"bundleName":"com.example.app","version":{"name":"1.0.0","code":7},"apiVersion":{"compatible":14}},"modules":[{"mainAbility":"EntryAbility"}]}}"#,
                )
                .unwrap();
            writer.finish().unwrap();
        }
        let zip_bytes = cursor.into_inner();
        let eocd = zip_bytes.windows(4).rposition(|mark| mark == [0x50, 0x4b, 0x05, 0x06]).unwrap();
        let cd_offset = u32::from_le_bytes(zip_bytes[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
        let chunk = profile.as_bytes();
        let mut output = Vec::new();
        output.extend_from_slice(&zip_bytes[..cd_offset]);
        output.extend_from_slice(chunk);
        output.extend_from_slice(&(chunk.len() as u64).to_le_bytes());
        output.extend_from_slice(b"<hap sign block>");
        output.extend_from_slice(&3_u32.to_le_bytes());
        let mut eocd_bytes = zip_bytes[eocd..].to_vec();
        eocd_bytes[16..20].copy_from_slice(&(output.len() as u32).to_le_bytes());
        output.extend_from_slice(&zip_bytes[cd_offset..eocd]);
        output.extend_from_slice(&eocd_bytes);
        output
    }
}
