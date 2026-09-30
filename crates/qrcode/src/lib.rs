use harmony_hap_core::{ErrorCode, InstallError};

pub fn decode_qr_bytes(bytes: &[u8]) -> Result<String, InstallError> {
    let image = image::load_from_memory(bytes)
        .map_err(|_| InstallError::new(ErrorCode::SourceInvalid, "无法读取二维码图片"))?;
    let luma = image.to_luma8();
    let width = luma.width();
    let height = luma.height();
    let results = rxing::helpers::detect_multiple_in_luma(luma.into_raw(), width, height)
        .map_err(|_| InstallError::new(ErrorCode::SourceInvalid, "无法识别二维码，请重新截图或粘贴链接"))?;
    let texts: Vec<String> = results.into_iter().map(|item| item.getText().to_string()).filter(|text| !text.is_empty()).collect();
    match texts.len() {
        0 => Err(InstallError::new(ErrorCode::SourceInvalid, "无法识别二维码，请重新截图或粘贴链接")),
        1 => Ok(texts.into_iter().next().unwrap()),
        _ => Err(InstallError::new(ErrorCode::SourceInvalid, "图片里有多个二维码，请重新截取只包含一个码的图片")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_one_https_qr_and_rejects_empty_image() {
        let code = qrcode::QrCode::new(b"https://download.example/app.hap").unwrap();
        let image = code.render::<image::Luma<u8>>().min_dimensions(240, 240).build();
        let mut png = std::io::Cursor::new(Vec::new());
        image.write_with_encoder(image::codecs::png::PngEncoder::new(&mut png)).unwrap();
        let text = decode_qr_bytes(png.get_ref()).unwrap();
        assert_eq!(text, "https://download.example/app.hap");
        assert_eq!(decode_qr_bytes(&[0, 1, 2, 3]).unwrap_err().code, ErrorCode::SourceInvalid);
    }
}
