#[tauri::command]
fn policy_gaps() -> Result<Vec<String>, String> {
    let dir = std::env::current_dir().map_err(|err| err.to_string())?;
    let policies =
        harmony_hap_core::load_policies(&dir.join("config")).map_err(|err| err.to_string())?;
    Ok(policies
        .report()
        .gaps
        .iter()
        .map(|gap| gap.message().to_string())
        .collect())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![policy_gaps])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
