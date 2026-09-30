use std::sync::Mutex;

use harmony_hap_cli::{find_config_dir, find_vendor_dir, Installer};
use harmony_hap_core::{ErrorCode, InstallError};
use harmony_hap_storage::Layout;

struct AppState {
    installer: Mutex<Result<Installer, String>>,
}

fn with_installer<T>(
    state: &AppState,
    run: impl FnOnce(&Installer) -> Result<T, InstallError>,
) -> Result<T, InstallError> {
    let guard = state
        .installer
        .lock()
        .map_err(|err| InstallError::new(ErrorCode::InstallFailed, err.to_string()))?;
    match guard.as_ref() {
        Ok(installer) => run(installer),
        Err(message) => Err(locked_installer_error(message)),
    }
}

fn with_installer_mut<T>(
    state: &AppState,
    run: impl FnOnce(&mut Installer) -> Result<T, InstallError>,
) -> Result<T, InstallError> {
    let mut guard = state
        .installer
        .lock()
        .map_err(|err| InstallError::new(ErrorCode::InstallFailed, err.to_string()))?;
    match guard.as_mut() {
        Ok(installer) => run(installer),
        Err(message) => Err(locked_installer_error(message)),
    }
}

fn locked_installer_error(message: &str) -> InstallError {
    InstallError {
        code: ErrorCode::HdcNotFound,
        message: message.to_string(),
        suggestion: String::new(),
        diagnostic: String::new(),
    }
}

#[tauri::command]
fn doctor(state: tauri::State<'_, AppState>) -> Result<harmony_hap_cli::DoctorView, InstallError> {
    with_installer(&state, |installer| Ok(installer.doctor()))
}

#[tauri::command]
fn identity(state: tauri::State<'_, AppState>) -> Result<harmony_hap_core::IdentityPolicy, InstallError> {
    with_installer(&state, |installer| Ok(installer.identity()))
}

#[tauri::command]
fn save_identity(
    state: tauri::State<'_, AppState>,
    policy: harmony_hap_core::IdentityPolicy,
) -> Result<harmony_hap_core::IdentityPolicy, InstallError> {
    with_installer_mut(&state, |installer| installer.save_identity(policy))
}

#[tauri::command]
fn resolve_url(state: tauri::State<'_, AppState>, url: String) -> Result<harmony_hap_cli::ResolveOutcome, InstallError> {
    with_installer(&state, |installer| installer.resolve_url(&url))
}

#[tauri::command]
fn resolve_qr(state: tauri::State<'_, AppState>, bytes: Vec<u8>) -> Result<harmony_hap_cli::ResolveOutcome, InstallError> {
    with_installer(&state, |installer| installer.resolve_qr(&bytes))
}

#[tauri::command]
fn resolve_local_bytes(
    state: tauri::State<'_, AppState>,
    file_name: String,
    bytes: Vec<u8>,
) -> Result<harmony_hap_cli::ArtifactView, InstallError> {
    with_installer(&state, |installer| installer.resolve_local_bytes(&file_name, &bytes))
}

#[tauri::command]
fn devices(state: tauri::State<'_, AppState>) -> Result<harmony_hap_cli::DevicesView, InstallError> {
    with_installer(&state, |installer| installer.devices())
}

#[tauri::command]
fn install(
    state: tauri::State<'_, AppState>,
    sha256: String,
    device_id: String,
    confirm: bool,
) -> Result<harmony_hap_cli::InstallView, InstallError> {
    with_installer(&state, |installer| installer.install(&sha256, &device_id, confirm))
}

#[tauri::command]
fn launch(
    state: tauri::State<'_, AppState>,
    device_id: String,
    bundle_name: String,
    ability: String,
) -> Result<(), InstallError> {
    with_installer(&state, |installer| installer.launch(&device_id, &bundle_name, &ability))
}

#[tauri::command]
fn history(state: tauri::State<'_, AppState>) -> Result<Vec<harmony_hap_storage::HistoryItem>, InstallError> {
    with_installer(&state, |installer| installer.history())
}

#[tauri::command]
fn packages(state: tauri::State<'_, AppState>) -> Result<Vec<harmony_hap_storage::PackageView>, InstallError> {
    with_installer(&state, |installer| installer.packages())
}

#[tauri::command]
fn open_cached(state: tauri::State<'_, AppState>, sha256: String) -> Result<harmony_hap_cli::ArtifactView, InstallError> {
    with_installer(&state, |installer| installer.open_cached(&sha256))
}

#[tauri::command]
fn forget_package(state: tauri::State<'_, AppState>, sha256: String) -> Result<(), InstallError> {
    with_installer(&state, |installer| installer.forget_package(&sha256))
}

#[tauri::command]
fn diagnostics(state: tauri::State<'_, AppState>) -> Result<String, InstallError> {
    with_installer(&state, |installer| installer.diagnostics())
}

#[tauri::command]
fn open_url(url: String) -> Result<(), String> {
    open::that(url).map_err(|err| err.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let installer = Installer::open_at(&find_config_dir(), &find_vendor_dir(), &Layout::system_default().root)
        .map_err(|err| err.to_string());
    tauri::Builder::default()
        .manage(AppState { installer: Mutex::new(installer) })
        .invoke_handler(tauri::generate_handler![
            doctor,
            identity,
            save_identity,
            resolve_url,
            resolve_qr,
            resolve_local_bytes,
            devices,
            install,
            launch,
            history,
            packages,
            open_cached,
            forget_package,
            diagnostics,
            open_url
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
