const COMMANDS: &[&str] = &[
    "atlas_status",
    "atlas_connect",
    "atlas_read",
    "atlas_prepare",
    "atlas_execute",
    "atlas_cancel",
    "atlas_money",
    "atlas_agent",
    "atlas_document",
    "atlas_qr",
    "atlas_config",
    "atlas_launch",
    "atlas_activity",
    "atlas_pending_links",
    "atlas_copy",
    "atlas_desktop",
];
fn main() {
    let manifest = tauri_build::AppManifest::new().commands(COMMANDS);
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(manifest))
        .expect("Atlas permission manifest or build configuration invalid");
}
