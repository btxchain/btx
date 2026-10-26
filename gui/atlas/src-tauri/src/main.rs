#![forbid(unsafe_code)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod commands;
mod host;
mod neuronlab;
use host::Host;
use std::sync::Arc;
use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    Manager, WebviewUrl, WebviewWindowBuilder,
};
use tauri_plugin_deep_link::DeepLinkExt;
fn trusted_url(url: &tauri::Url) -> bool {
    url.scheme() == "tauri" && url.host_str() == Some("localhost")
        || matches!(url.scheme(), "http" | "https") && url.host_str() == Some("tauri.localhost")
}
fn main() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            if let Some(h) = app.try_state::<Arc<Host>>() {
                for arg in args.iter().skip(1) {
                    h.receive_link(arg);
                }
            }
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.show();
                let _ = w.set_focus();
            }
        }))
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .invoke_handler(tauri::generate_handler![
            commands::atlas_status,
            commands::atlas_connect,
            commands::atlas_read,
            commands::atlas_prepare,
            commands::atlas_execute,
            commands::atlas_cancel,
            commands::atlas_money,
            commands::atlas_agent,
            commands::atlas_document,
            commands::atlas_qr,
            commands::atlas_config,
            commands::atlas_launch,
            commands::atlas_activity,
            commands::atlas_pending_links,
            commands::atlas_copy,
            commands::atlas_desktop,
            neuronlab::atlas_neuronlab,
            neuronlab::atlas_neuronlab_cancel
        ])
        .setup(|app| {
            let dir = app.path().app_local_data_dir()?;
            let host = Arc::new(Host::new(dir.join("audit/operations.jsonl"))?);
            for arg in std::env::args().skip(1) {
                host.receive_link(&arg);
            }
            app.manage(host.clone());
            if let Ok(Some(urls)) = app.deep_link().get_current() {
                for url in urls {
                    host.receive_link(url.as_str());
                }
            }
            app.deep_link().on_open_url(move |event| {
                for url in event.urls() {
                    host.receive_link(url.as_str());
                }
            });
            let window =
                WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                    .title("BTX Atlas · Source candidate")
                    .inner_size(1440.0, 940.0)
                    .min_inner_size(740.0, 560.0)
                    .on_navigation(trusted_url)
                    .devtools(cfg!(debug_assertions))
                    .build()?;
            commands::restore_window_bounds(&window);
            let show = MenuItem::with_id(app, "show", "Open BTX Atlas", true, None::<&str>)?;
            let quit = MenuItem::with_id(
                app,
                "quit",
                "Quit Atlas (leave node running)",
                true,
                None::<&str>,
            )?;
            let menu = Menu::with_items(app, &[&show, &quit])?;
            let mut tray = TrayIconBuilder::with_id("atlas").menu(&menu).on_menu_event(
                |app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                    // Exits Atlas only. Does not signal btxd.
                    "quit" => app.exit(0),
                    _ => {}
                },
            );
            if let Some(icon) = app.default_window_icon() {
                tray = tray.icon(icon.clone());
            }
            // A missing system tray must not block startup. The icon is retained so it can be shown again.
            let tray_icon = match tray.build(app) {
                Ok(icon) => {
                    if !commands::show_tray_enabled(app.handle()) {
                        let _ = icon.set_visible(false);
                    }
                    Some(icon)
                }
                Err(_) => None,
            };
            app.manage(tray_icon);
            Ok(())
        })
        .build(tauri::generate_context!());
    match app {
        Ok(app) => app.run(|app, event| {
            let tauri::RunEvent::WindowEvent { label, event, .. } = event else {
                return;
            };
            if label != "main" {
                return;
            }
            if let Some(window) = app.get_webview_window("main") {
                match &event {
                    tauri::WindowEvent::CloseRequested { .. }
                    | tauri::WindowEvent::Resized(_)
                    | tauri::WindowEvent::Moved(_) => commands::save_window_bounds(&window),
                    _ => {}
                }
            }
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if commands::minimize_on_close_enabled(app) {
                    api.prevent_close();
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window.hide();
                    }
                }
            }
        }),
        Err(e) => {
            eprintln!("BTX Atlas failed closed during startup: {e}");
            std::process::exit(1);
        }
    }
}
