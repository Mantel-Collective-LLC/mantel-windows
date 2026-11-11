use serde_json::{json, Value};
use std::time::Instant;
use tauri::{AppHandle, Manager};
use tauri_plugin_clipboard_manager::ClipboardExt;

use crate::api::{Auth, Failure, Method, Request};
use crate::{applog, commands, flavor, AppState};

type Answer = Result<Value, Failure>;

fn debug_only() -> Result<(), Failure> {
    if flavor::is_debug() {
        Ok(())
    } else {
        Err(Failure::localized("invalidInput", "invalid"))
    }
}

fn names() -> (&'static str, &'static str, &'static str) {
    if flavor::is_debug() {
        ("mantel-debug", "MantelServiceDebug → WireGuardTunnel$mantel-debug", "Mantel Debug Kill Switch")
    } else {
        ("mantel", "MantelService → WireGuardTunnel$mantel", "Mantel Kill Switch")
    }
}

async fn info(app: &AppHandle) -> Value {
    let state = app.state::<AppState>();
    let ready = commands::readiness().await.ready;
    let identity = flavor::identity();
    let (tunnel, service, firewall) = names();
    json!({
        "flavor": identity.name,
        "productName": identity.product_name,
        "appId": app.config().identifier,
        "appVersion": flavor::APP_VERSION,
        "electron": format!("Tauri {}", tauri::VERSION),
        "chrome": tauri::webview_version().unwrap_or_default(),
        "node": "",
        "v8": "",
        "platform": "win32",
        "arch": std::env::consts::ARCH.replace("x86_64", "x64").replace("aarch64", "arm64"),
        "buildTime": null,
        "commit": null,
        "packaged": !cfg!(debug_assertions),
        "elevated": ready,
        "baseUrl": flavor::api_base_url(),
        "userData": format!("%APPDATA%\\{}", identity.user_data_name),
        "tunnelName": tunnel,
        "serviceName": service,
        "firewallGroup": firewall,
        "verbose": applog::verbose(),
        "loggedIn": state.store.lock().unwrap().secrets().token.is_some(),
    })
}

#[tauri::command]
pub async fn debug_info(app: AppHandle) -> Answer {
    debug_only()?;
    Ok(info(&app).await)
}

#[tauri::command]
pub async fn debug_request_log(app: AppHandle) -> Answer {
    debug_only()?;
    Ok(Value::Array(app.state::<AppState>().api.requests.entries()))
}

#[tauri::command]
pub async fn debug_clear_request_log(app: AppHandle) -> Answer {
    debug_only()?;
    app.state::<AppState>().api.requests.clear();
    Ok(Value::Null)
}

#[tauri::command]
pub async fn debug_health_check(app: AppHandle) -> Answer {
    debug_only()?;
    let state = app.state::<AppState>();
    let started = Instant::now();
    let result = state.api.send(Request::new(Method::Get, "/api/v1/nodes").auth(Auth::None), None, state.language()).await;
    let latency = started.elapsed().as_millis() as u64;
    Ok(match result {
        Ok(nodes) => json!({
            "baseUrl": flavor::api_base_url(), "ok": true, "status": 200, "latencyMs": latency,
            "nodes": nodes.as_array().map(Vec::len), "error": null, "checkedAt": crate::now_ms()
        }),
        Err(failure) => json!({
            "baseUrl": flavor::api_base_url(), "ok": false, "status": failure.status(), "latencyMs": latency, "nodes": null,
            "error": applog::redact(&crate::strings::failure_text(state.language(), &failure)), "checkedAt": crate::now_ms()
        }),
    })
}

#[tauri::command]
pub async fn debug_set_verbose(app: AppHandle, enabled: bool) -> Answer {
    debug_only()?;
    applog::set_verbose(enabled);
    Ok(info(&app).await)
}

#[tauri::command]
pub async fn debug_copy_diagnostics(app: AppHandle) -> Answer {
    debug_only()?;
    let state = app.state::<AppState>();
    let ready = commands::readiness().await;
    let (preferences, encryption, device) = {
        let store = state.store.lock().unwrap();
        let device = store.secrets().device.as_ref().map(|device| json!({ "nodeId": device.get("nodeId"), "keySource": device.get("keySource") }));
        (store.preferences().clone(), store.encryption_available(), device)
    };
    let diagnostics = json!({
        "generatedAt": applog::iso_now(),
        "build": info(&app).await,
        "preferences": {
            "baseUrl": preferences.base_url,
            "alwaysOnKillSwitch": preferences.always_on_kill_switch,
            "lastNodeId": preferences.last_node_id,
            "language": preferences.language,
        },
        "wireguard": ready.wireguard_directory.map(|directory| json!({ "source": ready.wireguard_source, "directory": directory })),
        "encryptionAvailable": encryption,
        "device": device,
        "tunnel": state.status(),
        "requestLog": state.api.requests.entries(),
    });
    let text = applog::redact(&serde_json::to_string_pretty(&applog::redact_value(&diagnostics)).unwrap_or_default());
    app.clipboard().write_text(text.clone()).map_err(|_| Failure::localized("unknown", "internal"))?;
    Ok(json!(text))
}

#[tauri::command]
pub async fn debug_reset_local_data(app: AppHandle) -> Answer {
    debug_only()?;
    let state = app.state::<AppState>();
    let _ = commands::logout(app.clone()).await;
    let firewall = state.store.lock().unwrap().preferences().always_on_kill_switch || state.status()["firewallActive"] == true;
    if firewall {
        commands::emergency_disable_kill_switch(&app).await.map_err(|reason| Failure::with_params("helperCommand", "internal", json!({ "details": reason })))?;
    }
    state.store.lock().unwrap().reset_local_data();
    state.api.requests.clear();
    crate::apply_theme(&app);
    crate::update_tray(&app);
    applog::line("debug", "local data reset");
    Ok(Value::Null)
}

#[tauri::command]
pub async fn debug_open_devtools(app: AppHandle) -> Answer {
    debug_only()?;
    if let Some(window) = app.get_webview_window("main") {
        window.open_devtools();
    }
    Ok(Value::Null)
}
