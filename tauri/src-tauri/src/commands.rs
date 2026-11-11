use serde_json::{json, Map, Value};
use std::time::Duration;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_clipboard_manager::ClipboardExt;
use tauri_plugin_opener::OpenerExt;

use crate::api::{segment, Auth, Failure, Method, Request};
use crate::store::{is_identifier, Preferences, Secrets, LANGUAGES, OBFUSCATION_MODES, QUIT_ACTIONS, THEMES};
use crate::{flavor, latency, service, system, AppState, NodeInfo, PendingRegistration};

type Answer = Result<Value, Failure>;

const MAX_DEVICE_NAME: usize = 32;
const MAX_JSON_INPUT: usize = 8 * 1024;
const WIREGUARD_DOWNLOAD_URL: &str = "https://www.wireguard.com/install/";

fn io_failure(_: std::io::Error) -> Failure {
    Failure::localized("unknown", "internal")
}

fn preferences_value(state: &AppState) -> Value {
    serde_json::to_value(state.store.lock().unwrap().preferences()).unwrap_or(Value::Null)
}

fn update_preferences(app: &AppHandle, change: impl FnOnce(&mut Preferences)) -> Answer {
    let state = app.state::<AppState>();
    {
        let mut store = state.store.lock().unwrap();
        let mut next = store.preferences().clone();
        change(&mut next);
        store.set_preferences(next).map_err(io_failure)?;
    }
    crate::update_tray(app);
    Ok(preferences_value(&state))
}

pub(crate) async fn call(app: &AppHandle, request: Request<'_>) -> Answer {
    let state = app.state::<AppState>();
    let token = state.store.lock().unwrap().secrets().token.clone();
    let result = state.api.send(request, token.as_deref(), state.language()).await;
    if let Err(failure) = &result {
        note_api_error(app, failure);
    }
    result
}

pub(crate) fn note_api_error(app: &AppHandle, failure: &Failure) {
    if !failure.ends_session() {
        return;
    }
    let state = app.state::<AppState>();
    let ended = {
        let mut store = state.store.lock().unwrap();
        let secrets = store.secrets().clone();
        secrets.token.is_some() && store.set_secrets(Secrets { token: None, ..secrets }).is_ok()
    };
    if ended {
        crate::engine::spawn_push_secrets(app, false);
        use tauri::Emitter;
        let _ = app.emit("session-ended", ());
        crate::update_tray(app);
    }
}

fn unless_device_gone(result: Answer) -> Answer {
    match result {
        Err(failure) if failure.api_code() == Some("device_not_found") => Ok(Value::Null),
        other => other,
    }
}

fn is_account_code(code: &str) -> bool {
    code.len() == 16 && code.bytes().all(|b| b.is_ascii_digit())
}

fn is_totp_input(totp: &str) -> bool {
    (1..=40).contains(&totp.len()) && totp.bytes().all(|b| b.is_ascii_alphanumeric() || b == b' ' || b == b'-')
}

fn is_device_name(name: &str) -> bool {
    let trimmed = name.trim();
    !trimmed.is_empty() && trimmed.encode_utf16().count() <= MAX_DEVICE_NAME
}

fn is_telegram_proxy_link(link: &str) -> bool {
    let Some(rest) = link.strip_prefix("https://t.me/proxy?server=") else { return false };
    let Some((server, rest)) = rest.split_once("&port=") else { return false };
    let Some((port, secret)) = rest.split_once("&secret=") else { return false };
    let server_ok = (1..=255).contains(&server.len()) && server.bytes().all(|b| b.is_ascii_alphanumeric() || b".%:-".contains(&b));
    let port_ok = (1..=5).contains(&port.len()) && port.bytes().all(|b| b.is_ascii_digit());
    let secret_ok = secret.strip_prefix("ee").is_some_and(|hex| (40..=160).contains(&hex.len()) && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    server_ok && port_ok && secret_ok
}

fn small_object(value: &Value) -> bool {
    value.is_object() && value.to_string().len() <= MAX_JSON_INPUT
}

fn site_url(path: &str) -> String {
    let base = flavor::api_base_url();
    let origin_end = base.find("://").map(|start| base[start + 3..].find('/').map_or(base.len(), |end| start + 3 + end)).unwrap_or(base.len());
    format!("{}{path}", &base[..origin_end])
}

fn open_external(app: &AppHandle, url: &str) -> Answer {
    app.opener().open_url(url, None::<&str>).map_err(|_| Failure::localized("openWebsiteFailed", "internal"))?;
    Ok(Value::Null)
}

fn service_failure(error: service::ServiceError) -> Failure {
    match error {
        service::ServiceError::Unavailable(_) => Failure::localized("helperUnavailable", "elevation"),
        service::ServiceError::Command { code, .. } if code == "wireguard_missing" || code == "wireguardMissing" => Failure::localized("wireguardMissing", "wireguard_missing"),
        service::ServiceError::Command { code, detail } => {
            let details: String = format!("{code}: {detail}").chars().take(400).collect();
            Failure::with_params("helperCommand", "internal", json!({ "details": details }))
        }
    }
}

async fn service_call(op: &str, timeout: Duration) -> Result<Value, service::ServiceError> {
    service::call(flavor::identity().service_pipe, op, timeout).await
}

pub(crate) async fn readiness() -> service::Readiness {
    let Ok(hello) = service_call("hello", Duration::from_secs(5)).await else { return service::Readiness::default() };
    let status = service_call("status", Duration::from_secs(5)).await.ok();
    service::readiness(&hello, status.as_ref(), flavor::identity().name)
}

pub async fn detect_firewall(app: &AppHandle) {
    if !readiness().await.ready {
        return;
    }
    if let Ok(answer) = service_call("killswitch-status", Duration::from_secs(10)).await {
        let rules = answer.get("killSwitchRules").and_then(Value::as_u64).unwrap_or(0);
        crate::publish(app, json!({ "firewallActive": rules > 0 }));
    }
}

pub async fn emergency_disable_kill_switch(app: &AppHandle) -> Result<(), String> {
    let language = app.state::<AppState>().language();
    let _ = update_preferences(app, |preferences| preferences.always_on_kill_switch = false);
    let _ = crate::engine::request(app, json!({ "op": "always-on-flag", "enabled": false }), Duration::from_secs(5)).await;
    match service_call("killswitch-disable", Duration::from_secs(60)).await {
        Ok(_) => {
            crate::publish(app, json!({ "firewallActive": false }));
            Ok(())
        }
        Err(error) => Err(match service_failure(error) {
            Failure::Localized { key, .. } => crate::strings::text(language, &format!("errors.{key}")),
            Failure::Api { status, .. } => status.to_string(),
        }),
    }
}

const WINDOWS_FEATURES: &str = r#"{"desktopWindow":true,"managedWireGuard":true,"firewallLockdown":true,"systemLockdown":false,"appExclusion":false}"#;

#[tauri::command]
async fn environment(state: State<'_, AppState>) -> Result<Value, ()> {
    let ready = readiness().await;
    let assume = cfg!(debug_assertions) && flavor::is_debug() && std::env::var("MANTEL_DEV_ASSUME_WIREGUARD").as_deref() == Ok("1");
    let encryption = state.store.lock().unwrap().encryption_available();
    Ok(json!({
        "platform": std::env::consts::OS.replace("windows", "win32").replace("macos", "darwin"),
        "elevated": ready.ready,
        "wireguardInstalled": ready.wireguard_directory.is_some() || assume,
        "wireguardPath": ready.wireguard_directory,
        "wireguardSource": ready.wireguard_source,
        "encryptionAvailable": encryption,
        "appVersion": flavor::APP_VERSION,
        "features": serde_json::from_str::<Value>(WINDOWS_FEATURES).unwrap_or(Value::Null),
        "systemLocales": system::preferred_languages(),
    }))
}

#[tauri::command]
fn session(state: State<'_, AppState>) -> Value {
    state.store.lock().unwrap().session()
}

#[tauri::command]
fn preferences(state: State<'_, AppState>) -> Value {
    preferences_value(&state)
}

#[tauri::command]
fn tunnel_status(state: State<'_, AppState>) -> Value {
    state.status()
}

#[tauri::command]
fn select_node(app: AppHandle, node_id: String) -> Answer {
    if !is_identifier(&node_id) {
        return Err(Failure::invalid());
    }
    update_preferences(&app, |preferences| preferences.last_node_id = Some(node_id))
}

fn choice(value: &str, allowed: &[&str]) -> Result<String, Failure> {
    allowed.contains(&value).then(|| value.to_string()).ok_or_else(Failure::invalid)
}

#[tauri::command]
fn set_language(app: AppHandle, language: String) -> Answer {
    let language = choice(&language, &LANGUAGES)?;
    let answer = update_preferences(&app, |preferences| preferences.language = language)?;
    let resolved = app.state::<AppState>().language();
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        let _ = crate::engine::request(&handle, json!({ "op": "language", "language": resolved }), Duration::from_secs(5)).await;
    });
    Ok(answer)
}

#[tauri::command]
fn set_theme(app: AppHandle, theme: String) -> Answer {
    let theme = choice(&theme, &THEMES)?;
    let answer = update_preferences(&app, |preferences| preferences.theme = theme);
    crate::apply_theme(&app);
    answer
}

#[tauri::command]
fn set_post_quantum(app: AppHandle, enabled: bool) -> Answer {
    let changed = app.state::<AppState>().store.lock().unwrap().preferences().post_quantum != enabled;
    let answer = update_preferences(&app, |preferences| preferences.post_quantum = enabled)?;
    if changed {
        crate::tunnel::spawn_reconnect(&app);
    }
    Ok(answer)
}

#[tauri::command]
fn set_obfuscation(app: AppHandle, mode: String) -> Answer {
    let mode = choice(&mode, &OBFUSCATION_MODES)?;
    let changed = app.state::<AppState>().store.lock().unwrap().preferences().obfuscation != mode;
    let answer = update_preferences(&app, |preferences| preferences.obfuscation = mode)?;
    if changed {
        crate::tunnel::spawn_reconnect(&app);
    }
    Ok(answer)
}

#[tauri::command]
fn set_auto_connect_open_wifi(app: AppHandle, enabled: bool) -> Answer {
    update_preferences(&app, |preferences| preferences.auto_connect_open_wifi = enabled)
}

#[tauri::command]
fn set_connect_on_launch(app: AppHandle, enabled: bool) -> Answer {
    update_preferences(&app, |preferences| preferences.connect_on_launch = enabled)
}

#[tauri::command]
fn set_quit_action(app: AppHandle, action: String) -> Answer {
    let action = choice(&action, &QUIT_ACTIONS)?;
    update_preferences(&app, |preferences| preferences.quit_action = action)
}

#[tauri::command]
async fn set_always_on_kill_switch(app: AppHandle, enabled: bool) -> Answer {
    if enabled {
        crate::engine::request(&app, json!({ "op": "always-on", "enabled": true }), Duration::from_secs(120)).await?;
        update_preferences(&app, |preferences| preferences.always_on_kill_switch = true)?;
        crate::publish(&app, json!({ "firewallActive": true }));
        return Ok(preferences_value(&app.state::<AppState>()));
    }
    update_preferences(&app, |preferences| preferences.always_on_kill_switch = false)?;
    if crate::engine::request(&app, json!({ "op": "always-on", "enabled": false }), Duration::from_secs(60)).await.is_err() {
        service_call("killswitch-disable", Duration::from_secs(60)).await.map_err(service_failure)?;
    }
    crate::tunnel::poll_once(&app).await;
    Ok(preferences_value(&app.state::<AppState>()))
}

#[tauri::command]
async fn wifi_security() -> Result<Value, ()> {
    Ok(json!(tauri::async_runtime::spawn_blocking(system::wifi_security).await.unwrap_or("unknown")))
}

fn autostart_supported() -> bool {
    !cfg!(debug_assertions)
}

#[tauri::command]
async fn autostart() -> Result<Value, ()> {
    if !autostart_supported() {
        return Ok(json!({ "supported": false, "enabled": false }));
    }
    let enabled = tauri::async_runtime::spawn_blocking(|| system::autostart_enabled(flavor::identity().autostart_task)).await.unwrap_or(false);
    Ok(json!({ "supported": true, "enabled": enabled }))
}

#[tauri::command]
async fn set_autostart(enabled: bool) -> Answer {
    if !autostart_supported() {
        return Err(Failure::invalid());
    }
    let exe = std::env::current_exe().map_err(io_failure)?.to_string_lossy().into_owned();
    let identity = flavor::identity();
    let description = format!("{}: Start bei der Anmeldung (Einstellungen → Verbindung)", identity.product_name);
    let result = tauri::async_runtime::spawn_blocking(move || {
        system::set_autostart(identity.autostart_task, enabled, &exe, &description)?;
        Ok::<bool, String>(system::autostart_enabled(identity.autostart_task))
    })
    .await
    .map_err(|_| Failure::localized("unknown", "internal"))?;
    match result {
        Ok(enabled) => Ok(json!({ "supported": true, "enabled": enabled })),
        Err(message) => Err(Failure::Localized { key: "__plain".into(), params: Map::from_iter([("message".into(), json!(message))]), code: "internal".into() }),
    }
}

async fn adopt_session(app: &AppHandle, token: String, account_id: String, paid_until: String) -> Result<(), Failure> {
    let state = app.state::<AppState>();
    let same = state.store.lock().unwrap().secrets().account_id.as_deref() == Some(account_id.as_str());
    if !same && state.status()["phase"] != "disconnected" {
        crate::tunnel::disconnect(app).await?;
    }
    {
        let mut store = state.store.lock().unwrap();
        let previous = store.secrets().clone();
        store
            .set_secrets(Secrets {
                token: Some(token),
                account_id: Some(account_id),
                paid_until: Some(paid_until),
                device: if same { previous.device } else { None },
                ticket_key: if same { previous.ticket_key } else { None },
            })
            .map_err(io_failure)?;
    }
    crate::engine::push_secrets(app, !same).await;
    Ok(())
}

fn session_parts(value: &Value) -> Result<(String, String, String), Failure> {
    let text = |pointer: &str| value.pointer(pointer).and_then(Value::as_str).filter(|text| !text.is_empty()).map(str::to_string);
    let token_ok = |token: &String| (16..=512).contains(&token.len()) && token.bytes().all(|b| b.is_ascii_alphanumeric() || b"._~+/=-".contains(&b));
    match (text("/token"), text("/account/id"), text("/account/paidUntil")) {
        (Some(token), Some(id), Some(paid)) if token_ok(&token) && is_identifier(&id) && paid.len() <= 40 => Ok((token, id, paid)),
        _ => Err(Failure::localized("apiUnexpectedFormat", "server")),
    }
}

#[tauri::command]
async fn login(app: AppHandle, code: String, totp: Option<String>) -> Answer {
    if !is_account_code(&code) || totp.as_deref().is_some_and(|totp| !is_totp_input(totp)) {
        return Err(Failure::invalid());
    }
    let state = app.state::<AppState>();
    let _guard = state.queue.lock().await;
    let request = Request::new(Method::Post, "/api/v1/auth/login").auth(Auth::None).body(json!({ "code": code, "totp": totp }));
    let answer = call(&app, request).await?;
    let (token, account_id, paid_until) = session_parts(&answer)?;
    *state.pending.lock().unwrap() = None;
    adopt_session(&app, token, account_id, paid_until).await?;
    crate::update_tray(&app);
    let session = state.store.lock().unwrap().session();
    Ok(session)
}

#[tauri::command]
async fn register(app: AppHandle, referral_code: Option<String>) -> Answer {
    let state = app.state::<AppState>();
    let _guard = state.queue.lock().await;
    let body = match referral_code.filter(|code| !code.trim().is_empty() && code.len() <= 40) {
        Some(code) => json!({ "referralCode": code }),
        None => json!({}),
    };
    let answer = call(&app, Request::new(Method::Post, "/api/v1/auth/register").auth(Auth::None).body(body)).await?;
    let (token, account_id, paid_until) = session_parts(&answer)?;
    let code = answer.get("code").and_then(Value::as_str).filter(|code| is_account_code(code)).ok_or_else(|| Failure::localized("apiUnexpectedFormat", "server"))?;
    *state.pending.lock().unwrap() = Some(PendingRegistration { token, account_id, paid_until });
    let referral_days = answer.get("referralDays").and_then(Value::as_u64);
    Ok(json!({ "code": code, "referralDays": referral_days }))
}

#[tauri::command]
async fn confirm_registration(app: AppHandle) -> Answer {
    let state = app.state::<AppState>();
    let _guard = state.queue.lock().await;
    let pending = state.pending.lock().unwrap().take().ok_or_else(|| Failure::localized("registrationMissing", "invalid"))?;
    adopt_session(&app, pending.token, pending.account_id, pending.paid_until).await?;
    crate::update_tray(&app);
    let session = state.store.lock().unwrap().session();
    Ok(session)
}

#[tauri::command]
pub(crate) async fn logout(app: AppHandle) -> Answer {
    let state = app.state::<AppState>();
    let _guard = state.queue.lock().await;
    *state.pending.lock().unwrap() = None;
    if state.status()["phase"] != "disconnected" {
        crate::tunnel::disconnect(&app).await?;
    }
    let secrets = state.store.lock().unwrap().secrets().clone();
    if secrets.token.is_some() {
        if let Some(device) = secrets.device_id() {
            let route = format!("/api/v1/devices/{}", segment(&device));
            let _ = call(&app, Request::new(Method::Delete, route).expect(&[204, 200, 404])).await;
        }
        let _ = call(&app, Request::new(Method::Post, "/api/v1/auth/logout").expect(&[204, 200])).await;
    }
    state.store.lock().unwrap().wipe_secrets();
    crate::engine::push_secrets(&app, true).await;
    crate::update_tray(&app);
    Ok(Value::Null)
}

#[tauri::command]
async fn account(app: AppHandle) -> Answer {
    let state = app.state::<AppState>();
    let mut account = call(&app, Request::new(Method::Get, "/api/v1/account")).await?;
    let mut tokens = std::collections::HashMap::new();
    if let Some(devices) = account.get_mut("devices").and_then(Value::as_array_mut) {
        for device in devices {
            if let Some(object) = device.as_object_mut() {
                if let (Some(Value::String(id)), Some(Value::String(token))) = (object.get("id").cloned(), object.remove("obfsToken")) {
                    tokens.insert(id, token);
                }
            }
        }
    }
    *state.obfs_tokens.lock().unwrap() = tokens;
    if let Some(paid_until) = account.get("paidUntil").and_then(Value::as_str) {
        let mut store = state.store.lock().unwrap();
        let secrets = store.secrets().clone();
        if secrets.token.is_some() && secrets.paid_until.as_deref() != Some(paid_until) {
            let _ = store.set_secrets(Secrets { paid_until: Some(paid_until.to_string()), ..secrets });
            drop(store);
            crate::engine::spawn_push_secrets(&app, false);
        }
    }
    Ok(account)
}

#[tauri::command]
async fn update_settings(app: AppHandle, patch: Value) -> Answer {
    if !small_object(&patch) {
        return Err(Failure::invalid());
    }
    let routing = ["killSwitch", "lanAccess", "ipv6"].iter().any(|key| patch.get(key).is_some());
    let answer = call(&app, Request::new(Method::Patch, "/api/v1/settings").body(patch)).await?;
    if routing {
        let state = app.state::<AppState>();
        if state.status()["phase"] != "disconnected" {
            crate::tunnel::spawn_reconnect(&app);
        } else if state.store.lock().unwrap().preferences().always_on_kill_switch {
            let handle = app.clone();
            tauri::async_runtime::spawn(async move {
                if let Err(failure) = crate::engine::request(&handle, json!({ "op": "always-on", "enabled": true }), Duration::from_secs(120)).await {
                    crate::publish(&handle, json!({ "error": crate::strings::failure_text(handle.state::<AppState>().language(), &failure) }));
                }
            });
        }
    }
    Ok(answer)
}

#[tauri::command]
async fn recent_logins(app: AppHandle) -> Answer {
    call(&app, Request::new(Method::Get, "/api/v1/account/logins")).await
}

#[tauri::command]
async fn mark_logins_seen(app: AppHandle) -> Answer {
    call(&app, Request::new(Method::Post, "/api/v1/account/logins/seen").body(json!({})).expect(&[204, 200])).await?;
    Ok(Value::Null)
}

#[tauri::command]
async fn logout_other_sessions(app: AppHandle) -> Answer {
    call(&app, Request::new(Method::Post, "/api/v1/auth/logout-others").body(json!({})).expect(&[204, 200])).await?;
    Ok(Value::Null)
}

fn node_info(node: &Value) -> Option<NodeInfo> {
    let id = node.get("id")?.as_str()?;
    let host = node.get("endpointHost")?.as_str()?;
    let host_ok = !host.is_empty() && host.len() <= 253 && host.bytes().all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b));
    if !is_identifier(id) || !host_ok {
        return None;
    }
    Some(NodeInfo {
        id: id.to_string(),
        online: node.get("online").and_then(Value::as_bool).unwrap_or(false),
        host: host.to_string(),
        ping_port: node.get("pingPort").and_then(Value::as_u64).and_then(|port| u16::try_from(port).ok()).filter(|port| *port > 0),
    })
}

#[tauri::command]
async fn nodes(app: AppHandle) -> Answer {
    let state = app.state::<AppState>();
    let nodes = call(&app, Request::new(Method::Get, "/api/v1/nodes").auth(Auth::Optional)).await?;
    let list = nodes.as_array().ok_or_else(|| Failure::localized("apiUnexpectedFormat", "server"))?;
    *state.nodes.lock().unwrap() = list.iter().take(500).filter_map(node_info).collect();
    Ok(nodes)
}

#[tauri::command]
async fn measure_latency(state: State<'_, AppState>, node_ids: Vec<String>) -> Result<Vec<latency::Measurement>, ()> {
    if node_ids.len() > latency::MAX_PING_TARGETS || node_ids.iter().any(|id| !is_identifier(id)) {
        return Ok(Vec::new());
    }
    let tunnel_idle = state.status()["phase"].as_str() == Some("disconnected");
    if !tunnel_idle || state.measuring.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return Ok(Vec::new());
    }
    let targets: Vec<latency::Target> = state
        .nodes
        .lock()
        .unwrap()
        .iter()
        .filter(|node| node.online && node_ids.contains(&node.id))
        .filter_map(|node| node.ping_port.map(|port| latency::Target { id: node.id.clone(), host: node.host.clone(), port }))
        .take(latency::MAX_PING_TARGETS)
        .collect();
    let results = latency::measure_targets(targets).await;
    state.measuring.store(false, std::sync::atomic::Ordering::SeqCst);
    Ok(results)
}

#[tauri::command]
async fn check_app_version(state: State<'_, AppState>) -> Answer {
    let info = state.api.send(Request::new(Method::Get, "/api/v1/app-version?platform=windows").auth(Auth::None), None, state.language()).await?;
    state.update_required.store(update_required(flavor::APP_VERSION, &info), std::sync::atomic::Ordering::SeqCst);
    Ok(info)
}

fn version_code(value: &Value) -> Option<u64> {
    let text = value.as_str().filter(|text| text.len() <= 64)?;
    let base = text.trim().split(['-', '+']).next()?;
    let parts: Vec<&str> = base.split('.').collect();
    let widths = [4..=4, 1..=2, 1..=3];
    if parts.len() != 3 || parts.iter().zip(&widths).any(|(part, width)| !width.contains(&part.len()) || !part.bytes().all(|b| b.is_ascii_digit())) {
        return None;
    }
    let number = |index: usize| parts[index].parse::<u64>().ok();
    Some(number(0)? * 100_000 + number(1)? * 1000 + number(2)?)
}

fn update_required(current: &str, info: &Value) -> bool {
    if info["platform"] != "windows" {
        return false;
    }
    let (Some(current), Some(latest), Some(minimum)) = (version_code(&json!(current)), version_code(&info["latest"]), version_code(&info["minimum"])) else {
        return false;
    };
    latest > current && current < minimum
}

fn own_device(state: &AppState) -> Option<String> {
    state.store.lock().unwrap().secrets().device_id()
}

#[tauri::command]
fn current_device_id(state: State<'_, AppState>) -> Value {
    json!(own_device(&state))
}

fn port_forwarding_request(device: &str, action: &str) -> Request<'static> {
    let route = format!("/api/v1/devices/{}/port-forwarding", segment(device));
    match action {
        "enable" => Request::new(Method::Post, route).body(json!({})).expect(&[201, 200]),
        "disable" => Request::new(Method::Delete, route),
        _ => Request::new(Method::Get, route),
    }
}

#[tauri::command]
async fn port_forwarding(app: AppHandle) -> Answer {
    let Some(device) = own_device(&app.state::<AppState>()) else { return Ok(Value::Null) };
    unless_device_gone(call(&app, port_forwarding_request(&device, "get")).await)
}

#[tauri::command]
async fn set_port_forwarding(app: AppHandle, enabled: bool) -> Answer {
    let Some(device) = own_device(&app.state::<AppState>()) else { return Ok(Value::Null) };
    unless_device_gone(call(&app, port_forwarding_request(&device, if enabled { "enable" } else { "disable" })).await)
}

#[tauri::command]
async fn device_port_forwarding(app: AppHandle, id: String) -> Answer {
    if !is_identifier(&id) {
        return Err(Failure::invalid());
    }
    unless_device_gone(call(&app, port_forwarding_request(&id, "get")).await)
}

fn add_port_forward_request(device: &str, local_port: Option<u16>) -> Request<'static> {
    match local_port {
        Some(local) => Request::new(Method::Post, format!("/api/v1/devices/{}/port-forwarding", segment(device)))
            .body(json!({ "localPort": local }))
            .expect(&[201, 200]),
        None => port_forwarding_request(device, "enable"),
    }
}

#[tauri::command]
async fn add_port_forward(app: AppHandle, id: String, local_port: Option<u16>) -> Answer {
    if !is_identifier(&id) || local_port == Some(0) {
        return Err(Failure::invalid());
    }
    unless_device_gone(call(&app, add_port_forward_request(&id, local_port)).await)
}

#[tauri::command]
async fn set_port_forward_local_port(app: AppHandle, id: String, port: u16, local_port: Option<u16>) -> Answer {
    if !is_identifier(&id) || port == 0 || local_port == Some(0) {
        return Err(Failure::invalid());
    }
    let route = format!("/api/v1/devices/{}/port-forwarding/{port}", segment(&id));
    unless_device_gone(call(&app, Request::new(Method::Patch, route).body(json!({ "localPort": local_port }))).await)
}

#[tauri::command]
async fn remove_port_forward(app: AppHandle, id: String, port: u16) -> Answer {
    if !is_identifier(&id) || port == 0 {
        return Err(Failure::invalid());
    }
    let route = format!("/api/v1/devices/{}/port-forwarding/{port}", segment(&id));
    unless_device_gone(call(&app, Request::new(Method::Delete, route)).await)
}

async fn tor_state(app: &AppHandle, enabled: Option<bool>) -> Answer {
    let Some(device) = own_device(&app.state::<AppState>()) else { return Ok(Value::Null) };
    let own = match enabled {
        None => {
            let account = call(app, Request::new(Method::Get, "/api/v1/account")).await;
            let account = match unless_device_gone(account)? {
                Value::Null => return Ok(Value::Null),
                account => account,
            };
            account["devices"].as_array().and_then(|devices| devices.iter().find(|entry| entry["id"].as_str() == Some(device.as_str())).cloned())
        }
        Some(enabled) => {
            let route = format!("/api/v1/devices/{}/tor", segment(&device));
            match unless_device_gone(call(app, Request::new(Method::Put, route).body(json!({ "enabled": enabled }))).await)? {
                Value::Null => return Ok(Value::Null),
                own => Some(own),
            }
        }
    };
    let Some(mut own) = own else { return Ok(Value::Null) };
    if let Some(object) = own.as_object_mut() {
        object.remove("obfsToken");
    }
    let nodes = unless_device_gone(call(app, Request::new(Method::Get, "/api/v1/nodes").auth(Auth::Optional)).await)?;
    Ok(json!({ "device": own, "nodes": nodes }))
}

#[tauri::command]
async fn tor(app: AppHandle) -> Answer {
    tor_state(&app, None).await
}

#[tauri::command]
async fn set_tor(app: AppHandle, enabled: bool) -> Answer {
    tor_state(&app, Some(enabled)).await
}

#[tauri::command]
async fn rename_device(app: AppHandle, id: String, name: String) -> Answer {
    if !is_identifier(&id) || !is_device_name(&name) {
        return Err(Failure::invalid());
    }
    let route = format!("/api/v1/devices/{}", segment(&id));
    call(&app, Request::new(Method::Patch, route).body(json!({ "name": name.trim() }))).await
}

#[tauri::command]
async fn remove_device(app: AppHandle, id: String) -> Answer {
    if !is_identifier(&id) {
        return Err(Failure::invalid());
    }
    let state = app.state::<AppState>();
    let own = own_device(&state).as_deref() == Some(id.as_str());
    if own && state.status()["phase"] != "disconnected" {
        crate::tunnel::disconnect(&app).await?;
    }
    let route = format!("/api/v1/devices/{}", segment(&id));
    call(&app, Request::new(Method::Delete, route).expect(&[204, 200, 404])).await?;
    if own {
        {
            let mut store = state.store.lock().unwrap();
            let secrets = store.secrets().clone();
            let _ = store.set_secrets(Secrets { device: None, ..secrets });
        }
        crate::engine::push_secrets(&app, true).await;
    }
    Ok(Value::Null)
}

#[tauri::command]
async fn proxies(app: AppHandle) -> Answer {
    match call(&app, Request::new(Method::Get, "/api/v1/proxies")).await {
        Ok(answer) => Ok(answer.get("proxies").cloned().unwrap_or(Value::Null)),
        Err(failure) if failure.status() == Some(404) => Ok(Value::Null),
        Err(failure) => Err(failure),
    }
}

#[tauri::command]
async fn create_proxy(app: AppHandle, input: Value) -> Answer {
    if !small_object(&input) {
        return Err(Failure::invalid());
    }
    call(&app, Request::new(Method::Post, "/api/v1/proxies").body(input).expect(&[201, 200])).await
}

#[tauri::command]
async fn update_proxy(app: AppHandle, id: String, patch: Value) -> Answer {
    if !is_identifier(&id) || !small_object(&patch) {
        return Err(Failure::invalid());
    }
    call(&app, Request::new(Method::Patch, format!("/api/v1/proxies/{}", segment(&id))).body(patch)).await
}

#[tauri::command]
async fn delete_proxy(app: AppHandle, id: String) -> Answer {
    if !is_identifier(&id) {
        return Err(Failure::invalid());
    }
    call(&app, Request::new(Method::Delete, format!("/api/v1/proxies/{}", segment(&id))).expect(&[204, 200])).await?;
    Ok(Value::Null)
}

#[tauri::command]
async fn device_key(app: AppHandle) -> Answer {
    if app.state::<AppState>().store.lock().unwrap().secrets().device.is_none() {
        return Ok(Value::Null);
    }
    crate::engine::request(&app, json!({ "op": "device-key" }), Duration::from_secs(20)).await
}

#[tauri::command]
async fn rotate_device_key(app: AppHandle) -> Answer {
    if app.state::<AppState>().store.lock().unwrap().secrets().device.is_none() {
        return Ok(Value::Null);
    }
    crate::tunnel::rotate_device_key(&app).await
}

#[tauri::command]
fn open_wireguard_download(app: AppHandle) -> Value {
    let _ = open_external(&app, WIREGUARD_DOWNLOAD_URL);
    Value::Null
}

#[tauri::command]
fn open_account_page(app: AppHandle) -> Answer {
    open_external(&app, &site_url("/dashboard/abo"))
}

#[tauri::command]
fn open_security_page(app: AppHandle) -> Answer {
    open_external(&app, &site_url("/dashboard/konto"))
}

#[tauri::command]
fn open_download_page(app: AppHandle) -> Answer {
    open_external(&app, &site_url("/download"))
}

#[tauri::command]
fn open_telegram_proxy(app: AppHandle, link: String) -> Answer {
    if !is_telegram_proxy_link(&link) {
        return Err(Failure::invalid());
    }
    open_external(&app, &link)
}

#[tauri::command]
fn copy_text(app: AppHandle, text: String) -> Answer {
    if text.is_empty() || text.encode_utf16().count() > 64 * 1024 {
        return Err(Failure::invalid());
    }
    app.clipboard().write_text(text).map_err(|_| Failure::localized("unknown", "internal"))?;
    Ok(Value::Null)
}

#[tauri::command]
fn window_control(window: tauri::WebviewWindow, action: String) -> Result<(), ()> {
    let _ = match action.as_str() {
        "minimize" => window.minimize(),
        "toggle-maximize" => window.is_maximized().and_then(|maximized| if maximized { window.unmaximize() } else { window.maximize() }),
        "close" => window.hide(),
        "drag" => window.start_dragging(),
        "ready" => window.show().and_then(|()| window.set_focus()),
        _ => Ok(()),
    };
    Ok(())
}

#[tauri::command]
async fn connect(app: AppHandle, node_id: String) -> Answer {
    if !is_identifier(&node_id) {
        return Err(Failure::invalid());
    }
    let _ = update_preferences(&app, |preferences| preferences.last_node_id = Some(node_id.clone()));
    crate::tunnel::connect(&app, node_id).await
}

#[tauri::command]
async fn disconnect(app: AppHandle) -> Answer {
    crate::tunnel::disconnect(&app).await
}

async fn repair_service(app: &AppHandle) -> Result<(), Failure> {
    let unavailable = || Failure::localized("helperUnavailable", "elevation");
    if cfg!(debug_assertions) {
        return Err(unavailable());
    }
    let exe = std::env::current_exe().map_err(|_| unavailable())?;
    let resources = app.path().resource_dir().map_err(|_| unavailable())?;
    let (service, root) = system::repair_paths(&exe, &resources).filter(|(service, _)| service.exists()).ok_or_else(unavailable)?;
    crate::applog::line("service", "repair requested (UAC)");
    tauri::async_runtime::spawn_blocking(move || system::repair_service(&service, &root))
        .await
        .map_err(|_| unavailable())?
        .map_err(|details| Failure::with_params("helperCommand", "internal", json!({ "details": details })))?;
    for _ in 0..20 {
        if readiness().await.ready {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err(unavailable())
}

#[tauri::command]
async fn install_wire_guard(app: AppHandle) -> Answer {
    if !readiness().await.ready {
        repair_service(&app).await?;
    }
    crate::engine::request(&app, json!({ "op": "install-wireguard" }), Duration::from_secs(300)).await
}

pub fn handler() -> impl Fn(tauri::ipc::Invoke) -> bool + Send + Sync + 'static {
    tauri::generate_handler![
        environment,
        session,
        preferences,
        tunnel_status,
        select_node,
        set_language,
        set_theme,
        set_post_quantum,
        set_obfuscation,
        set_auto_connect_open_wifi,
        set_connect_on_launch,
        set_quit_action,
        set_always_on_kill_switch,
        wifi_security,
        autostart,
        set_autostart,
        login,
        register,
        confirm_registration,
        logout,
        account,
        update_settings,
        recent_logins,
        mark_logins_seen,
        logout_other_sessions,
        nodes,
        measure_latency,
        check_app_version,
        current_device_id,
        port_forwarding,
        set_port_forwarding,
        device_port_forwarding,
        add_port_forward,
        remove_port_forward,
        set_port_forward_local_port,
        rotate_device_key,
        tor,
        set_tor,
        rename_device,
        remove_device,
        proxies,
        create_proxy,
        update_proxy,
        delete_proxy,
        device_key,
        open_wireguard_download,
        open_account_page,
        open_security_page,
        open_download_page,
        open_telegram_proxy,
        copy_text,
        window_control,
        connect,
        disconnect,
        install_wire_guard,
        crate::support::support_request,
        crate::support::support_key_load,
        crate::support::support_key_save,
        crate::support::support_key_clear,
        crate::debug::debug_info,
        crate::debug::debug_request_log,
        crate::debug::debug_clear_request_log,
        crate::debug::debug_health_check,
        crate::debug::debug_set_verbose,
        crate::debug::debug_copy_diagnostics,
        crate::debug::debug_reset_local_data,
        crate::debug::debug_open_devtools,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_port_forward_sends_local_port_only_when_set() {
        let plain = add_port_forward_request("0123456789abcdef", None);
        assert_eq!(plain.body, Some(json!({})), "older servers refuse localPort");
        let local = add_port_forward_request("0123456789abcdef", Some(3000));
        assert_eq!(local.route, "/api/v1/devices/0123456789abcdef/port-forwarding");
        assert_eq!(local.body, Some(json!({ "localPort": 3000 })));
        assert_eq!(local.expect, &[201, 200]);
    }

    #[test]
    fn input_checks_match_ipc_ts() {
        assert!(is_account_code("1234567890123456"));
        assert!(!is_account_code("123456789012345a"));
        assert!(is_totp_input("123 456"));
        assert!(!is_totp_input("12;34"));
        assert!(is_device_name("  Laptop  "));
        assert!(!is_device_name("   "));
        assert!(!is_device_name(&"x".repeat(33)));
        assert!(small_object(&json!({ "killSwitch": true })));
        assert!(!small_object(&json!([1])));
        assert!(!small_object(&json!({ "x": "y".repeat(9000) })));
    }

    #[test]
    fn telegram_links_like_shared_proxy() {
        let secret = format!("ee{}", "a1".repeat(20));
        assert!(is_telegram_proxy_link(&format!("https://t.me/proxy?server=hk-2.mantel.net&port=443&secret={secret}")));
        assert!(!is_telegram_proxy_link(&format!("https://evil.example/proxy?server=x&port=443&secret={secret}")));
        assert!(!is_telegram_proxy_link(&format!("https://t.me/proxy?server=x&port=443&secret={secret}&x=1")));
        assert!(!is_telegram_proxy_link("https://t.me/proxy?server=x&port=443&secret=eeAB"));
    }

    #[test]
    fn site_urls_use_only_the_api_origin() {
        let url = site_url("/dashboard/abo");
        assert!(url.ends_with("/dashboard/abo"));
        assert_eq!(url.matches("://").count(), 1);
        assert!(!url[url.find("://").unwrap() + 3..].trim_end_matches("/dashboard/abo").contains('/'));
    }

    #[test]
    fn session_parts_need_all_fields() {
        let token = "tok_0123456789abcdef";
        let ok = json!({ "token": token, "account": { "id": "a", "paidUntil": "2030-01-01" } });
        assert_eq!(session_parts(&ok).unwrap(), (token.into(), "a".into(), "2030-01-01".into()));
        assert!(session_parts(&json!({ "token": token, "account": { "id": "a" } })).is_err());
        assert!(session_parts(&json!({ "token": "short", "account": { "id": "a", "paidUntil": "x" } })).is_err());
        assert!(session_parts(&json!({ "token": "bad token with spaces", "account": { "id": "a", "paidUntil": "x" } })).is_err());
        let dev = json!({ "token": "aMZlR0gJXM3TqykO5l7THeuv2uV8F4CQv0DbCwJyjIw", "account": { "id": "ecb7506b7290c1f6", "paidUntil": "2026-11-11T00:00:00.000Z" } });
        assert!(session_parts(&dev).is_ok());
    }

    #[test]
    fn node_info_rejects_odd_hosts() {
        assert!(node_info(&json!({ "id": "hk-2", "endpointHost": "203.0.113.5", "online": true, "pingPort": 51821 })).is_some());
        assert!(node_info(&json!({ "id": "hk-2", "endpointHost": "a/b", "online": true })).is_none());
        let info = node_info(&json!({ "id": "x", "endpointHost": "x.example", "online": true, "pingPort": 70000 })).unwrap();
        assert_eq!(info.ping_port, None);
    }
}

#[cfg(test)]
mod version_tests {
    use super::*;

    #[test]
    fn update_required_matches_evaluate_update() {
        let info = |latest: Value, minimum: Value| json!({ "platform": "windows", "latest": latest, "minimum": minimum });
        assert!(update_required("2026.0.12", &info(json!("2026.0.13"), json!("2026.0.13"))));
        assert!(update_required("2026.0.12-browser", &info(json!("2026.1.0"), json!("2026.0.13"))));
        assert!(!update_required("2026.0.13", &info(json!("2026.0.14"), json!("2026.0.13"))), "at the minimum");
        assert!(!update_required("2026.0.12", &info(json!("2026.0.14"), Value::Null)), "no minimum");
        assert!(!update_required("2026.0.12", &info(json!("2026.0.12"), json!("2026.0.13"))), "nothing newer offered");
        assert!(!update_required("2026.0.12", &info(json!("2026.0.x"), json!("2026.0.13"))), "malformed never blocks");
        assert!(!update_required("2026.0.12", &json!({ "platform": "macos", "latest": "2026.0.13", "minimum": "2026.0.13" })));
        assert!(!update_required("dev", &info(json!("2026.0.13"), json!("2026.0.13"))));
        assert_eq!(version_code(&json!("2026.10.200")), Some(202_610_200));
        assert_eq!(version_code(&json!("26.1.1")), None);
    }
}
