use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use tauri::{AppHandle, Manager};

use crate::api::Failure;
use crate::{engine, AppState};

const POLL_VISIBLE_MS: u64 = 1000;
const POLL_HIDDEN_MS: u64 = 15_000;
const POLL_BURST_MS: [u64; 6] = [300, 600, 1200, 2500, 5000, 10_000];
const REVOCATION_EVERY_MS: u64 = 5 * 60_000;
const REVOCATION_STALE_MS: u64 = 30_000;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(240);

pub fn next_poll_delay(visible: bool, step: usize) -> u64 {
    let base = if visible { POLL_VISIBLE_MS } else { POLL_HIDDEN_MS };
    POLL_BURST_MS.get(step).copied().unwrap_or(base).min(base)
}

pub fn revocation_due(phase: &str, last_check_ms: u64, now_ms: u64) -> bool {
    let every = match phase {
        "disconnected" => return false,
        "stale" => REVOCATION_STALE_MS,
        _ => REVOCATION_EVERY_MS,
    };
    now_ms.saturating_sub(last_check_ms) >= every
}

#[derive(Default)]
pub struct Poller {
    step: AtomicU64,
    last_check: AtomicU64,
    quantum_recovery_tried: AtomicBool,
    relay_recovery_tried: AtomicBool,
}

#[derive(Debug, PartialEq)]
enum Recovery {
    Reconnect(String),
    Fail,
}

fn recovery(lost: &str, node_id: Option<&str>, poller: &Poller) -> Recovery {
    let tried = if lost == "quantum" { &poller.quantum_recovery_tried } else { &poller.relay_recovery_tried };
    match node_id {
        Some(node) if !tried.swap(true, Ordering::SeqCst) => Recovery::Reconnect(node.to_string()),
        _ => Recovery::Fail,
    }
}

fn window_visible(app: &AppHandle) -> bool {
    app.get_webview_window("main").and_then(|window| window.is_visible().ok()).unwrap_or(false)
}

fn publish_engine_status(app: &AppHandle, mut status: Value) {
    let state = app.state::<AppState>();
    let lost = status.as_object_mut().and_then(|object| object.remove("lost")).and_then(|lost| lost.as_str().map(str::to_string));
    if let Some(lost) = lost {
        match recovery(&lost, status["nodeId"].as_str(), &state.poller) {
            Recovery::Reconnect(node) => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let _ = connect(&app, node).await;
                });
                return;
            }
            Recovery::Fail if lost == "quantum" => {
                let text = crate::strings::text(state.language(), "errors.pqNotActive");
                status["phase"] = json!("stale");
                status["quantum"] = json!("off");
                status["error"] = json!(text);
            }
            Recovery::Fail => status["phase"] = json!("stale"),
        }
    }
    let before = state.status()["phase"].as_str().unwrap_or("").to_string();
    if status["phase"].as_str() != Some(before.as_str()) {
        state.poller.step.store(0, Ordering::SeqCst);
    }
    crate::publish(app, status);
}

pub async fn poll_once(app: &AppHandle) {
    let state = app.state::<AppState>();
    if state.operation.load(Ordering::SeqCst) {
        return;
    }
    let now = crate::now_ms();
    let phase = state.status()["phase"].as_str().unwrap_or("disconnected").to_string();
    let check = revocation_due(&phase, state.poller.last_check.load(Ordering::SeqCst), now) && state.store.lock().unwrap().secrets().token.is_some();
    if check {
        state.poller.last_check.store(now, Ordering::SeqCst);
    }
    if let Ok(status) = engine::request(app, json!({ "op": "status", "check": check }), Duration::from_secs(30)).await {
        if !state.operation.load(Ordering::SeqCst) {
            publish_engine_status(app, status);
        }
    }
}

pub async fn poll_loop(app: AppHandle) {
    loop {
        let state = app.state::<AppState>();
        let step = state.poller.step.fetch_add(1, Ordering::SeqCst) as usize;
        tokio::time::sleep(Duration::from_millis(next_poll_delay(window_visible(&app), step))).await;
        poll_once(&app).await;
    }
}

struct Operation<'a>(&'a AppState);

impl Drop for Operation<'_> {
    fn drop(&mut self) {
        self.0.operation.store(false, Ordering::SeqCst);
        self.0.poller.step.store(0, Ordering::SeqCst);
    }
}

fn begin(state: &AppState) -> Operation<'_> {
    state.operation.store(true, Ordering::SeqCst);
    Operation(state)
}

pub async fn connect(app: &AppHandle, node_id: String) -> Result<Value, Failure> {
    let state = app.state::<AppState>();
    if refuses_connect(state.update_required.load(Ordering::SeqCst), &state.status()["phase"]) {
        return Err(Failure::localized("updateRequired", "update_required"));
    }
    let _serial = state.tunnel_queue.lock().await;
    let _operation = begin(&state);
    let (post_quantum, obfuscation) = {
        let store = state.store.lock().unwrap();
        (store.preferences().post_quantum, store.preferences().obfuscation.clone())
    };
    let request = json!({ "op": "connect", "nodeId": node_id, "postQuantum": post_quantum, "obfuscation": obfuscation });
    let result = engine::request(app, request, CONNECT_TIMEOUT).await;
    if result.is_ok() {
        state.poller.quantum_recovery_tried.store(false, Ordering::SeqCst);
        state.poller.relay_recovery_tried.store(false, Ordering::SeqCst);
    }
    finish(app, result).await
}

pub async fn disconnect(app: &AppHandle) -> Result<Value, Failure> {
    let state = app.state::<AppState>();
    let _serial = state.tunnel_queue.lock().await;
    let _operation = begin(&state);
    if state.status()["phase"] != "disconnected" {
        crate::publish(app, json!({ "phase": "disconnecting", "error": null }));
    }
    let result = engine::request(app, json!({ "op": "disconnect" }), Duration::from_secs(120)).await;
    finish(app, result).await
}

pub async fn rotate_device_key(app: &AppHandle) -> Result<Value, Failure> {
    let state = app.state::<AppState>();
    let _serial = state.tunnel_queue.lock().await;
    let _operation = begin(&state);
    if state.status()["phase"] != "disconnected" {
        crate::publish(app, json!({ "phase": "connecting", "error": null, "revoked": null, "quantum": "off" }));
    }
    let result = engine::request(app, json!({ "op": "rotate-key" }), CONNECT_TIMEOUT).await;
    let _ = finish(app, Ok(Value::Null)).await;
    result
}

pub fn spawn_reconnect(app: &AppHandle) {
    let state = app.state::<AppState>();
    let status = state.status();
    let Some(node) = status["nodeId"].as_str().filter(|_| status["phase"] != "disconnected").map(str::to_string) else { return };
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let _ = connect(&app, node).await;
    });
}

pub fn should_auto_connect(previous: Option<&str>, current: &str, phase: &str, has_location: bool) -> bool {
    has_location && current == "open" && previous != Some("open") && phase == "disconnected"
}

pub async fn wifi_loop(app: AppHandle) {
    let mut previous: Option<&'static str> = None;
    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;
        let state = app.state::<AppState>();
        let (enabled, node, logged_in) = {
            let store = state.store.lock().unwrap();
            (store.preferences().auto_connect_open_wifi, store.preferences().last_node_id.clone(), store.secrets().token.is_some())
        };
        if !enabled {
            previous = None;
            continue;
        }
        let current = tauri::async_runtime::spawn_blocking(crate::system::wifi_security).await.unwrap_or("unknown");
        let phase = state.status()["phase"].as_str().unwrap_or("disconnected").to_string();
        let before = previous.replace(current);
        if let Some(node) = node.filter(|_| should_auto_connect(before, current, &phase, logged_in)) {
            let _ = connect(&app, node).await;
        }
    }
}

async fn finish(app: &AppHandle, result: Result<Value, Failure>) -> Result<Value, Failure> {
    let status = match &result {
        Ok(status) if status.is_object() => Some(status.clone()),
        _ => engine::request(app, json!({ "op": "status" }), Duration::from_secs(30)).await.ok(),
    };
    let mut status = status.unwrap_or_else(|| json!({ "phase": "disconnected" }));
    if let (Err(failure), Some(object)) = (&result, status.as_object_mut()) {
        object.insert("error".into(), json!(crate::strings::failure_text(app.state::<AppState>().language(), failure)));
    }
    publish_engine_status(app, status);
    result.map(|_| app.state::<AppState>().status())
}

fn refuses_connect(update_required: bool, phase: &Value) -> bool {
    update_required && phase == "disconnected"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_update_refuses_only_new_connections() {
        assert!(refuses_connect(true, &json!("disconnected")));
        assert!(!refuses_connect(true, &json!("connected")));
        assert!(!refuses_connect(true, &json!("stale")));
        assert!(!refuses_connect(false, &json!("disconnected")));
    }

    #[test]
    fn poll_pace_matches_poll_schedule() {
        assert_eq!(next_poll_delay(true, 0), 300);
        assert_eq!(next_poll_delay(true, 2), 1000);
        assert_eq!(next_poll_delay(false, 3), 2500);
        assert_eq!(next_poll_delay(false, 9), 15_000);
    }

    #[test]
    fn open_wifi_connects_once_per_network() {
        assert!(should_auto_connect(None, "open", "disconnected", true));
        assert!(should_auto_connect(Some("secure"), "open", "disconnected", true));
        assert!(!should_auto_connect(Some("open"), "open", "disconnected", true));
        assert!(!should_auto_connect(None, "open", "connected", true));
        assert!(!should_auto_connect(None, "open", "disconnected", false));
        assert!(!should_auto_connect(None, "secure", "disconnected", true));
    }

    #[test]
    fn lost_session_or_relay_reconnects_once() {
        let poller = Poller::default();
        assert_eq!(recovery("quantum", Some("ch-zrh"), &poller), Recovery::Reconnect("ch-zrh".into()));
        assert_eq!(recovery("quantum", Some("ch-zrh"), &poller), Recovery::Fail);
        assert_eq!(recovery("relay", None, &poller), Recovery::Fail);
        poller.relay_recovery_tried.store(false, Ordering::SeqCst);
        assert_eq!(recovery("relay", Some("ch-zrh"), &poller), Recovery::Reconnect("ch-zrh".into()));
    }

    #[test]
    fn revocation_pace() {
        assert!(!revocation_due("disconnected", 0, 10_000_000));
        assert!(revocation_due("connected", 0, REVOCATION_EVERY_MS));
        assert!(!revocation_due("connected", 1000, REVOCATION_EVERY_MS));
        assert!(revocation_due("stale", 0, REVOCATION_STALE_MS));
    }
}
