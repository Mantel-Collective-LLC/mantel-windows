use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{ChildStdin, Command};
use tokio::sync::oneshot;

use crate::api::Failure;
use crate::store::Secrets;
use crate::AppState;

const MAX_LINE: usize = 256 * 1024;

type Reply = Result<Value, Failure>;

#[derive(Default)]
pub struct Engine {
    stdin: tokio::sync::Mutex<Option<ChildStdin>>,
    pending: Mutex<HashMap<u64, oneshot::Sender<Reply>>>,
    next: AtomicU64,
}

fn engine_exe(app: &AppHandle) -> Option<PathBuf> {
    if cfg!(debug_assertions) {
        if let Ok(path) = std::env::var("MANTEL_ENGINE_EXE") {
            return Some(PathBuf::from(path));
        }
    }
    let path = app.path().resource_dir().ok()?.join("service").join("mantel.exe");
    path.exists().then_some(path)
}

fn failure_of(error: &Value, text: Option<&str>) -> Failure {
    let key = error.get("key").and_then(Value::as_str).filter(|key| key.len() <= 64 && key.bytes().all(|b| b.is_ascii_alphanumeric())).unwrap_or("helperCommand");
    if let (true, Some(text)) = (key.starts_with("cli"), text) {
        let message: String = text.chars().take(400).collect();
        return Failure::Localized { key: "__plain".into(), params: Map::from_iter([("message".into(), json!(message))]), code: "internal".into() };
    }
    let params = error.get("params").and_then(Value::as_object).cloned().unwrap_or_default();
    let code = match key {
        "apiUnreachable" | "apiRedirected" | "apiTooLarge" | "dnsTimeout" => "network",
        "apiNotLoggedIn" => "auth",
        _ => "internal",
    };
    Failure::Localized { key: key.to_string(), params, code: code.into() }
}

impl Engine {
    pub async fn start(app: &AppHandle, directory: PathBuf) {
        let Some(exe) = engine_exe(app) else {
            crate::applog::line("engine", r"service\mantel.exe not found: tunnel actions unavailable");
            return;
        };
        let mut command = Command::new(exe);
        command.arg("engine").arg("--dir").arg(&directory).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).kill_on_drop(true);
        if crate::flavor::is_debug() {
            command.env("MANTEL_API_URL", crate::flavor::api_base_url());
        }
        #[cfg(windows)]
        command.creation_flags(0x0800_0000);
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                crate::applog::line("engine", &format!("start failed: {error}"));
                return;
            }
        };
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else { return };
        let state = app.state::<AppState>();
        *state.engine.stdin.lock().await = Some(stdin);
        let handle = app.clone();
        tauri::async_runtime::spawn(async move {
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) if line.len() > MAX_LINE => continue,
                    Ok(_) => {
                        if let Ok(message) = serde_json::from_str::<Value>(&line) {
                            on_message(&handle, message);
                        }
                    }
                }
            }
            let state = handle.state::<AppState>();
            *state.engine.stdin.lock().await = None;
            for (_, sender) in state.engine.pending.lock().unwrap().drain() {
                let _ = sender.send(Err(Failure::localized("helperUnavailable", "elevation")));
            }
            let code = child.wait().await.ok().and_then(|status| status.code());
            crate::applog::line("engine", &format!("ended (exit code {})", code.map_or("–".to_string(), |code| code.to_string())));
        });
        push_secrets(app, true).await;
        let always_on = state.store.lock().unwrap().preferences().always_on_kill_switch;
        let _ = request(app, json!({ "op": "always-on-flag", "enabled": always_on }), Duration::from_secs(5)).await;
        let language = state.language();
        let _ = request(app, json!({ "op": "language", "language": language }), Duration::from_secs(5)).await;
    }
}

fn on_message(app: &AppHandle, message: Value) {
    let state = app.state::<AppState>();
    if let Some(id) = message.get("id").and_then(Value::as_u64) {
        let Some(sender) = state.engine.pending.lock().unwrap().remove(&id) else { return };
        let reply = if message.get("ok") == Some(&Value::Bool(true)) {
            Ok(message.get("result").cloned().unwrap_or(Value::Null))
        } else {
            Err(failure_of(message.get("error").unwrap_or(&Value::Null), message.get("text").and_then(Value::as_str)))
        };
        let _ = sender.send(reply);
        return;
    }
    match message.get("event").and_then(Value::as_str) {
        Some("secrets") => adopt_secrets(app, message.get("secrets").unwrap_or(&Value::Null)),
        Some("progress") if message.get("step").and_then(Value::as_str) == Some("pq") => {
            crate::publish(app, json!({ "quantum": "negotiating" }));
        }
        _ => {}
    }
}

fn adopt_secrets(app: &AppHandle, value: &Value) {
    let text = |name: &str| value.get(name).and_then(Value::as_str).filter(|text| !text.is_empty()).map(str::to_string);
    let state = app.state::<AppState>();
    let ended = {
        let mut store = state.store.lock().unwrap();
        let previous = store.secrets().clone();
        let next = Secrets {
            token: text("token"),
            account_id: text("accountId"),
            paid_until: text("paidUntil"),
            device: value.get("device").filter(|device| device.is_object()).cloned(),
            ticket_key: previous.ticket_key.clone(),
        };
        let ended = previous.token.is_some() && next.token.is_none();
        let _ = store.set_secrets(next);
        ended
    };
    if ended {
        let _ = app.emit("session-ended", ());
    }
    crate::update_tray(app);
}

pub async fn push_secrets(app: &AppHandle, with_device: bool) {
    let secrets = app.state::<AppState>().store.lock().unwrap().secrets().clone();
    let value = json!({
        "token": secrets.token.unwrap_or_default(),
        "accountId": secrets.account_id.unwrap_or_default(),
        "paidUntil": secrets.paid_until.unwrap_or_default(),
        "device": secrets.device,
    });
    let _ = request(app, json!({ "op": "secrets", "secrets": value, "withDevice": with_device }), Duration::from_secs(5)).await;
}

pub async fn request(app: &AppHandle, mut body: Value, timeout: Duration) -> Reply {
    let state = app.state::<AppState>();
    let engine = &state.engine;
    let id = engine.next.fetch_add(1, Ordering::SeqCst) + 1;
    if let Some(object) = body.as_object_mut() {
        object.insert("id".into(), json!(id));
    }
    let (sender, receiver) = oneshot::channel();
    engine.pending.lock().unwrap().insert(id, sender);
    let line = format!("{body}\n");
    let sent = match engine.stdin.lock().await.as_mut() {
        Some(stdin) => stdin.write_all(line.as_bytes()).await.is_ok() && stdin.flush().await.is_ok(),
        None => false,
    };
    if !sent {
        engine.pending.lock().unwrap().remove(&id);
        return Err(Failure::localized("helperUnavailable", "elevation"));
    }
    match tokio::time::timeout(timeout, receiver).await {
        Ok(Ok(reply)) => reply,
        _ => {
            engine.pending.lock().unwrap().remove(&id);
            Err(Failure::localized("helperUnavailable", "elevation"))
        }
    }
}

pub fn spawn_push_secrets(app: &AppHandle, with_device: bool) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move { push_secrets(&app, with_device).await });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_errors_become_localized_failures() {
        match failure_of(&json!({ "key": "apiNotLoggedIn" }), None) {
            Failure::Localized { key, .. } => assert_eq!(key, "apiNotLoggedIn"),
            other => panic!("{other:?}"),
        }
        match failure_of(&json!({ "key": "errors.x/../y" }), None) {
            Failure::Localized { key, .. } => assert_eq!(key, "helperCommand"),
            other => panic!("{other:?}"),
        }
        match failure_of(&json!({ "key": "cliForceNeedsAdmin" }), Some("Needs admin.")) {
            Failure::Localized { key, params, .. } => assert_eq!((key.as_str(), params["message"].as_str()), ("__plain", Some("Needs admin."))),
            other => panic!("{other:?}"),
        }
    }
}
