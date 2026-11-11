use serde_json::{Map, Value};
use tauri::{AppHandle, Manager};

use crate::api::{Failure, Method, Request};
use crate::AppState;

const MAX_BODY_INPUT: usize = 1024 * 1024;
const MAX_PKCS8: usize = 4096;

fn is_ticket_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn allowed(method: &str, path: &str) -> bool {
    let parts: Vec<&str> = if path.is_empty() { Vec::new() } else { path.split('/').collect() };
    match (method, parts.as_slice()) {
        ("GET", []) | ("POST", []) | ("GET", ["keys"]) | ("POST", ["keys"]) | ("POST", ["rewrap"]) => true,
        ("DELETE", ["keys", id]) | ("GET", [id]) => is_ticket_id(id),
        ("POST", [id, action]) => is_ticket_id(id) && matches!(*action, "close" | "reopen" | "seen"),
        _ => false,
    }
}

fn query_string(query: &Map<String, Value>) -> Option<String> {
    match query.iter().next() {
        None => Some(String::new()),
        Some((name, Value::String(id))) if query.len() == 1 && name == "key" && is_ticket_id(id) => Some(format!("?key={id}")),
        _ => None,
    }
}

#[tauri::command]
pub async fn support_request(app: AppHandle, method: String, path: String, query: Option<Map<String, Value>>, body: Option<Value>) -> Result<Value, Failure> {
    let query = query_string(&query.unwrap_or_default()).ok_or_else(Failure::invalid)?;
    let body_ok = body.as_ref().is_none_or(|body| body.is_object() && body.to_string().len() <= MAX_BODY_INPUT);
    if !allowed(&method, &path) || !body_ok {
        return Err(Failure::invalid());
    }
    let route = if path.is_empty() { format!("/api/v1/tickets{query}") } else { format!("/api/v1/tickets/{path}{query}") };
    let method = match method.as_str() {
        "GET" => Method::Get,
        "POST" => Method::Post,
        _ => Method::Delete,
    };
    let mut request = Request::new(method, route).raw();
    if let Some(body) = body {
        request = request.body(body);
    }
    let answer = crate::commands::call(&app, request).await?;
    if answer["status"] == 401 {
        crate::commands::note_api_error(&app, &Failure::Api { status: 401, body: answer["body"].clone() });
    }
    Ok(answer)
}

#[tauri::command]
pub fn support_key_load(app: AppHandle) -> Value {
    app.state::<AppState>().store.lock().unwrap().secrets().ticket_key.clone().map_or(Value::Null, Value::String)
}

#[tauri::command]
pub fn support_key_save(app: AppHandle, pkcs8: String) -> Result<(), Failure> {
    let state = app.state::<AppState>();
    let mut store = state.store.lock().unwrap();
    let base64 = pkcs8.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_+/=".contains(&b));
    if !store.encryption_available() || pkcs8.is_empty() || pkcs8.len() > MAX_PKCS8 || !base64 {
        return Err(Failure::localized("supportKeyStorage", "internal"));
    }
    let secrets = crate::store::Secrets { ticket_key: Some(pkcs8), ..store.secrets().clone() };
    store.set_secrets(secrets).map_err(|_| Failure::localized("supportKeyStorage", "internal"))
}

#[tauri::command]
pub fn support_key_clear(app: AppHandle) {
    let state = app.state::<AppState>();
    let mut store = state.store.lock().unwrap();
    if store.secrets().ticket_key.is_some() {
        let secrets = crate::store::Secrets { ticket_key: None, ..store.secrets().clone() };
        let _ = store.set_secrets(secrets);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_user_ticket_routes() {
        let id = "0123456789abcdef0123456789abcdef";
        for (method, path) in [("GET", "".to_string()), ("POST", "".into()), ("POST", "keys".into()), ("GET", "keys".into()), ("DELETE", format!("keys/{id}")), ("GET", id.into()), ("POST", format!("{id}/seen")), ("POST", format!("{id}/close")), ("POST", "rewrap".into())] {
            assert!(allowed(method, &path), "{method} {path}");
        }
        for (method, path) in [("GET", "team".to_string()), ("POST", "team/rewrap".into()), ("DELETE", format!("team/devices/{id}")), ("POST", format!("{id}/status")), ("GET", "../account".into()), ("GET", "0123".into()), ("PUT", id.into()), ("DELETE", id.into())] {
            assert!(!allowed(method, &path), "{method} {path}");
        }
        assert_eq!(query_string(json!({ "key": id }).as_object().unwrap()).as_deref(), Some(&*format!("?key={id}")));
        assert_eq!(query_string(&Map::new()).as_deref(), Some(""));
        assert!(query_string(json!({ "key": "x&y=1" }).as_object().unwrap()).is_none());
        assert!(query_string(json!({ "other": id }).as_object().unwrap()).is_none());
    }
}
