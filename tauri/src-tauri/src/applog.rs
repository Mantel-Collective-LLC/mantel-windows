use serde_json::{json, Value};
use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

const MAX_LOG_BYTES: u64 = 1024 * 1024;
const MAX_REQUEST_ENTRIES: usize = 200;

static FILE: OnceLock<Mutex<PathBuf>> = OnceLock::new();
static VERBOSE: AtomicBool = AtomicBool::new(false);

pub fn init(data_dir: &std::path::Path) {
    let _ = FILE.set(Mutex::new(data_dir.join("logs").join("mantel.log")));
}

pub fn verbose() -> bool {
    VERBOSE.load(Ordering::SeqCst)
}

pub fn set_verbose(enabled: bool) {
    VERBOSE.store(enabled, Ordering::SeqCst);
    line("debug", &format!("verbose logging {}", if enabled { "on" } else { "off" }));
}

pub fn line(scope: &str, text: &str) {
    let Some(file) = FILE.get() else { return };
    let path = file.lock().unwrap();
    let text: String = redact(text).chars().filter(|c| !c.is_control()).take(1000).collect();
    let entry = format!("{} [{scope}] {text}\r\n", iso_now());
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if fs::metadata(&*path).map(|meta| meta.len() + entry.len() as u64 > MAX_LOG_BYTES).unwrap_or(false) {
        let _ = fs::rename(&*path, path.with_extension("log.1"));
    }
    if let Ok(mut out) = OpenOptions::new().create(true).append(true).open(&*path) {
        let _ = out.write_all(entry.as_bytes());
    }
}

pub fn iso_now() -> String {
    let ms = crate::now_ms();
    let (days, rest) = (ms / 86_400_000, ms % 86_400_000);
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z", rest / 3_600_000, rest / 60_000 % 60, rest / 1000 % 60, rest % 1000)
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

fn is_key_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '+' || c == '/'
}

pub fn redact(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        if let Some(end) = bearer_at(&chars, i) {
            out.push_str("Bearer [token]");
            i = end;
        } else if key_at(&chars, i) {
            out.push_str("[key]");
            i += 44;
        } else if let Some(end) = account_code_at(&chars, i) {
            out.push_str("[account code]");
            i = end;
        } else if is_token_char(chars[i]) && (i == 0 || !is_token_char(chars[i - 1])) {
            let end = (i..chars.len()).find(|&j| !is_token_char(chars[j])).unwrap_or(chars.len());
            if end - i >= 32 {
                out.push_str("[token]");
            } else {
                out.extend(&chars[i..end]);
            }
            i = end;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

fn bearer_at(chars: &[char], i: usize) -> Option<usize> {
    let word: String = chars.get(i..i + 6)?.iter().collect();
    if !word.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let mut j = i + 6;
    let spaces = j;
    while chars.get(j).is_some_and(|c| c.is_whitespace()) {
        j += 1;
    }
    let start = j;
    while chars.get(j).is_some_and(|c| c.is_ascii_alphanumeric() || "._~+/=-".contains(*c)) {
        j += 1;
    }
    (j > spaces && start > spaces && j > start).then_some(j)
}

fn key_at(chars: &[char], i: usize) -> bool {
    let Some(window) = chars.get(i..i + 44) else { return false };
    window[..42].iter().all(|c| is_key_char(*c)) && "AEIMQUYcgkosw480".contains(window[42]) && window[43] == '='
}

fn account_code_at(chars: &[char], i: usize) -> Option<usize> {
    if i > 0 && chars[i - 1].is_ascii_digit() {
        return None;
    }
    let mut j = i;
    for group in 0..4 {
        if group > 0 && chars.get(j).is_some_and(|c| *c == ' ' || *c == '-') {
            j += 1;
        }
        if !chars.get(j..j + 4)?.iter().all(char::is_ascii_digit) {
            return None;
        }
        j += 4;
    }
    (!chars.get(j).is_some_and(char::is_ascii_digit)).then_some(j)
}

pub fn redact_value(value: &Value) -> Value {
    const SECRET_KEYS: [&str; 9] = ["token", "accountcode", "privatekey", "presharedkey", "publickey", "authorization", "password", "secret", "accountid"];
    match value {
        Value::String(text) => json!(redact(text)),
        Value::Array(items) => Value::Array(items.iter().map(redact_value).collect()),
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, entry)| {
                    let secret = SECRET_KEYS.contains(&key.to_ascii_lowercase().as_str()) && !entry.is_null();
                    (key.clone(), if secret { json!("[redacted]") } else { redact_value(entry) })
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

#[derive(Default)]
pub struct RequestLog {
    entries: Mutex<VecDeque<Value>>,
    next: AtomicU64,
}

impl RequestLog {
    pub fn record(&self, method: &str, route: &str, status: Option<u16>, duration_ms: u64, code: Option<&str>, api_code: Option<&str>) {
        let route = redact(route);
        if verbose() {
            let status_text = status.map_or("–".to_string(), |status| status.to_string());
            let codes = code.map(|code| format!(" ({code}{})", api_code.map(|api| format!("/{api}")).unwrap_or_default())).unwrap_or_default();
            line("api", &format!("{method} {route} → {status_text} {duration_ms} ms{codes}"));
        }
        if !crate::flavor::is_debug() {
            return;
        }
        let id = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        let mut entry = json!({ "id": id, "at": crate::now_ms(), "method": method, "route": route, "status": status, "durationMs": duration_ms });
        if let Some(code) = code {
            entry["code"] = json!(code);
        }
        if let Some(api_code) = api_code {
            entry["apiCode"] = json!(api_code);
        }
        let mut entries = self.entries.lock().unwrap();
        entries.push_back(entry);
        while entries.len() > MAX_REQUEST_ENTRIES {
            entries.pop_front();
        }
    }

    pub fn entries(&self) -> Vec<Value> {
        self.entries.lock().unwrap().iter().cloned().collect()
    }

    pub fn clear(&self) {
        self.entries.lock().unwrap().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_tokens_codes_and_keys() {
        let text = [
            "Authorization: Bearer abcDEF123._~+/=-xyz",
            "code 1234 5678 9012 3456 and 1234567890123456 and 1234-5678-9012-3456",
            "key yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
            "token Qm9vX2Zvby1iYXJfYmF6LWJhcl9xdXV4LXF1dXg123456",
            "/api/v1/devices/0f8fad5b-d9cb-469f-a165-70867728950e/tor",
        ]
        .join("\n");
        let result = redact(&text);
        for secret in ["abcDEF123", "1234 5678", "1234567890123456", "1234-5678", "yAnz5TF", "Qm9vX2Zv", "0f8fad5b"] {
            assert!(!result.contains(secret), "{secret} in {result}");
        }
        assert!(result.contains("[account code]") && result.contains("[key]") && result.contains("Bearer [token]"));
    }

    #[test]
    fn keeps_ordinary_diagnostics_readable() {
        for text in ["GET /api/v1/devices/:id → 204 12 ms", "10.64.0.7/32, 198.51.100.7:51820, 2026-10-22T03:00:00.000Z", "connected node=ch-zrh firewall=true"] {
            assert_eq!(redact(text), text);
        }
        assert_eq!(redact("12345678901234567"), "12345678901234567");
    }

    #[test]
    fn redacts_secret_keys_in_objects() {
        let value = redact_value(&json!({ "token": "short", "nested": { "privateKey": "x", "nodeId": "ch-zrh" }, "code": "network" }));
        assert_eq!(value, json!({ "token": "[redacted]", "nested": { "privateKey": "[redacted]", "nodeId": "ch-zrh" }, "code": "network" }));
    }

    #[test]
    fn iso_time_shape() {
        let now = iso_now();
        assert_eq!(now.len(), 24);
        assert!(now.starts_with("20") && now.ends_with('Z'));
    }

    #[test]
    fn log_file_rotates() {
        let dir = std::env::temp_dir().join(format!("mantel-log-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        init(&dir);
        line("test", "Bearer secret-token-value");
        let path = dir.join("logs").join("mantel.log");
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("Bearer [token]") && !content.contains("secret-token-value"));
        fs::write(&path, vec![b'x'; MAX_LOG_BYTES as usize]).unwrap();
        line("test", "after rotation");
        assert!(dir.join("logs").join("mantel.log.1").exists());
        assert!(fs::read_to_string(&path).unwrap().contains("after rotation"));
        let _ = fs::remove_dir_all(&dir);
    }
}
