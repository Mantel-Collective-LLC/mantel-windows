use serde_json::{json, Value};
use std::time::Duration;

pub const SERVICE_PROTOCOL: u64 = 1;
const MAX_RESPONSE: usize = 256 * 1024;

#[derive(Debug, PartialEq)]
pub enum ServiceError {
    Unavailable(String),
    Command { code: String, detail: String },
}

pub fn request_line(op: &str) -> Vec<u8> {
    let mut line = json!({ "v": SERVICE_PROTOCOL, "client": "app", "op": op }).to_string().into_bytes();
    line.push(b'\n');
    line
}

pub fn parse_response(data: &[u8]) -> Option<Result<Value, ServiceError>> {
    let end = data.iter().position(|&byte| byte == b'\n')?;
    let parsed: Value = match serde_json::from_slice(&data[..end]) {
        Ok(value) => value,
        Err(_) => return Some(Err(ServiceError::Unavailable("unexpected answer".into()))),
    };
    match parsed.get("ok").and_then(Value::as_bool) {
        Some(true) => Some(Ok(parsed)),
        Some(false) => {
            let code = parsed.get("error").and_then(Value::as_str).unwrap_or("system").to_string();
            if code == "forbidden" {
                return Some(Err(ServiceError::Unavailable(code)));
            }
            let detail = parsed.get("detail").and_then(Value::as_str).unwrap_or("").to_string();
            Some(Err(ServiceError::Command { code, detail }))
        }
        None => Some(Err(ServiceError::Unavailable("unexpected answer".into()))),
    }
}

#[cfg(windows)]
pub async fn call(pipe: &str, op: &str, timeout: Duration) -> Result<Value, ServiceError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::windows::named_pipe::ClientOptions;

    let exchange = async {
        let mut client = ClientOptions::new().open(pipe).map_err(|error| ServiceError::Unavailable(error.to_string()))?;
        client.write_all(&request_line(op)).await.map_err(|error| ServiceError::Unavailable(error.to_string()))?;
        let mut data = Vec::new();
        let mut buffer = [0u8; 8192];
        loop {
            let read = client.read(&mut buffer).await.map_err(|error| ServiceError::Unavailable(error.to_string()))?;
            if read == 0 {
                return Err(ServiceError::Unavailable("closed".into()));
            }
            data.extend_from_slice(&buffer[..read]);
            if data.len() > MAX_RESPONSE {
                return Err(ServiceError::Unavailable("response too large".into()));
            }
            if let Some(result) = parse_response(&data) {
                return result;
            }
        }
    };
    tokio::time::timeout(timeout, exchange).await.unwrap_or_else(|_| Err(ServiceError::Unavailable("timeout".into())))
}

#[cfg(not(windows))]
pub async fn call(_pipe: &str, _op: &str, _timeout: Duration) -> Result<Value, ServiceError> {
    Err(ServiceError::Unavailable("not supported".into()))
}

#[derive(Debug, Default, PartialEq)]
pub struct Readiness {
    pub ready: bool,
    pub wireguard_directory: Option<String>,
    pub wireguard_source: Option<&'static str>,
}

pub fn readiness(hello: &Value, status: Option<&Value>, flavor: &str) -> Readiness {
    let ready = hello.get("protocol").and_then(Value::as_u64) == Some(SERVICE_PROTOCOL) && hello.get("flavor").and_then(Value::as_str) == Some(flavor);
    if !ready {
        return Readiness::default();
    }
    let wireguard = status.and_then(|status| status.get("wireguard"));
    Readiness {
        ready,
        wireguard_directory: wireguard.and_then(|wg| wg.get("directory")).and_then(Value::as_str).map(str::to_string),
        wireguard_source: wireguard.map(|wg| if wg.get("source").and_then(Value::as_str) == Some("system") { "system" } else { "managed" }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_carries_protocol_header() {
        let line = request_line("hello");
        assert_eq!(line.last(), Some(&b'\n'));
        let value: Value = serde_json::from_slice(&line[..line.len() - 1]).unwrap();
        assert_eq!(value, json!({ "v": 1, "client": "app", "op": "hello" }));
    }

    #[test]
    fn parses_answers() {
        assert_eq!(parse_response(b"{\"ok\":true"), None);
        assert_eq!(parse_response(b"{\"ok\":true,\"protocol\":1}\nrest"), Some(Ok(json!({ "ok": true, "protocol": 1 }))));
        assert_eq!(parse_response(b"{\"ok\":false,\"error\":\"forbidden\"}\n"), Some(Err(ServiceError::Unavailable("forbidden".into()))));
        assert_eq!(
            parse_response(b"{\"ok\":false,\"error\":\"invalid\",\"detail\":\"x\"}\n"),
            Some(Err(ServiceError::Command { code: "invalid".into(), detail: "x".into() }))
        );
        assert!(matches!(parse_response(b"nope\n"), Some(Err(ServiceError::Unavailable(_)))));
    }

    #[test]
    fn readiness_needs_same_protocol_and_flavor() {
        let status = json!({ "wireguard": { "directory": "C:\\WG", "source": "system" } });
        let ready = readiness(&json!({ "protocol": 1, "flavor": "prod" }), Some(&status), "prod");
        assert_eq!(ready, Readiness { ready: true, wireguard_directory: Some("C:\\WG".into()), wireguard_source: Some("system") });
        assert_eq!(readiness(&json!({ "protocol": 1, "flavor": "debug" }), Some(&status), "prod"), Readiness::default());
        assert_eq!(readiness(&json!({ "protocol": 2, "flavor": "prod" }), None, "prod"), Readiness::default());
    }
}
