use serde::Serialize;
use serde_json::{json, Map, Value};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tauri::AppHandle;

use crate::flavor;

static APP: OnceLock<AppHandle> = OnceLock::new();

pub fn attach(app: &AppHandle) {
    let _ = APP.set(app.clone());
}

#[derive(Debug)]
struct DnsFailure(Failure);

impl std::fmt::Display for DnsFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{:?}", self.0)
    }
}

impl std::error::Error for DnsFailure {}

struct PinnedDns;

fn addresses_of(value: &Value) -> Vec<SocketAddr> {
    value["addresses"].as_array().into_iter().flatten().filter_map(Value::as_str).filter_map(|text| text.parse::<IpAddr>().ok()).map(|ip| SocketAddr::new(ip, 0)).collect()
}

impl reqwest::dns::Resolve for PinnedDns {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            if let Some(app) = APP.get() {
                match crate::engine::request(app, json!({ "op": "resolve", "host": host }), Duration::from_secs(10)).await {
                    Ok(value) => {
                        let found = addresses_of(&value);
                        if !found.is_empty() {
                            return Ok(Box::new(found.into_iter()) as reqwest::dns::Addrs);
                        }
                    }
                    Err(Failure::Localized { key, params, code }) if key == "dnsBlockedUnknownHost" || key == "hostUnresolved" => {
                        return Err(Box::new(DnsFailure(Failure::Localized { key, params, code })) as Box<dyn std::error::Error + Send + Sync>);
                    }
                    Err(_) => {}
                }
            }
            let found: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            Ok(Box::new(found.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

fn send_failure(error: &reqwest::Error) -> Failure {
    let mut source = std::error::Error::source(error);
    while let Some(inner) = source {
        if let Some(DnsFailure(failure)) = inner.downcast_ref::<DnsFailure>() {
            return failure.clone();
        }
        source = inner.source();
    }
    Failure::localized("apiUnreachable", "network")
}

const MAX_BODY_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Failure {
    Localized { key: String, params: Map<String, Value>, code: String },
    Api { status: u16, body: Value },
}

impl Failure {
    pub fn localized(key: &str, code: &str) -> Self {
        Failure::Localized { key: key.into(), params: Map::new(), code: code.into() }
    }

    pub fn with_params(key: &str, code: &str, params: Value) -> Self {
        Failure::Localized { key: key.into(), params: params.as_object().cloned().unwrap_or_default(), code: code.into() }
    }

    pub fn invalid() -> Self {
        Self::localized("invalidInput", "invalid")
    }

    pub fn status(&self) -> Option<u16> {
        match self {
            Failure::Api { status, .. } => Some(*status),
            Failure::Localized { .. } => None,
        }
    }

    pub fn api_code(&self) -> Option<&str> {
        match self {
            Failure::Api { body, .. } => body.get("code").and_then(Value::as_str),
            Failure::Localized { .. } => None,
        }
    }

    pub fn is_network(&self) -> bool {
        matches!(self, Failure::Localized { code, .. } if code == "network")
    }

    pub fn ends_session(&self) -> bool {
        match (self.status(), self.api_code()) {
            (None, _) => false,
            (Some(_), Some(code)) => code == "unauthorized" || code == "account_not_found",
            (Some(status), None) => status == 401,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Method {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

pub enum Auth {
    None,
    Required,
    Optional,
}

pub struct Request<'a> {
    pub method: Method,
    pub route: String,
    pub body: Option<Value>,
    pub auth: Auth,
    pub expect: &'a [u16],
    pub raw: bool,
}

const MAX_RAW_BODY_BYTES: usize = 8 * 1024 * 1024;

impl<'a> Request<'a> {
    pub fn new(method: Method, route: impl Into<String>) -> Self {
        Self { method, route: route.into(), body: None, auth: Auth::Required, expect: &[200], raw: false }
    }
    pub fn raw(mut self) -> Self {
        self.raw = true;
        self
    }
    pub fn body(mut self, body: Value) -> Self {
        self.body = Some(body);
        self
    }
    pub fn auth(mut self, auth: Auth) -> Self {
        self.auth = auth;
        self
    }
    pub fn expect(mut self, expect: &'a [u16]) -> Self {
        self.expect = expect;
        self
    }
}

pub struct Client {
    http: reqwest::Client,
    pub requests: crate::applog::RequestLog,
}

fn not_json(status: u16, content_type: Option<&str>, server: Option<&str>, mitigated: Option<&str>) -> Failure {
    let html = content_type.unwrap_or("").contains("text/html");
    let cloudflare = mitigated == Some("challenge") || (server == Some("cloudflare") && html);
    let key = if cloudflare {
        "apiCloudflare"
    } else if status == 404 {
        "apiNoMantelApi"
    } else {
        "apiInvalidJson"
    };
    let content_type = content_type.map(|value| json!(value)).unwrap_or_else(|| json!({ "key": "apiUnknownContentType" }));
    Failure::with_params(key, "server", json!({ "status": status, "contentType": content_type }))
}

pub fn evaluate(status: u16, expect: &[u16], body: &[u8], headers: [Option<&str>; 3]) -> Result<Value, Failure> {
    if (300..400).contains(&status) {
        return Err(Failure::localized("apiRedirected", "network"));
    }
    let value = if body.is_empty() {
        Value::Null
    } else {
        match serde_json::from_slice::<Value>(body) {
            Ok(value) => value,
            Err(_) => return Err(not_json(status, headers[0], headers[1], headers[2])),
        }
    };
    if !expect.contains(&status) {
        return Err(Failure::Api { status, body: value });
    }
    Ok(value)
}

impl Client {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(flavor::user_agent())
            .dns_resolver(Arc::new(PinnedDns))
            .build()
            .expect("HTTP client");
        Self { http, requests: Default::default() }
    }

    pub async fn send(&self, request: Request<'_>, token: Option<&str>, language: &str) -> Result<Value, Failure> {
        let started = std::time::Instant::now();
        let (method, route) = (format!("{:?}", request.method).to_uppercase(), request.route.to_string());
        let (status, result) = self.send_once(request, token, language).await;
        let (code, api_code) = match &result {
            Ok(_) => (None, None),
            Err(Failure::Api { body, .. }) => (None, body.get("code").and_then(Value::as_str).filter(|code| code.len() <= 64).map(str::to_string)),
            Err(Failure::Localized { code, .. }) => (Some(code.clone()), None),
        };
        self.requests.record(&method, &route, status, started.elapsed().as_millis() as u64, code.as_deref(), api_code.as_deref());
        result
    }

    async fn send_once(&self, request: Request<'_>, token: Option<&str>, language: &str) -> (Option<u16>, Result<Value, Failure>) {
        let url = format!("{}{}", flavor::api_base_url(), request.route);
        let method = match request.method {
            Method::Get => reqwest::Method::GET,
            Method::Post => reqwest::Method::POST,
            Method::Put => reqwest::Method::PUT,
            Method::Patch => reqwest::Method::PATCH,
            Method::Delete => reqwest::Method::DELETE,
        };
        let mut builder = self.http.request(method, &url).header("Accept", "application/json").header("Accept-Language", language);
        match (&request.auth, token) {
            (Auth::None, _) => {}
            (Auth::Required, None) => return (None, Err(Failure::localized("apiNotLoggedIn", "unauthorized"))),
            (_, Some(token)) => builder = builder.bearer_auth(token),
            (Auth::Optional, None) => {}
        }
        if let Some(body) = &request.body {
            builder = builder.header("Content-Type", "application/json").body(body.to_string());
        }
        let mut response = match builder.send().await {
            Ok(response) => response,
            Err(error) => return (None, Err(send_failure(&error))),
        };
        let status = response.status().as_u16();
        let header = |name: &str| response.headers().get(name).and_then(|value| value.to_str().ok()).map(str::to_string);
        let (content_type, server, mitigated) = (header("content-type"), header("server"), header("cf-mitigated"));
        let mut body = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    if body.len() + chunk.len() > if request.raw { MAX_RAW_BODY_BYTES } else { MAX_BODY_BYTES } {
                        return (Some(status), Err(Failure::localized("apiTooLarge", "server")));
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(_) => return (Some(status), Err(Failure::localized("apiUnreachable", "network"))),
            }
        }
        let headers = [content_type.as_deref(), server.as_deref(), mitigated.as_deref()];
        if request.raw {
            return (Some(status), evaluate(status, &[status], &body, headers).map(|body| json!({ "status": status, "body": body })));
        }
        (Some(status), evaluate(status, request.expect, &body, headers))
    }
}

pub fn segment(id: &str) -> &str {
    debug_assert!(crate::store::is_identifier(id));
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ends_session_like_shared_api_errors() {
        let api = |status, body| Failure::Api { status, body };
        assert!(api(401, Value::Null).ends_session());
        assert!(api(403, json!({ "code": "account_not_found" })).ends_session());
        assert!(!api(401, json!({ "code": "totp_required" })).ends_session());
        assert!(!Failure::localized("apiUnreachable", "network").ends_session());
    }

    #[test]
    fn evaluates_status_and_body() {
        assert_eq!(evaluate(200, &[200], br#"{"a":1}"#, [None; 3]), Ok(json!({ "a": 1 })));
        assert_eq!(evaluate(204, &[204, 200], b"", [None; 3]), Ok(Value::Null));
        assert_eq!(evaluate(302, &[200], b"", [None; 3]), Err(Failure::localized("apiRedirected", "network")));
        assert_eq!(evaluate(400, &[200], br#"{"code":"x"}"#, [None; 3]), Err(Failure::Api { status: 400, body: json!({ "code": "x" }) }));
        match evaluate(403, &[200], b"<html>", [Some("text/html"), Some("cloudflare"), None]) {
            Err(Failure::Localized { key, code, params }) => {
                assert_eq!((key.as_str(), code.as_str()), ("apiCloudflare", "server"));
                assert_eq!(params["status"], 403);
            }
            other => panic!("{other:?}"),
        }
        match evaluate(404, &[200], b"nope", [None; 3]) {
            Err(Failure::Localized { key, params, .. }) => {
                assert_eq!(key, "apiNoMantelApi");
                assert_eq!(params["contentType"], json!({ "key": "apiUnknownContentType" }));
            }
            other => panic!("{other:?}"),
        }
    }
}

#[cfg(test)]
mod dns_tests {
    use super::*;

    #[test]
    fn engine_addresses_become_socket_addresses() {
        let found = addresses_of(&json!({ "addresses": ["203.0.113.1", "2001:db8::1", "not-an-ip", 7] }));
        assert_eq!(found, vec!["203.0.113.1:0".parse().unwrap(), "[2001:db8::1]:0".parse().unwrap()]);
        assert!(addresses_of(&json!({})).is_empty());
    }
}
