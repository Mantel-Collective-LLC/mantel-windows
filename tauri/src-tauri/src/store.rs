use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

use crate::flavor;

pub const LANGUAGES: [&str; 3] = ["de", "en", "system"];
pub const THEMES: [&str; 3] = ["system", "light", "dark"];
pub const OBFUSCATION_MODES: [&str; 3] = ["auto", "off", "on"];
pub const QUIT_ACTIONS: [&str; 3] = ["ask", "keep", "disconnect"];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Preferences {
    pub base_url: String,
    pub always_on_kill_switch: bool,
    pub last_node_id: Option<String>,
    pub language: String,
    pub post_quantum: bool,
    pub auto_connect_open_wifi: bool,
    pub theme: String,
    pub obfuscation: String,
    pub connect_on_launch: bool,
    pub quit_action: String,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            base_url: flavor::api_base_url().to_string(),
            always_on_kill_switch: false,
            last_node_id: None,
            language: "en".into(),
            post_quantum: false,
            auto_connect_open_wifi: false,
            theme: "system".into(),
            obfuscation: "auto".into(),
            connect_on_launch: false,
            quit_action: "ask".into(),
        }
    }
}

pub fn is_identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64 && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn pick(value: Option<&Value>, allowed: &[&str], fallback: &str) -> String {
    match value.and_then(Value::as_str) {
        Some(text) if allowed.contains(&text) => text.to_string(),
        _ => fallback.to_string(),
    }
}

fn flag(value: Option<&Value>) -> bool {
    value.and_then(Value::as_bool).unwrap_or(false)
}

impl Preferences {
    pub fn from_json(value: &Value) -> Option<Self> {
        let object = value.as_object()?;
        object.get("baseUrl")?.as_str()?;
        let always_on_kill_switch = object.get("alwaysOnKillSwitch")?.as_bool()?;
        let last_node_id = match object.get("lastNodeId")? {
            Value::Null => None,
            Value::String(id) if is_identifier(id) => Some(id.clone()),
            _ => return None,
        };
        let defaults = Self::default();
        Some(Self {
            base_url: defaults.base_url,
            always_on_kill_switch,
            last_node_id,
            language: pick(object.get("language"), &LANGUAGES, "en"),
            post_quantum: flag(object.get("postQuantum")),
            auto_connect_open_wifi: flag(object.get("autoConnectOpenWifi")),
            theme: pick(object.get("theme"), &THEMES, "system"),
            obfuscation: pick(object.get("obfuscation"), &OBFUSCATION_MODES, "auto"),
            connect_on_launch: flag(object.get("connectOnLaunch")),
            quit_action: pick(object.get("quitAction"), &QUIT_ACTIONS, "ask"),
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Secrets {
    pub token: Option<String>,
    pub account_id: Option<String>,
    pub paid_until: Option<String>,
    #[serde(default)]
    pub device: Option<Value>,
    #[serde(default)]
    pub ticket_key: Option<String>,
}

impl Secrets {
    pub fn device_id(&self) -> Option<String> {
        self.device.as_ref()?.get("id")?.as_str().filter(|id| is_identifier(id)).map(str::to_string)
    }
}

fn write_atomic(file: &Path, content: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = file.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = file.with_extension("tmp");
    fs::write(&temporary, content)?;
    fs::rename(&temporary, file)
}

pub struct Store {
    directory: PathBuf,
    preferences: Preferences,
    secrets: Secrets,
}

impl Store {
    pub fn load(directory: PathBuf) -> Self {
        let preferences = fs::read_to_string(directory.join("preferences.json"))
            .ok()
            .and_then(|text| serde_json::from_str::<Value>(&text).ok())
            .and_then(|value| Preferences::from_json(&value))
            .unwrap_or_default();
        let blob = fs::read(directory.join("secrets.bin")).ok();
        let own = blob.as_deref().and_then(dpapi::unprotect).and_then(|plain| serde_json::from_slice::<Secrets>(&plain).ok());
        let electron = if own.is_none() { blob.as_deref().and_then(|blob| crate::migrate::electron_secrets(&directory, blob)) } else { None };
        let mut store = Self { directory, preferences, secrets: own.unwrap_or_default() };
        if let Some(secrets) = electron {
            let _ = store.set_secrets(secrets);
            crate::applog::line("app", "signed-in state taken over from the Electron app");
        }
        store
    }

    pub fn encryption_available(&self) -> bool {
        dpapi::AVAILABLE
    }

    pub fn preferences(&self) -> &Preferences {
        &self.preferences
    }

    pub fn set_preferences(&mut self, next: Preferences) -> std::io::Result<()> {
        self.preferences = Preferences { base_url: flavor::api_base_url().to_string(), ..next };
        let text = serde_json::to_string_pretty(&self.preferences).map_err(std::io::Error::other)?;
        write_atomic(&self.directory.join("preferences.json"), text.as_bytes())
    }

    pub fn secrets(&self) -> &Secrets {
        &self.secrets
    }

    pub fn set_secrets(&mut self, next: Secrets) -> std::io::Result<()> {
        self.secrets = next;
        let plain = serde_json::to_vec(&self.secrets).map_err(std::io::Error::other)?;
        match dpapi::protect(&plain) {
            Some(blob) => write_atomic(&self.directory.join("secrets.bin"), &blob),
            None => Ok(()),
        }
    }

    pub fn wipe_secrets(&mut self) {
        self.secrets = Secrets::default();
        let _ = fs::remove_file(self.directory.join("secrets.bin"));
        let _ = fs::remove_file(self.directory.join("secrets.tmp"));
    }

    pub fn reset_local_data(&mut self) {
        self.wipe_secrets();
        let _ = self.set_preferences(Preferences::default());
        let _ = fs::remove_file(self.directory.join("network.json"));
    }

    pub fn session(&self) -> Value {
        let logged_in = self.secrets.token.is_some();
        json!({
            "loggedIn": logged_in,
            "accountId": if logged_in { json!(self.secrets.account_id) } else { Value::Null },
            "paidUntil": if logged_in { json!(self.secrets.paid_until) } else { Value::Null },
        })
    }
}

#[cfg(windows)]
pub(crate) mod dpapi {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    pub const AVAILABLE: bool = true;
    const ENTROPY: &[u8] = b"Mantel secrets.bin v1";

    fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 }
    }

    fn run(data: &[u8], protect: bool) -> Option<Vec<u8>> {
        run_with(data, protect, Some(ENTROPY))
    }

    pub(crate) fn run_with(data: &[u8], protect: bool, entropy: Option<&[u8]>) -> Option<Vec<u8>> {
        let input = blob(data);
        let entropy_blob = entropy.map(blob);
        let entropy: *const CRYPT_INTEGER_BLOB = entropy_blob.as_ref().map_or(std::ptr::null(), |blob| blob);
        let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
        let ok = unsafe {
            if protect {
                CryptProtectData(&input, std::ptr::null(), entropy, std::ptr::null(), std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut output)
            } else {
                CryptUnprotectData(&input, std::ptr::null_mut(), entropy, std::ptr::null(), std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut output)
            }
        };
        if ok == 0 || output.pbData.is_null() {
            return None;
        }
        let result = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
        unsafe { LocalFree(output.pbData as _) };
        Some(result)
    }

    pub fn protect(data: &[u8]) -> Option<Vec<u8>> {
        run(data, true)
    }

    pub fn unprotect(data: &[u8]) -> Option<Vec<u8>> {
        run(data, false)
    }
}

#[cfg(not(windows))]
mod dpapi {
    pub const AVAILABLE: bool = false;
    pub fn protect(_: &[u8]) -> Option<Vec<u8>> {
        None
    }
    pub fn unprotect(_: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preferences_fall_back_like_the_zod_schema() {
        let parsed = Preferences::from_json(&json!({
            "baseUrl": "https://old.example", "alwaysOnKillSwitch": true, "lastNodeId": "hk-2",
            "language": "fr", "theme": "dark", "quitAction": 3
        }))
        .unwrap();
        assert_eq!(parsed.base_url, flavor::api_base_url());
        assert!(parsed.always_on_kill_switch);
        assert_eq!(parsed.last_node_id.as_deref(), Some("hk-2"));
        assert_eq!(parsed.language, "en");
        assert_eq!(parsed.theme, "dark");
        assert_eq!(parsed.obfuscation, "auto");
        assert_eq!(parsed.quit_action, "ask");
        assert!(Preferences::from_json(&json!({ "baseUrl": "x", "alwaysOnKillSwitch": "yes", "lastNodeId": null })).is_none());
        assert!(Preferences::from_json(&json!({ "baseUrl": "x", "alwaysOnKillSwitch": false, "lastNodeId": "../x" })).is_none());
    }

    #[test]
    fn preferences_round_trip_with_electron_field_names() {
        let value = serde_json::to_value(Preferences::default()).unwrap();
        for key in ["baseUrl", "alwaysOnKillSwitch", "lastNodeId", "language", "postQuantum", "autoConnectOpenWifi", "theme", "obfuscation", "connectOnLaunch", "quitAction"] {
            assert!(value.get(key).is_some(), "{key}");
        }
        assert_eq!(Preferences::from_json(&value), Some(Preferences::default()));
    }

    #[cfg(windows)]
    #[test]
    fn secrets_are_encrypted_and_read_back() {
        let directory = std::env::temp_dir().join(format!("mantel-tauri-store-{}", std::process::id()));
        let mut store = Store::load(directory.clone());
        let secrets = Secrets { token: Some("t0ken-secret".into()), account_id: Some("acc".into()), ..Default::default() };
        store.set_secrets(secrets.clone()).unwrap();
        let raw = fs::read(directory.join("secrets.bin")).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("t0ken-secret"));
        assert_eq!(Store::load(directory.clone()).secrets(), &secrets);
        store.wipe_secrets();
        assert_eq!(Store::load(directory.clone()).secrets(), &Secrets::default());
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn identifier_check() {
        assert!(is_identifier("hk-2_A"));
        assert!(!is_identifier(""));
        assert!(!is_identifier("a/b"));
        assert!(!is_identifier(&"a".repeat(65)));
    }
}
