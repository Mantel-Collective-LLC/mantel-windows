use serde_json::{json, Value};
use std::fs;
use std::path::Path;

use crate::store::Secrets;

fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let value = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let bytes: Vec<u8> = text.trim().trim_end_matches('=').bytes().collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut acc = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            acc |= value(c)? << (18 - 6 * i);
        }
        let n = match chunk.len() {
            4 => 3,
            3 => 2,
            2 => 1,
            _ => return None,
        };
        out.extend_from_slice(&acc.to_be_bytes()[1..1 + n]);
    }
    Some(out)
}

#[cfg(windows)]
pub(crate) mod gcm {
    use windows_sys::Win32::Security::Cryptography::*;

    pub fn run(key: &[u8], nonce: &[u8], data: &[u8], encrypt: bool) -> Option<Vec<u8>> {
        if key.len() != 32 || nonce.len() != 12 || (!encrypt && data.len() < 16) {
            return None;
        }
        let (body, tag) = if encrypt { (data, [0u8; 16]) } else { let (b, t) = data.split_at(data.len() - 16); (b, t.try_into().ok()?) };
        let mut tag = tag;
        let mut nonce = nonce.to_vec();
        let mut algorithm: BCRYPT_ALG_HANDLE = std::ptr::null_mut();
        let mut handle: BCRYPT_KEY_HANDLE = std::ptr::null_mut();
        let mut out = vec![0u8; body.len()];
        let mut written = 0u32;
        let ok = unsafe {
            let mode: Vec<u16> = "ChainingModeGCM\0".encode_utf16().collect();
            let mut ok = BCryptOpenAlgorithmProvider(&mut algorithm, BCRYPT_AES_ALGORITHM, std::ptr::null(), 0) == 0
                && BCryptSetProperty(algorithm, BCRYPT_CHAINING_MODE, mode.as_ptr() as *const u8, (mode.len() * 2) as u32, 0) == 0
                && BCryptGenerateSymmetricKey(algorithm, &mut handle, std::ptr::null_mut(), 0, key.as_ptr(), key.len() as u32, 0) == 0;
            if ok {
                let info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
                    cbSize: std::mem::size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
                    dwInfoVersion: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
                    pbNonce: nonce.as_mut_ptr(),
                    cbNonce: 12,
                    pbTag: tag.as_mut_ptr(),
                    cbTag: 16,
                    ..Default::default()
                };
                let info = &info as *const _ as *const core::ffi::c_void;
                let status = if encrypt {
                    BCryptEncrypt(handle, body.as_ptr(), body.len() as u32, info, std::ptr::null_mut(), 0, out.as_mut_ptr(), out.len() as u32, &mut written, 0)
                } else {
                    BCryptDecrypt(handle, body.as_ptr(), body.len() as u32, info, std::ptr::null_mut(), 0, out.as_mut_ptr(), out.len() as u32, &mut written, 0)
                };
                ok = status == 0;
            }
            if !handle.is_null() {
                BCryptDestroyKey(handle);
            }
            if !algorithm.is_null() {
                BCryptCloseAlgorithmProvider(algorithm, 0);
            }
            ok
        };
        if !ok {
            return None;
        }
        out.truncate(written as usize);
        if encrypt {
            out.extend_from_slice(&tag);
        }
        Some(out)
    }
}

#[cfg(windows)]
fn electron_key(directory: &Path) -> Option<Vec<u8>> {
    let state: Value = serde_json::from_str(&fs::read_to_string(directory.join("Local State")).ok()?).ok()?;
    let wrapped = base64_decode(state["os_crypt"]["encrypted_key"].as_str()?)?;
    let blob = wrapped.strip_prefix(b"DPAPI")?;
    crate::store::dpapi::run_with(blob, false, None).filter(|key| key.len() == 32)
}

#[cfg(windows)]
pub fn electron_secrets(directory: &Path, blob: &[u8]) -> Option<Secrets> {
    let rest = blob.strip_prefix(b"v10")?;
    if rest.len() < 12 + 16 {
        return None;
    }
    let key = electron_key(directory)?;
    let plain = gcm::run(&key, &rest[..12], &rest[12..], false)?;
    serde_json::from_slice(&plain).ok()
}

#[cfg(not(windows))]
pub fn electron_secrets(_: &Path, _: &[u8]) -> Option<Secrets> {
    None
}

pub fn engine_runtime(electron: &Value) -> Option<Value> {
    let node = electron["nodeId"].as_str().filter(|id| crate::store::is_identifier(id))?;
    let strings = |key: &str| -> Value { json!(electron[key].as_array().map(|list| list.iter().filter_map(Value::as_str).collect::<Vec<_>>()).unwrap_or_default()) };
    let leak = electron["leakProtection"].as_str().filter(|leak| ["wireguard", "firewall", "none"].contains(leak)).unwrap_or("none");
    let post_quantum = electron["postQuantum"].as_bool().unwrap_or(false);
    Some(json!({
        "nodeId": node,
        "city": "",
        "country": "",
        "connectedAtMs": electron["connectedAt"].as_i64().unwrap_or(0),
        "addresses": strings("addresses"),
        "dns": strings("dns"),
        "endpoint": electron["endpoint"].as_str().unwrap_or(""),
        "leakProtection": leak,
        "firewallForTunnel": electron["firewallForTunnel"].as_bool().unwrap_or(false),
        "postQuantum": post_quantum,
        "nodePq": post_quantum,
        "pqSessionKey": electron["pqSessionKey"].as_str().unwrap_or(""),
        "obfuscated": electron["obfuscated"].as_bool().unwrap_or(false),
    }))
}

pub fn migrate_runtime(directory: &Path) {
    let target = directory.join("engine").join("runtime.json");
    if target.exists() {
        return;
    }
    let Some(electron) = fs::read_to_string(directory.join("runtime.json")).ok().and_then(|text| serde_json::from_str::<Value>(&text).ok()) else { return };
    if let Some(runtime) = engine_runtime(&electron) {
        let _ = fs::create_dir_all(directory.join("engine"));
        if fs::write(&target, serde_json::to_vec_pretty(&runtime).unwrap_or_default()).is_ok() {
            crate::applog::line("app", "tunnel record taken over from the Electron app");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_like_chromium() {
        assert_eq!(base64_decode("RFBBUEk=").unwrap(), b"DPAPI");
        assert_eq!(base64_decode("YWJj").unwrap(), b"abc");
        assert_eq!(base64_decode("YQ==").unwrap(), b"a");
        assert!(base64_decode("a$==").is_none());
    }

    #[test]
    fn runtime_of_a_running_electron_tunnel() {
        let electron = json!({
            "nodeId": "ch-zrh", "connectedAt": 1_700_000_000_000i64, "addresses": ["10.64.0.7/32"], "dns": ["10.64.0.1"],
            "endpoint": "198.51.100.7:51820", "leakProtection": "firewall", "firewallForTunnel": true,
            "postQuantum": true, "pqSessionKey": "E", "obfuscated": false
        });
        let runtime = engine_runtime(&electron).unwrap();
        assert_eq!(runtime["connectedAtMs"], 1_700_000_000_000i64);
        assert_eq!(runtime["nodePq"], true);
        assert_eq!(runtime["leakProtection"], "firewall");
        assert!(engine_runtime(&json!({ "nodeId": null })).is_none());
    }

    #[cfg(windows)]
    #[test]
    fn electron_secrets_are_taken_over() {
        let directory = std::env::temp_dir().join(format!("mantel-electron-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let key = [7u8; 32];
        let wrapped = [b"DPAPI".as_slice(), &crate::store::dpapi::run_with(&key, true, None).unwrap()].concat();
        let encoded = base64_encode(&wrapped);
        fs::write(directory.join("Local State"), json!({ "os_crypt": { "encrypted_key": encoded } }).to_string()).unwrap();
        let secrets = json!({ "token": "tok", "accountId": "acc", "paidUntil": null, "device": { "id": "d1" }, "ticketKey": "pk" });
        let nonce = [3u8; 12];
        let sealed = gcm::run(&key, &nonce, secrets.to_string().as_bytes(), true).unwrap();
        let blob = [b"v10".as_slice(), &nonce, &sealed].concat();
        fs::write(directory.join("secrets.bin"), &blob).unwrap();

        let parsed = electron_secrets(&directory, &blob).unwrap();
        assert_eq!((parsed.token.as_deref(), parsed.ticket_key.as_deref()), (Some("tok"), Some("pk")));
        let store = crate::store::Store::load(directory.clone());
        assert_eq!(store.secrets().token.as_deref(), Some("tok"));
        assert!(!fs::read(directory.join("secrets.bin")).unwrap().starts_with(b"v10"));
        assert_eq!(crate::store::Store::load(directory.clone()).secrets().device_id().as_deref(), Some("d1"));
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(electron_secrets(&directory, &bad).is_none());
        let _ = fs::remove_dir_all(&directory);
    }

    #[cfg(windows)]
    fn base64_encode(data: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let n = chunk.iter().enumerate().fold(0u32, |acc, (i, &b)| acc | (b as u32) << (16 - 8 * i));
            for i in 0..4 {
                out.push(if i <= chunk.len() { ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
            }
        }
        out
    }
}
