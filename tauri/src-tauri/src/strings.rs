use serde_json::Value;
use std::sync::OnceLock;

fn dictionary(language: &str) -> &'static Value {
    static EN: OnceLock<Value> = OnceLock::new();
    static DE: OnceLock<Value> = OnceLock::new();
    if language == "de" {
        DE.get_or_init(|| serde_json::from_str(include_str!("../../../shared/core/i18n/de.json")).expect("de.json"))
    } else {
        EN.get_or_init(|| serde_json::from_str(include_str!("../../../shared/core/i18n/en.json")).expect("en.json"))
    }
}

pub fn language_of(preference: &str) -> &'static str {
    if preference == "de" {
        "de"
    } else {
        "en"
    }
}

pub fn text(language: &str, path: &str) -> String {
    let lookup = |root: &Value| path.split('.').try_fold(root, |node, key| node.get(key)).and_then(Value::as_str).map(str::to_string);
    lookup(dictionary(language)).or_else(|| lookup(dictionary("en"))).unwrap_or_else(|| path.to_string())
}

pub fn format(template: &str, params: &[(&str, &str)]) -> String {
    params.iter().fold(template.to_string(), |text, (key, value)| text.replace(&format!("{{{key}}}"), value))
}

pub fn failure_text(language: &str, failure: &crate::api::Failure) -> String {
    match failure {
        crate::api::Failure::Localized { key, params, .. } if key == "__plain" => params.get("message").and_then(Value::as_str).unwrap_or_default().to_string(),
        crate::api::Failure::Localized { key, params, .. } => {
            let values: Vec<(String, String)> = params.iter().map(|(name, value)| (name.clone(), value.as_str().map(str::to_string).unwrap_or_else(|| value.to_string()))).collect();
            let pairs: Vec<(&str, &str)> = values.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();
            format(&text(language, &format!("errors.{key}")), &pairs)
        }
        crate::api::Failure::Api { status, .. } => format!("{} ({status})", text(language, "errors.unknown")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_shared_dictionaries() {
        assert_eq!(text("en", "tray.quit"), "Quit");
        assert_ne!(text("de", "tray.quit"), "tray.quit");
        assert_eq!(format(&text("en", "tray.title"), &[("status", "Connected")]), "Mantel · Connected");
        assert_eq!(text("en", "tray.nope"), "tray.nope");
        assert_eq!(failure_text("en", &crate::api::Failure::localized("apiNotLoggedIn", "auth")), "Not signed in.");
        for key in ["connect", "disconnect", "openWindow", "disableKillSwitch", "quit", "status.connected", "status.disconnected", "status.connecting", "status.disconnecting", "status.stale"] {
            assert_ne!(text("de", &format!("tray.{key}")), format!("tray.{key}"));
        }
    }
}
