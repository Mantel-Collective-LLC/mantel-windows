#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    Prod,
    Debug,
}

#[derive(Debug)]
pub struct Identity {
    pub flavor: Flavor,
    pub name: &'static str,
    pub product_name: &'static str,
    pub user_data_name: &'static str,
    pub autostart_task: &'static str,
    pub service_pipe: &'static str,
}

const PROD: Identity = Identity {
    flavor: Flavor::Prod,
    name: "prod",
    product_name: "Mantel",
    user_data_name: "Mantel",
    autostart_task: "Mantel Autostart",
    service_pipe: r"\\.\pipe\mantel-service",
};

const DEBUG: Identity = Identity {
    flavor: Flavor::Debug,
    name: "debug",
    product_name: "Mantel Debug",
    user_data_name: "Mantel Debug",
    autostart_task: "Mantel Debug Autostart",
    service_pipe: r"\\.\pipe\mantel-service-debug",
};

pub fn identity() -> &'static Identity {
    match option_env!("MANTEL_FLAVOR") {
        Some("debug") => &DEBUG,
        _ => &PROD,
    }
}

pub fn is_debug() -> bool {
    identity().flavor == Flavor::Debug
}

const DEBUG_API_URL: &str = "http://localhost:3000";

pub fn api_base_url() -> &'static str {
    match option_env!("MANTEL_API_URL") {
        Some(url) if !url.is_empty() => url,
        _ => DEBUG_API_URL,
    }
}

pub const APP_VERSION: &str = env!("MANTEL_APP_VERSION");

pub fn user_agent() -> String {
    format!("MantelDesktop/{APP_VERSION} (Windows)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_matches_package_json() {
        let package: serde_json::Value = serde_json::from_str(include_str!("../../../package.json")).unwrap();
        assert_eq!(package["version"].as_str(), Some(APP_VERSION));
    }

    #[test]
    fn identities_differ() {
        assert_ne!(PROD.user_data_name, DEBUG.user_data_name);
        assert_ne!(PROD.service_pipe, DEBUG.service_pipe);
        assert_ne!(PROD.autostart_task, DEBUG.autostart_task);
    }
}
