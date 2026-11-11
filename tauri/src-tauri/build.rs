fn main() {
    println!("cargo:rerun-if-env-changed=MANTEL_FLAVOR");
    println!("cargo:rerun-if-env-changed=MANTEL_API_URL");
    let flavor = std::env::var("MANTEL_FLAVOR").unwrap_or_default();
    if !flavor.is_empty() && flavor != "prod" && flavor != "debug" {
        panic!("MANTEL_FLAVOR=\"{flavor}\" ist ungültig. Erlaubt: prod, debug.");
    }
    let release = std::env::var("PROFILE").as_deref() == Ok("release");
    if release && flavor != "debug" && std::env::var("MANTEL_API_URL").unwrap_or_default().trim().is_empty() {
        panic!("MANTEL_API_URL fehlt: prod-Builds brauchen die API-Adresse.");
    }
    println!("cargo:rerun-if-changed=../../package.json");
    let package = std::fs::read_to_string("../../package.json").expect("package.json");
    let version = package
        .lines()
        .find_map(|line| line.trim().strip_prefix("\"version\": \"")?.split('"').next().map(str::to_string))
        .expect("version in package.json");
    println!("cargo:rustc-env=MANTEL_APP_VERSION={version}");
    tauri_build::build()
}
