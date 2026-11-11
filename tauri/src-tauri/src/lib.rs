mod api;
mod applog;
mod commands;
mod debug;
mod engine;
mod flavor;
mod latency;
mod migrate;
mod service;
mod store;
mod strings;
mod support;
mod system;
mod tray_icon;
mod tunnel;

use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::image::Image;
use tauri::menu::{Menu, MenuBuilder, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::window::Color;
use tauri::{AppHandle, Emitter, Manager, RunEvent, Theme, WebviewUrl, WebviewWindowBuilder, WindowEvent};

pub(crate) const DISABLE_KILLSWITCH_FLAG: &str = "--disable-killswitch";
const TRAY_ID: &str = "main";
const WINDOW: &str = "main";

pub(crate) struct PendingRegistration {
    token: String,
    account_id: String,
    paid_until: String,
}

#[derive(Clone)]
pub(crate) struct NodeInfo {
    id: String,
    online: bool,
    host: String,
    ping_port: Option<u16>,
}

pub(crate) struct AppState {
    store: Mutex<store::Store>,
    api: api::Client,
    pending: Mutex<Option<PendingRegistration>>,
    nodes: Mutex<Vec<NodeInfo>>,
    obfs_tokens: Mutex<HashMap<String, String>>,
    status: Mutex<Value>,
    measuring: AtomicBool,
    quitting: AtomicBool,
    queue: tokio::sync::Mutex<()>,
    engine: engine::Engine,
    poller: tunnel::Poller,
    operation: AtomicBool,
    update_required: AtomicBool,
    tunnel_queue: tokio::sync::Mutex<()>,
}

pub(crate) fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|duration| duration.as_millis() as u64).unwrap_or(0)
}

fn initial_status() -> Value {
    json!({
        "phase": "disconnected", "nodeId": null, "connectedAt": null, "lastHandshakeAt": null, "rxBytes": 0, "txBytes": 0,
        "endpoint": null, "addresses": [], "dns": [], "leakProtection": "none", "firewallActive": false,
        "serviceState": null, "error": null, "checkedAt": now_ms(), "quantum": "off", "obfuscated": false
    })
}

impl AppState {
    fn new(directory: std::path::PathBuf) -> Self {
        Self {
            store: Mutex::new(store::Store::load(directory)),
            api: api::Client::new(),
            pending: Mutex::new(None),
            nodes: Mutex::new(Vec::new()),
            obfs_tokens: Mutex::new(HashMap::new()),
            status: Mutex::new(initial_status()),
            measuring: AtomicBool::new(false),
            quitting: AtomicBool::new(false),
            queue: tokio::sync::Mutex::new(()),
            engine: engine::Engine::default(),
            poller: tunnel::Poller::default(),
            operation: AtomicBool::new(false),
            tunnel_queue: tokio::sync::Mutex::new(()),
            update_required: AtomicBool::new(false),
        }
    }

    pub(crate) fn language(&self) -> &'static str {
        strings::language_of(&self.store.lock().unwrap().preferences().language)
    }

    pub(crate) fn status(&self) -> Value {
        self.status.lock().unwrap().clone()
    }
}

pub(crate) fn publish(app: &AppHandle, patch: Value) {
    let state = app.state::<AppState>();
    let next = {
        let mut status = state.status.lock().unwrap();
        log_status_change(&status, &patch);
        if let (Some(target), Some(source)) = (status.as_object_mut(), patch.as_object()) {
            for (key, value) in source {
                target.insert(key.clone(), value.clone());
            }
            target.insert("checkedAt".into(), json!(now_ms()));
        }
        status.clone()
    };
    let _ = app.emit("tunnel-status", next);
    update_tray(app);
}

fn log_status_change(before: &Value, patch: &Value) {
    let phase = patch.get("phase").filter(|phase| *phase != &before["phase"]);
    let error = patch.get("error").and_then(Value::as_str).filter(|error| Some(*error) != before["error"].as_str());
    if let Some(phase) = phase.and_then(Value::as_str) {
        let node = patch.get("nodeId").unwrap_or(&before["nodeId"]).as_str().unwrap_or("–");
        let firewall = patch.get("firewallActive").unwrap_or(&before["firewallActive"]);
        applog::line("tunnel", &format!("{phase} node={node} firewall={firewall}"));
    }
    if let Some(error) = error {
        applog::line("error", error);
    }
}

fn theme_colors(app: &AppHandle) -> (bool, Color) {
    let preference = app.state::<AppState>().store.lock().unwrap().preferences().theme.clone();
    let system_dark = app.get_webview_window(WINDOW).and_then(|window| window.theme().ok()).map(|theme| theme == Theme::Dark).unwrap_or(false);
    let dark = match preference.as_str() {
        "dark" => true,
        "light" => false,
        _ => system_dark,
    };
    (dark, if dark { Color(0x0c, 0x0c, 0x0e, 255) } else { Color(0xfa, 0xfa, 0xf9, 255) })
}

pub(crate) fn apply_theme(app: &AppHandle) {
    let (_, color) = theme_colors(app);
    if let Some(window) = app.get_webview_window(WINDOW) {
        let _ = window.set_background_color(Some(color));
    }
}

fn create_window(app: &AppHandle) -> tauri::Result<()> {
    let (_, color) = theme_colors(app);
    let dev_url = app.config().build.dev_url.clone();
    let window = WebviewWindowBuilder::new(app, WINDOW, WebviewUrl::App("index.html".into()))
        .title(flavor::identity().product_name)
        .inner_size(420.0, 720.0)
        .min_inner_size(380.0, 620.0)
        .decorations(false)
        .visible(false)
        .devtools(flavor::is_debug())
        .background_color(color)
        .on_navigation(move |url| {
            let app_origin = matches!((url.scheme(), url.host_str()), ("tauri", Some("localhost")) | ("http", Some("tauri.localhost")) | ("https", Some("tauri.localhost")));
            app_origin || dev_url.as_ref().is_some_and(|dev| dev.origin() == url.origin())
        })
        .build()?;
    let handle = window.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_secs(4)).await;
        if !handle.is_visible().unwrap_or(true) {
            let _ = handle.show();
        }
    });
    Ok(())
}

pub(crate) fn show_window(app: &AppHandle) {
    match app.get_webview_window(WINDOW) {
        Some(window) => {
            let _ = window.unminimize();
            let _ = window.show();
            let _ = window.set_focus();
        }
        None => {
            let _ = create_window(app);
        }
    }
}

fn tray_menu(app: &AppHandle) -> tauri::Result<Menu<tauri::Wry>> {
    let state = app.state::<AppState>();
    let status = state.status();
    let language = state.language();
    let (logged_in, always_on) = {
        let store = state.store.lock().unwrap();
        (store.secrets().token.is_some(), store.preferences().always_on_kill_switch)
    };
    let phase = status["phase"].as_str().unwrap_or("disconnected");
    let active = phase != "disconnected";
    let firewall = status["firewallActive"].as_bool().unwrap_or(false);
    let text = |key: &str| strings::text(language, key);
    let title = tray_title(language, phase);
    let mut menu = MenuBuilder::new(app).item(&MenuItem::with_id(app, "title", &title, false, None::<&str>)?).separator();
    menu = if active {
        menu.item(&MenuItem::with_id(app, "disconnect", text("tray.disconnect"), true, None::<&str>)?)
    } else {
        menu.item(&MenuItem::with_id(app, "connect", text("tray.connect"), logged_in, None::<&str>)?)
    };
    menu = menu.item(&MenuItem::with_id(app, "open", text("tray.openWindow"), true, None::<&str>)?).separator();
    if firewall || always_on {
        menu = menu.item(&MenuItem::with_id(app, "disable-killswitch", text("tray.disableKillSwitch"), true, None::<&str>)?);
    }
    menu.item(&MenuItem::with_id(app, "quit", text("tray.quit"), true, None::<&str>)?).build()
}

fn tray_title(language: &str, phase: &str) -> String {
    let status = strings::text(language, &format!("tray.status.{phase}"));
    let title = strings::format(&strings::text(language, "tray.title"), &[("status", &status)]);
    match title.strip_prefix("Mantel") {
        Some(rest) => format!("{}{rest}", flavor::identity().product_name),
        None => title,
    }
}

pub(crate) fn update_tray(app: &AppHandle) {
    let Some(tray) = app.tray_by_id(TRAY_ID) else { return };
    let state = app.state::<AppState>();
    let phase = state.status()["phase"].as_str().unwrap_or("disconnected").to_string();
    let _ = tray.set_icon(Some(Image::new_owned(tray_icon::render(32, &phase), 32, 32)));
    let _ = tray.set_tooltip(Some(tray_title(state.language(), &phase)));
    if let Ok(menu) = tray_menu(app) {
        let _ = tray.set_menu(Some(menu));
    }
}

fn create_tray(app: &AppHandle) -> tauri::Result<()> {
    TrayIconBuilder::with_id(TRAY_ID)
        .icon(Image::new_owned(tray_icon::render(32, "disconnected"), 32, 32))
        .menu(&tray_menu(app)?)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "connect" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move { tray_connect(&app).await });
            }
            "disconnect" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    if let Err(failure) = tunnel::disconnect(&app).await {
                        message_box(&strings::failure_text(app.state::<AppState>().language(), &failure));
                    }
                });
            }
            "open" => show_window(app),
            "disable-killswitch" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move { disable_kill_switch_interactive(&app).await });
            }
            "quit" => quit(app),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                show_window(tray.app_handle());
            }
        })
        .build(app)?;
    update_tray(app);
    Ok(())
}

async fn tray_connect(app: &AppHandle) {
    let node = app.state::<AppState>().store.lock().unwrap().preferences().last_node_id.clone();
    let Some(node) = node else { return show_window(app) };
    if let Err(failure) = tunnel::connect(app, node).await {
        message_box(&strings::failure_text(app.state::<AppState>().language(), &failure));
    }
}

async fn connect_at_login(app: &AppHandle) {
    let state = app.state::<AppState>();
    let (wanted, node) = {
        let store = state.store.lock().unwrap();
        (store.preferences().connect_on_launch && store.secrets().token.is_some(), store.preferences().last_node_id.clone())
    };
    let Some(node) = node.filter(|_| wanted) else { return };
    let autostart = tauri::async_runtime::spawn_blocking(|| system::autostart_enabled(flavor::identity().autostart_task)).await.unwrap_or(false);
    if !autostart {
        return;
    }
    for attempt in 1..=6 {
        if state.status()["phase"] != "disconnected" {
            return;
        }
        match tunnel::connect(app, node.clone()).await {
            Ok(_) => return,
            Err(failure) if failure.is_network() && attempt < 6 => tokio::time::sleep(Duration::from_secs(15)).await,
            Err(_) => return,
        }
    }
}

fn quit_plan(phase: &str, remembered: &str) -> &'static str {
    if phase == "disconnected" {
        return "quit";
    }
    match (phase, remembered) {
        ("connected", "keep") => "keep",
        ("connected", "disconnect") => "disconnect",
        _ => "ask",
    }
}

fn quit(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move { quit_flow(&app).await });
}

async fn quit_flow(app: &AppHandle) {
    let state = app.state::<AppState>();
    let status = state.status();
    let phase = status["phase"].as_str().unwrap_or("disconnected").to_string();
    let remembered = state.store.lock().unwrap().preferences().quit_action.clone();
    let mut choice = quit_plan(&phase, &remembered).to_string();
    if choice == "ask" {
        let language = state.language();
        let working = phase == "connected";
        let blocked = !working && status["firewallActive"].as_bool().unwrap_or(false);
        let text = |key: &str| strings::text(language, &format!("dialogs.{key}"));
        let detail = if blocked {
            text("quitBlockedDetail")
        } else {
            text("quitDetail")
        };
        let dialog = QuitDialog {
            title: text("quitTitle"),
            message: if blocked { text("quitBlockedMessage") } else { text("quitMessage") },
            detail,
            buttons: [if blocked { text("quitKeepBlocked") } else { text("quitKeep") }, text("quitDisconnect"), text("quitCancel")],
            default: if working { 0 } else { 1 },
            remember: working.then(|| text("quitRemember")),
        };
        let (answer, remember) = tauri::async_runtime::spawn_blocking(move || ask_quit(&dialog)).await.unwrap_or((2, false));
        choice = ["keep", "disconnect", "cancel"][answer.min(2)].to_string();
        if remember && choice != "cancel" {
            let mut store = state.store.lock().unwrap();
            let mut next = store.preferences().clone();
            next.quit_action = choice.clone();
            let _ = store.set_preferences(next);
        }
    }
    match choice.as_str() {
        "cancel" => return,
        "disconnect" => {
            if let Err(failure) = tunnel::disconnect(app).await {
                message_box(&strings::failure_text(state.language(), &failure));
                show_window(app);
                return;
            }
        }
        _ => {}
    }
    state.quitting.store(true, Ordering::SeqCst);
    app.exit(0);
}

struct QuitDialog {
    title: String,
    message: String,
    detail: String,
    buttons: [String; 3],
    default: usize,
    remember: Option<String>,
}

#[cfg(windows)]
fn ask_quit(dialog: &QuitDialog) -> (usize, bool) {
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
    use windows_sys::Win32::UI::Controls::{TASKDIALOGCONFIG, TASKDIALOG_BUTTON, TDF_ALLOW_DIALOG_CANCELLATION};
    use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, IDNO, IDYES, MB_SETFOREGROUND, MB_YESNOCANCEL};
    type TaskDialogIndirect = unsafe extern "system" fn(*const TASKDIALOGCONFIG, *mut i32, *mut i32, *mut i32) -> i32;
    let wide = |value: &str| value.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
    let (title, message, detail) = (wide(&dialog.title), wide(&dialog.message), wide(&dialog.detail));
    let labels: Vec<Vec<u16>> = dialog.buttons.iter().map(|label| wide(label)).collect();
    let remember = dialog.remember.as_deref().map(wide);
    let library = wide("comctl32.dll");
    let function = unsafe {
        let module = LoadLibraryW(library.as_ptr());
        if module.is_null() {
            None
        } else {
            GetProcAddress(module, c"TaskDialogIndirect".as_ptr().cast())
        }
    };
    if let Some(function) = function {
        let task_dialog: TaskDialogIndirect = unsafe { std::mem::transmute::<_, TaskDialogIndirect>(function) };
        let buttons: Vec<TASKDIALOG_BUTTON> = labels.iter().enumerate().map(|(index, label)| TASKDIALOG_BUTTON { nButtonID: 100 + index as i32, pszButtonText: label.as_ptr() }).collect();
        let mut config: TASKDIALOGCONFIG = unsafe { std::mem::zeroed() };
        config.cbSize = std::mem::size_of::<TASKDIALOGCONFIG>() as u32;
        config.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION;
        config.pszWindowTitle = title.as_ptr();
        config.pszMainInstruction = message.as_ptr();
        config.pszContent = detail.as_ptr();
        config.cButtons = buttons.len() as u32;
        config.pButtons = buttons.as_ptr();
        config.nDefaultButton = 100 + dialog.default as i32;
        if let Some(remember) = &remember {
            config.pszVerificationText = remember.as_ptr();
        }
        let (mut button, mut checked) = (0i32, 0i32);
        if unsafe { task_dialog(&config, &mut button, std::ptr::null_mut(), &mut checked) } == 0 {
            let index = if (100..103).contains(&button) { (button - 100) as usize } else { 2 };
            return (index, checked != 0);
        }
    }
    let text = wide(&format!("{}\n\n{}\n\n{} / {} / {}", dialog.message, dialog.detail, dialog.buttons[0], dialog.buttons[1], dialog.buttons[2]));
    let answer = unsafe { MessageBoxW(std::ptr::null_mut(), text.as_ptr(), title.as_ptr(), MB_YESNOCANCEL | MB_SETFOREGROUND) };
    (if answer == IDYES { 0 } else if answer == IDNO { 1 } else { 2 }, false)
}

#[cfg(not(windows))]
fn ask_quit(_: &QuitDialog) -> (usize, bool) {
    (2, false)
}

async fn disable_kill_switch_interactive(app: &AppHandle) {
    let language = app.state::<AppState>().language();
    let message = match commands::emergency_disable_kill_switch(app).await {
        Ok(()) => strings::text(language, "dialogs.killSwitchDisabled"),
        Err(reason) => strings::format(&strings::text(language, "dialogs.killSwitchFailed"), &[("reason", &reason)]),
    };
    message_box(&message);
}

#[cfg(windows)]
fn message_box(text: &str) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_OK, MB_SETFOREGROUND};
    let wide = |value: &str| value.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
    let (text, title) = (wide(text), wide(flavor::identity().product_name));
    unsafe { MessageBoxW(std::ptr::null_mut(), text.as_ptr(), title.as_ptr(), MB_OK | MB_SETFOREGROUND) };
}

#[cfg(not(windows))]
fn message_box(text: &str) {
    eprintln!("{text}");
}

pub fn run() {
    let args: Vec<String> = std::env::args().collect();
    let cli_disable = args.iter().any(|arg| arg == DISABLE_KILLSWITCH_FLAG);
    let at_login = args.iter().any(|arg| arg == system::AUTOSTART_FLAG);

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            if argv.iter().any(|arg| arg == DISABLE_KILLSWITCH_FLAG) {
                let app = app.clone();
                tauri::async_runtime::spawn(async move { disable_kill_switch_interactive(&app).await });
                return;
            }
            show_window(app);
        }))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .invoke_handler(commands::handler())
        .setup(move |app| {
            let directory = app.path().data_dir()?.join(flavor::identity().user_data_name);
            applog::init(&directory);
            migrate::migrate_runtime(&directory);
            app.manage(AppState::new(directory.clone()));
            api::attach(app.handle());
            applog::line("app", &format!("Mantel {} ({}) started", flavor::APP_VERSION, flavor::identity().name));
            let handle = app.handle().clone();
            if cli_disable {
                tauri::async_runtime::spawn(async move {
                    match commands::emergency_disable_kill_switch(&handle).await {
                        Ok(()) => {
                            println!("{}", strings::text(handle.state::<AppState>().language(), "dialogs.cliKillSwitchDisabled"));
                            handle.exit(0);
                        }
                        Err(reason) => {
                            eprintln!("Mantel: {reason}");
                            handle.exit(1);
                        }
                    }
                });
                return Ok(());
            }
            create_tray(&handle)?;
            if !at_login {
                create_window(&handle)?;
            }
            tauri::async_runtime::spawn(async move {
                engine::Engine::start(&handle, directory).await;
                commands::detect_firewall(&handle).await;
                tunnel::poll_once(&handle).await;
                tauri::async_runtime::spawn(tunnel::poll_loop(handle.clone()));
                tauri::async_runtime::spawn(tunnel::wifi_loop(handle.clone()));
                if at_login {
                    connect_at_login(&handle).await;
                }
            });
            Ok(())
        })
        .on_window_event(|window, event| match event {
            WindowEvent::CloseRequested { api, .. } => {
                if !window.app_handle().state::<AppState>().quitting.load(Ordering::SeqCst) {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
            WindowEvent::ThemeChanged(theme) => {
                let app = window.app_handle();
                apply_theme(app);
                let _ = app.emit("system-theme", if *theme == Theme::Dark { "dark" } else { "light" });
            }
            _ => {}
        })
        .build(tauri::generate_context!())
        .expect("Mantel konnte nicht starten");

    app.run(|app, event| {
        if let RunEvent::ExitRequested { api, code: None, .. } = event {
            if !app.state::<AppState>().quitting.load(Ordering::SeqCst) {
                api.prevent_exit();
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quit_plan_matches_lifecycle() {
        assert_eq!(quit_plan("disconnected", "keep"), "quit");
        assert_eq!(quit_plan("connected", "keep"), "keep");
        assert_eq!(quit_plan("stale", "disconnect"), "ask");
        assert_eq!(quit_plan("connected", "ask"), "ask");
    }

    #[test]
    fn tray_title_uses_product_name_and_status() {
        let title = tray_title("en", "connected");
        assert!(title.starts_with(flavor::identity().product_name));
        assert!(title.ends_with("Connected"));
    }
}
