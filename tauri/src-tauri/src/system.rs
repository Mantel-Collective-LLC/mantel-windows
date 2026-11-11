use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

fn system_root() -> PathBuf {
    let root = std::env::var("SystemRoot").or_else(|_| std::env::var("windir")).unwrap_or_else(|_| r"C:\Windows".into());
    let path = PathBuf::from(&root);
    if path.is_absolute() {
        path
    } else {
        PathBuf::from(r"C:\Windows")
    }
}

pub fn system32(binary: &str) -> PathBuf {
    system_root().join("System32").join(binary)
}

fn powershell() -> PathBuf {
    system_root().join("System32").join("WindowsPowerShell").join("v1.0").join("powershell.exe")
}

fn run(program: PathBuf, args: &[&str], env: &[(&str, &str)]) -> std::io::Result<Output> {
    let mut command = Command::new(program);
    command.args(args).stdin(Stdio::null()).env_remove("NODE_OPTIONS");
    for (key, value) in env {
        command.env(key, value);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command.output()
}

const REPAIR_SCRIPT: &str = "$ErrorActionPreference = 'Stop'
$p = Start-Process -FilePath $env:MANTEL_SERVICE_EXE -ArgumentList @('service','install','--root',('\"' + $env:MANTEL_ROOT + '\"')) -Verb RunAs -WindowStyle Hidden -Wait -PassThru
exit $p.ExitCode";

pub fn repair_paths(app_exe: &std::path::Path, resource_dir: &std::path::Path) -> Option<(PathBuf, PathBuf)> {
    let root = app_exe.parent()?.to_path_buf();
    let service = resource_dir.join("service").join("mantel.exe");
    (root.is_absolute() && service.is_absolute()).then_some((service, root))
}

pub fn repair_service(service: &std::path::Path, root: &std::path::Path) -> Result<(), String> {
    let (service, root) = (service.to_string_lossy(), root.to_string_lossy());
    let output = run(
        powershell(),
        &["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", REPAIR_SCRIPT],
        &[("MANTEL_SERVICE_EXE", &service), ("MANTEL_ROOT", &root)],
    )
    .map_err(|error| error.to_string())?;
    if output.status.success() {
        return Ok(());
    }
    let details: String = String::from_utf8_lossy(&output.stderr).split_whitespace().collect::<Vec<_>>().join(" ").chars().take(300).collect();
    Err(if details.is_empty() { format!("Code {}", output.status.code().unwrap_or(-1)) } else { details })
}

pub fn parse_multi_sz(buffer: &[u16]) -> Vec<String> {
    buffer.split(|&unit| unit == 0).filter(|part| !part.is_empty()).map(String::from_utf16_lossy).collect()
}

#[cfg(windows)]
pub fn preferred_languages() -> Vec<String> {
    use windows_sys::Win32::Globalization::{GetUserPreferredUILanguages, MUI_LANGUAGE_NAME};
    let (mut count, mut size) = (0u32, 0u32);
    unsafe {
        if GetUserPreferredUILanguages(MUI_LANGUAGE_NAME, &mut count, std::ptr::null_mut(), &mut size) == 0 || size == 0 {
            return Vec::new();
        }
        let mut buffer = vec![0u16; size as usize];
        if GetUserPreferredUILanguages(MUI_LANGUAGE_NAME, &mut count, buffer.as_mut_ptr(), &mut size) == 0 {
            return Vec::new();
        }
        parse_multi_sz(&buffer)
    }
}

#[cfg(not(windows))]
pub fn preferred_languages() -> Vec<String> {
    Vec::new()
}

fn field<'a>(block: &'a str, names: &[&str]) -> Option<&'a str> {
    block.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        let name = name.trim();
        names.iter().any(|candidate| name.eq_ignore_ascii_case(candidate) || (candidate.ends_with('*') && name.to_lowercase().starts_with(&candidate[..candidate.len() - 1].to_lowercase())))
            .then_some(value.trim())
    })
}

pub fn parse_netsh_interfaces(text: &str) -> &'static str {
    let mut found = "none";
    let mut blocks = Vec::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        if line.trim_start().split(':').next().map(str::trim) == Some("Name") && line.contains(':') {
            if let Some(block) = current.take() {
                blocks.push(block);
            }
            current = Some(String::new());
        } else if let Some(block) = current.as_mut() {
            block.push_str(line);
            block.push('\n');
        }
    }
    blocks.extend(current);
    for block in &blocks {
        let Some(auth) = field(block, &["Authentication", "Authentifizierung"]) else { continue };
        let cipher = field(block, &["Cipher", "Verschl*"]);
        let open = auth.eq_ignore_ascii_case("open") || auth.eq_ignore_ascii_case("offen");
        match cipher {
            None if open => return "unknown",
            Some(cipher) if open && (cipher.eq_ignore_ascii_case("none") || cipher.eq_ignore_ascii_case("keine")) => return "open",
            _ => found = "secured",
        }
    }
    found
}

pub fn wifi_security() -> &'static str {
    match run(system32("netsh.exe"), &["wlan", "show", "interfaces"], &[]) {
        Ok(output) if output.status.success() => parse_netsh_interfaces(&String::from_utf8_lossy(&output.stdout)),
        _ => "none",
    }
}

pub const AUTOSTART_FLAG: &str = "--autostart";

fn xml_text(value: &str) -> String {
    value.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

pub fn autostart_task_xml(exe: &str, user: &str, description: &str) -> String {
    let user = xml_text(user);
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>{description}</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{user}</UserId></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>{user}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>5</Priority>
  </Settings>
  <Actions Context="Author"><Exec><Command>"{exe}"</Command><Arguments>{flag}</Arguments></Exec></Actions>
</Task>"#,
        description = xml_text(description),
        exe = xml_text(exe),
        flag = AUTOSTART_FLAG,
    )
}

const REGISTER_SCRIPT: &str = "$ErrorActionPreference = 'Stop'\nRegister-ScheduledTask -TaskName $env:MANTEL_TASK -TaskPath '\\' -Xml $env:MANTEL_TASK_XML -Force | Out-Null\nWrite-Output 'ok'";

fn windows_user() -> String {
    let name = std::env::var("USERNAME").unwrap_or_default();
    match std::env::var("USERDOMAIN") {
        Ok(domain) if !domain.is_empty() => format!("{domain}\\{name}"),
        _ => name,
    }
}

pub fn autostart_enabled(task: &str) -> bool {
    run(system32("schtasks.exe"), &["/Query", "/TN", task], &[]).map(|output| output.status.success()).unwrap_or(false)
}

pub fn set_autostart(task: &str, enabled: bool, exe: &str, description: &str) -> Result<(), String> {
    if enabled {
        let xml = autostart_task_xml(exe, &windows_user(), description);
        let output = run(
            powershell(),
            &["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", REGISTER_SCRIPT],
            &[("MANTEL_TASK", task), ("MANTEL_TASK_XML", &xml)],
        )
        .map_err(|error| error.to_string())?;
        if !output.status.success() {
            let text = String::from_utf8_lossy(&output.stderr).split_whitespace().collect::<Vec<_>>().join(" ");
            return Err(if text.is_empty() { "Register-ScheduledTask".into() } else { text.chars().take(300).collect() });
        }
        return Ok(());
    }
    let _ = run(system32("schtasks.exe"), &["/Delete", "/TN", task, "/F"], &[]);
    if autostart_enabled(task) {
        return Err(format!("schtasks /Delete {task}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_list() {
        let buffer: Vec<u16> = "en-GB\0de-DE\0\0".encode_utf16().collect();
        assert_eq!(parse_multi_sz(&buffer), vec!["en-GB".to_string(), "de-DE".to_string()]);
        assert!(!preferred_languages().is_empty());
    }

    #[test]
    fn netsh_parsing_matches_wifi_ts() {
        let open = "There is 1 interface on the system:\n\n    Name                   : WLAN\n    SSID                   : Cafe\n    Authentication         : Open\n    Cipher                 : None\n";
        assert_eq!(parse_netsh_interfaces(open), "open");
        let secured = "    Name                   : WLAN\n    Authentication         : WPA2-Personal\n    Cipher                 : CCMP\n";
        assert_eq!(parse_netsh_interfaces(secured), "secured");
        let german = "    Name                   : WLAN\n    Authentifizierung      : Offen\n    Verschl\u{81}sselung        : Keine\n";
        assert_eq!(parse_netsh_interfaces(german), "open");
        let no_cipher = "    Name                   : WLAN\n    Authentication         : Open\n";
        assert_eq!(parse_netsh_interfaces(no_cipher), "unknown");
        assert_eq!(parse_netsh_interfaces("There is no wireless interface on the system."), "none");
    }

    #[test]
    fn task_xml_escapes_and_keeps_least_privilege() {
        let xml = autostart_task_xml(r"C:\Program Files\Mantel & Co\Mantel.exe", "PC\\luke", "Mantel: <Start>");
        assert!(xml.contains(r#"<Command>"C:\Program Files\Mantel &amp; Co\Mantel.exe"</Command>"#));
        assert!(xml.contains("<Description>Mantel: &lt;Start&gt;</Description>"));
        assert!(xml.contains("<RunLevel>LeastPrivilege</RunLevel>"));
        assert!(xml.contains("<Arguments>--autostart</Arguments>"));
        assert!(xml.contains("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"));
    }

    #[test]
    fn repair_runs_the_installed_service_for_the_install_folder() {
        let (service, root) = repair_paths(std::path::Path::new(r"C:\Program Files\Mantel\Mantel.exe"), std::path::Path::new(r"C:\Program Files\Mantel")).unwrap();
        assert_eq!(service, PathBuf::from(r"C:\Program Files\Mantel\service\mantel.exe"));
        assert_eq!(root, PathBuf::from(r"C:\Program Files\Mantel"));
        assert!(repair_paths(std::path::Path::new("Mantel.exe"), std::path::Path::new("x")).is_none());
        assert!(!REPAIR_SCRIPT.contains("Program Files") && REPAIR_SCRIPT.contains("-Verb RunAs"));
    }
}
