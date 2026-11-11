# Mantel for Windows

The Windows client of [Mantel VPN](https://mantelvpn.com). A [Tauri](https://tauri.app) app: the window, tray,
settings, secrets and API client are Rust (`tauri/src-tauri/`), the user interface is React (TypeScript, Tailwind CSS)
in the system WebView2. The tunnel is the official [WireGuard for Windows](https://www.wireguard.com/install/) tunnel
service, controlled by the Mantel Service, a Windows service that does everything that needs system rights (tunnel,
firewall kill switch, obfuscation relay). The app itself runs without administrator rights.

This repository contains the app only. **The Mantel Service and its tunnel engine are not open source** and not part
of this repository, nor is the Mantel server side (API, VPN servers). The signed installer with the app and the
service is attached to every [GitHub release](../../releases) and offered at
[mantelvpn.com](https://mantelvpn.com/en/download).

## Features

- WireGuard tunnel with kill switch (Windows Firewall rules), LAN access, IPv6 and DNS blocker settings
- Quantum-resistant tunnel (optional): an ML-KEM-768 key exchange derives a WireGuard pre-shared key
- Obfuscation: WireGuard over TLS 1.3 on TCP 443 for networks that block VPN traffic
- Port forwarding, server proxies, Tor over VPN, device management
- Auto-connect on open Wi-Fi, connect at login, tray icon
- Latency per location, measured on the device
- End-to-end encrypted support tickets
- Light/dark theme, English and German
- Account number login with optional two-factor authentication; secrets are stored with Windows DPAPI

## Layout

| Path | Content |
|---|---|
| `tauri/src-tauri/` | Rust: window, tray, settings, secrets (DPAPI), API client, service pipe, autostart, log file, NSIS hooks |
| `tauri/src/` | The bridge between the user interface and Rust, support ticket crypto (WebCrypto) |
| `shared/ui/` | The React user interface (shared with the Mantel Android app, so some screens are Android-only) |
| `shared/core/` | Contracts between UI and app, i18n texts (`i18n/*.json`), shared helpers |
| `shared/ticket/` | Support ticket protocol and end-to-end encryption (WebCrypto) |
| `src/main/` | Shared TypeScript (API schemas) and the previous Electron app |
| `test/`, `tauri/test/` | Vitest tests |

## Requirements

- Windows 10 or 11 (x64) with WebView2
- Node.js 22 or newer and npm
- Rust 1.90 or newer (MSVC toolchain)

## Build

```sh
npm ci
npm run typecheck
npm test                                                     # Vitest
cargo test --manifest-path tauri/src-tauri/Cargo.toml        # Rust
```

This repository does not build an installer: the installer bundles the Mantel Service, which is not open source. Use
the signed installer from the GitHub release (`Mantel-Setup-<version>-x64.exe` with its `.asc` signature and
`SHA256SUMS`). The API server is fixed at build time (`MANTEL_API_URL`, must be HTTPS for prod builds); without
it a debug build talks to `http://localhost:3000`.

## Verifying a release

```sh
gpg --verify Mantel-Setup-<version>-x64.exe.asc Mantel-Setup-<version>-x64.exe
sha256sum -c SHA256SUMS
```

## Development

`npm run tauri:dev` starts the debug app with hot reload. Connecting needs the Mantel Service, which is not part of
this repository; the user interface itself works without it.
