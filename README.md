# Mantel for Windows

Mantel VPN for Windows, built in Rust with Tauri 2. It replaces the earlier Electron app.

The app (window, tray, settings, secrets, API client) is Rust; the user interface is React in the system WebView2.
The tunnel itself runs in the Mantel Service, a Windows service that is installed with the app and is not part of
this repository. The app runs without administrator rights.

## Tech stack

| Part | Technology |
|---|---|
| App | Rust 1.90+, Tauri 2.12 |
| User interface | React 19, TypeScript, Vite, Tailwind CSS 4, in Microsoft WebView2 |
| HTTP | reqwest with rustls |
| Tunnel | WireGuard, through the official WireGuard for Windows tunnel service |
| Kill switch | Windows Firewall rules |
| Post-quantum | Optional ML-KEM-768 key exchange that derives the WireGuard pre-shared key |
| Secrets | Windows DPAPI |
| Releases | Installer signed with GPG, plus `SHA256SUMS` |

## Features

- WireGuard tunnel with kill switch, LAN access, IPv6 and DNS blocker settings
- Optional quantum-resistant tunnel (ML-KEM-768)
- Obfuscation: WireGuard over TLS on TCP 443 for networks that block VPNs
- Port forwarding, server proxies, Tor over VPN, device management
- Auto-connect on open Wi-Fi, connect at login, tray icon
- End-to-end encrypted support tickets
- Login with an account number and optional two-factor authentication

## Download

Get the signed installer `Mantel-Setup-<version>-x64.exe` from the [releases](../../releases) or from
[mantelvpn.com](https://mantelvpn.com/en/download). The release key and its fingerprint are listed at
[mantelvpn.com/en/download/verify](https://mantelvpn.com/en/download/verify).

```sh
gpg --verify Mantel-Setup-<version>-x64.exe.asc Mantel-Setup-<version>-x64.exe
sha256sum -c SHA256SUMS
```

## Build from source

Prerequisites: Windows 10 or 11 (x64) with WebView2, Node.js 22+, Rust 1.90+ (MSVC toolchain).

```sh
npm ci
npm run typecheck
npm test
cargo test --manifest-path tauri/src-tauri/Cargo.toml
```

`npm run tauri:dev` starts the debug app. Connecting needs the Mantel Service, so this repository does not build an
installer; the user interface works without it.

## License

GPL-3.0-only, see [LICENSE](LICENSE).

## Security

Report vulnerabilities as described in [security.txt](https://mantelvpn.com/.well-known/security.txt).
