# Mantel for Windows

The Windows client of [Mantel VPN](https://mantelvpn.com). An [Electron](https://www.electronjs.org) app: the user
interface is React (TypeScript, Tailwind CSS), the tunnel is the official
[WireGuard for Windows](https://www.wireguard.com/install/) tunnel service, controlled by the Mantel Service, a
Windows service that does everything that needs system rights (tunnel, firewall kill switch). The app itself runs
without administrator rights and talks to the service over a named pipe.

This repository contains the app window only. **The Mantel Service is not open source** and not part of this
repository, nor is the Mantel server side (API, VPN servers). The signed installer with the app and the service is
attached to every [GitHub release](../../releases) and offered at [mantelvpn.com](https://mantelvpn.com/en/download).

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
| `src/main/` | Electron main process: VPN controller, API client, kill switch rules, quantum-resistant exchange, platform layer |
| `src/preload/` | The narrow bridge between the user interface and the main process |
| `shared/ui/` | The React user interface (shared with the Mantel Android app, so some screens are Android-only) |
| `shared/core/` | Contracts between UI and main process, i18n texts (`i18n/*.json`), shared helpers |
| `shared/ticket/` | Support ticket protocol and end-to-end encryption (WebCrypto) |
| `obfs-sidecar/`, `obfs/` | Go: `mantel-obfs`, the local relay of the obfuscation (WireGuard over TLS) |
| `build/` | Build configuration, icons, NSIS installer scripts (for reference: they expect the service binary) |
| `scripts/` | Helpers that build the obfuscation relay and the icons |
| `dev/` | Mock API server and end-to-end checks for development |
| `test/` | Vitest tests |

## Requirements

- Windows 10 or 11 (x64)
- Node.js 22 or newer and npm
- Go 1.26 or newer (obfuscation relay)
- [WireGuard for Windows](https://www.wireguard.com/install/) on the machine that runs the app

## Build

```sh
npm ci
npm run typecheck
npm test            # Vitest
npm run test:obfs   # Go tests of the obfuscation relay
npm run build:prod  # type-checks and builds the app into out/
```

This repository does not build an installer: the installer bundles the Mantel Service, which is not open source. Use
the signed installer from the GitHub release (`Mantel-Setup-<version>-x64.exe` with its `.asc` signature and
`SHA256SUMS`). The API server is fixed at build time (`MANTEL_API_URL`, must be HTTPS for prod builds); without
it a debug build talks to `http://localhost:3000`.

## Verifying a release

Every installer is signed with the Mantel release key (`Mantel-Setup-<version>-x64.exe.asc`). The `SHA256SUMS`
attached to a GitHub release contains the lines of the official, signed checksum list for the files of that release
(the full signed list, `SHA256SUMS` with `SHA256SUMS.asc`, also covers the other Mantel downloads and is offered
at [mantelvpn.com](https://mantelvpn.com/en/download)):

```sh
gpg --verify Mantel-Setup-<version>-x64.exe.asc Mantel-Setup-<version>-x64.exe
sha256sum -c SHA256SUMS
```

## Development

- `npm run dev` starts the app with hot reload (`npm run dev:debug` for the debug flavor). Connecting needs the
  Mantel Service, which is not part of this repository; the user interface itself works without it
  (`npm run dev:mock`, `npm run web`).
- `npm run dev:mock` starts the app against the bundled mock API (`dev/mock-api.mjs`), no server needed.
- `npm run web` serves the user interface in a browser on port 5174, talking to the mock API.
- `npm run obfs:build` builds the obfuscation relay once so `npm run dev` can use it.

## License

GPL-3.0, see [LICENSE](LICENSE). "Mantel" and the Mantel logo are not covered by the license; if you publish a
modified build, use your own name, icon and application ID.
