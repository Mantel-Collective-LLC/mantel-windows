# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions are the Mantel app version
(`YEAR.MINOR.PATCH`); every release is tagged `v<version>`.

## [2026.0.15] - 2026-11-11

### Added

- Enter an invite code when you create an account; the days it adds are shown together with your new account number.
- Port forwarding: pick the local port on this PC that a forwarded port goes to, for example when your program listens
  on a different port.

### Changed

- Rewritten in Rust with Tauri instead of Electron: the installer shrinks from about 115 MB to about 6 MB,
  with the same look, settings and features.
- The new installer replaces the previous version in place: you stay signed in and keep your settings, devices and
  support tickets.
- The app keeps a small log file for troubleshooting (`logs\mantel.log` in its data folder, at most 2 MB). Tokens,
  keys, account numbers and IDs are never written to it.

## [2026.0.14] - 2026-11-09

### Changed

- Obfuscation now runs in the background service and stays active even when the app window is closed.

## [2026.0.13] - 2026-11-08

### Changed

- No changes in the Windows app; version number aligned with the Android app.

## [2026.0.12] - 2026-11-07

### Changed

- Lighter: the app checks in far less often while idle or minimized, saving CPU and battery.
- In the ticket chat only the messages scroll, the reply field stays in place, and the chat opens at the newest message.

## [2026.0.11] - 2026-11-07

### Changed

- Faster: the app now checks the connection status without delay.

### Fixed

- Connecting to RAM-only locations works again after the server has restarted.

## [2026.0.10] - 2026-11-06

### Changed

- The app now starts in English unless you picked German in the settings; the language setting offers Deutsch and
  English.

## [2026.0.9] - 2026-11-06

### Changed

- New accounts start without time: the app then shows “No time yet” with a direct way to buy time or redeem a voucher.
- Clearer message when an account has no paid time.

## [2026.0.8] - 2026-11-05

### Added

- Two-factor sign-in with an authenticator app (optional, set up in the dashboard): the app asks for the code when you
  sign in.
- MTProto proxies for Telegram on our servers, with a link that opens straight in Telegram.

## [2026.0.7] - 2026-11-05

### Added

- Tor over VPN with one switch.
- Your own proxies on our servers, leaving through Tor or the server IP.
- Obfuscation for networks that block VPNs.
- Automatic key rotation.
- Manage devices and port forwarding in the app, and see new sign-ins to your account.
- Autostart on/off in the settings.

### Fixed

- Disconnecting now always lifts the kill switch block, even when the server cannot be reached.

## [2026.0.6] - 2026-11-04

### Added

- A Support tab: send tickets to our team right from the app, end-to-end encrypted, with a counter for new replies.

### Changed

- Calmer navigation: the active page is marked with an accent line instead of a large filled area.
- Uptime, handshake and data usage are shown as separate live tiles on the home screen.
- Renew now opens the subscription page directly.

## [2026.0.5] - 2026-10-25

### Added

- Port forwarding under Settings → Connection: a switch opens one port (TCP and UDP) for this device at the connected
  location, with a copy button and a hint for torrent clients.

### Changed

- Locations are being upgraded step by step; where port forwarding is not available yet, the app says so and the
  switch stays off.

## [2026.0.4] - 2026-10-25

### Changed

- Speed per location (fast, medium, slow) is now measured by your device instead of the server. Nothing is shown when
  there is no measurement, and nothing is measured while connected.

## [2026.0.3] - 2026-10-25

### Changed

- New design with a bottom tab bar and a world map, a dedicated Locations tab, clearer buttons (green to connect, red to
  disconnect) and a tidier connection card.

## [2026.0.1] - 2026-10-24

### Added

- Quantum-resistant tunnel (beta).

### Changed

- The location list is only shown when you are signed in.

### Fixed

- Various bug fixes.

[2026.0.15]: https://github.com/Mantel-Collective-LLC/mantel-windows/compare/v2026.0.14...v2026.0.15
[2026.0.14]: https://github.com/Mantel-Collective-LLC/mantel-windows/releases/tag/v2026.0.14
