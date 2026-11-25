# Hisn · حصن

Scan and run untrusted programs on Windows 11 without giving them your files or your network.

Pick a folder. Hisn watches it, scans new files with Microsoft Defender, and lets you launch programs from it inside an AppContainer.

> **Early preview.** Not audited. Do not use it to handle live malware.

## Install

Download the installer from [Releases](../../releases). It installs for the current user and does not need administrator rights.

The installer is not code-signed yet, so SmartScreen will warn about it.

## Updates

Hisn checks GitHub for a new version twice a day and notifies you. Updates are signed, replace the installed version, and can be installed automatically from Settings.

## Features

- Scans protected folders, and new files as they arrive
- Moves files Defender confirms as malicious to an encrypted quarantine, with restore
- Runs programs with no network and no access to your files unless you allow it
- Optional private screen per program, to keep it away from your desktop
- Flags files modified after signing and DLLs that impersonate Windows libraries
- Stays in the tray; about 7 MB when the window is closed
- No driver, no code injection, no telemetry

The interface is in Arabic.

## What it protects

| | Status |
|---|---|
| Personal files | Blocked in our tests |
| Network | Blocked unless allowed |
| Startup entries, scheduled tasks | Blocked in our tests |
| Keyboard, screen, mouse | Partial, only with a private screen |
| Programs opened directly from Explorer | **Not protected** |
| Kernel exploits, administrator-level malware | **Not protected** |

A scan that finds nothing does not mean a file is safe. Threats you have allowed in Defender are not reported.

Hisn refuses the usual folders of game launchers and anti-cheat software. Do not add your legitimate online games to it.

## Requirements

Windows 11 with Microsoft Defender. Developed and tested on 26H2 (x64) only.

## Build

Requires Rust (MSVC toolchain).

```powershell
cargo build --release
cargo test -p hisn
```

To build the installer:

```powershell
cd app
npx @tauri-apps/cli@2 build
```

| Path | |
|---|---|
| `hisn/` | Core library and command line |
| `app/` | Desktop app (Tauri) |
| `probe/`, `lab/` | Isolation tests, for disposable VMs only |

## Uninstall

Before removing Hisn, use **الإعدادات ← خيارات متقدمة ← حذف** to undo folder permissions. This also deletes data saved inside containers. Restore anything you need from quarantine first, and turn off start with Windows.

## Credits

[Fluent UI System Icons](https://github.com/microsoft/fluentui-system-icons) © Microsoft, MIT License.
