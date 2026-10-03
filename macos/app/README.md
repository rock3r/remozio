# Native Mac application

The Xcode target builds `Remozio.app` for macOS 26 and Apple Silicon. This is the product app scaffold, separate from the disposable packaging experiment.

The SwiftUI app has a main window, a menu bar entry, and a native Settings window. The menu can reopen the main window and quit the app. Settings can hide the menu entry; the Dock and Applications remain available. That preference uses the current user's defaults. It carries no enrollment or approval authority.

The app shows an explicit unconfigured state. It has no pairing, routing controls, network listeners, or approval actions yet. It does not load the experiment's service manifests, register services, request permissions, or start persistent background services. Privileged services still need the protected installation and identity gates before integration.

## Build checks

Run on an Apple Silicon Mac with Xcode and a macOS 26 or later SDK:

```sh
python3 scripts/check-macos-app.py
```

The script builds Debug and Release, verifies their signatures and hardened runtime, and checks arm64 architecture, deployment targets, localization resources, and bundle contents. It does not launch either app. The repository gate runs this check on macOS.

Build outputs are under `.build/macos-app/DerivedData/Build/Products/`. Debug uses `dev.remozio.mac.debug`; Release uses `dev.remozio.mac`. Both currently use ad-hoc signing for local build validation. The project explicitly enables the runtime signing option and disables the debug injection library. Release configuration is not a distributable release: Developer ID signing, notarization, updater integration, and trusted service identities remain outstanding.

Logs are `.build/macos-app/xcodebuild-debug.log` and `.build/macos-app/xcodebuild-release.log`. The shared Xcode scheme is available at `macos/app/Remozio.xcodeproj`.

## Validation limits

Compilation and bundle checks do not prove window behavior, menu accessibility, localization, VoiceOver, or large-text usability. Those checks remain for the interactive session. The app has not been installed or launched by the build script.

Native surfaces use [MenuBarExtra](https://developer.apple.com/documentation/swiftui/menubarextra), [Settings](https://developer.apple.com/documentation/swiftui/settings), and [SettingsLink](https://developer.apple.com/documentation/swiftui/settingslink).

## Setup file preview

The main window can open an encrypted setup file in a native sheet. The file picker uses a security-scoped URL. A shared actor reads a bounded regular file and decrypts it away from the UI actor. It rejects directories, FIFOs, remote URLs, and oversized files. Reading uses one descriptor, so replacing the path does not redirect an active read.

The password entry clears when opening starts and when the sheet closes. Derivation retains a temporary password copy until it finishes; this does not promise memory erasure. Cancellation prevents a late result from replacing the view. The UI receives only category and scope metadata, never the decrypted configuration or credentials. Closing the sheet does not change setup state.

This is a preview, not an import command. Provider access is unverified; protected application and provisioning remain pending. The UI says this before and after opening a file.

For synthetic offscreen renders of the actual SwiftUI view:

```sh
swift run --package-path macos/app SetupPreviewSnapshots /tmp/remozio-preview-snapshots
```

This Debug-only helper renders empty, error, and scope states in light/dark appearance. It does not open the product app, register services, select real files, or contact providers. Native controls, file-picker interaction, keyboard focus, cancellation timing, and VoiceOver still need the interactive session.
