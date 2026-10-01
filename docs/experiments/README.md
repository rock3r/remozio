# Experiment sequence

The [design specification](https://remozio-plan.seebrock3r.chatgpt.site/) defines the product. Experiments establish evidence before implementation relies on platform behavior.

| Work | Status | Next evidence |
| --- | --- | --- |
| Swift build and XPC identity checks | [Measured with ad-hoc signing](macos-xpc.md) | macOS 26 and Developer ID repeats |
| Single app and background services | [Bundle build and seals checked](macos-packaging.md) | SMAppService registration, protected placement, update replacement |
| Keys and durable authority | [Disposable enclave signing and restoration measured](macos-key-custody.md) | Pre-login availability, code access, crash and rollback cases |
| Command executable binding | [Path replacement and descriptor behavior measured](macos-execution-binding.md) | macOS 26 repeat and user-selected execution contract |
| UI adapters and presence | Needs interactive session | Authorized dialog fixtures and remote desktop states |
| Per-Mac push and tunnel | Pending configuration | FCM delivery and independent Mac endpoints |
| Android ADB bridge | Needs device session | Wi-Fi-off fallback, listener exposure, reconnect and Stop |
| Setup exports and APK updates | Pending | Independent import, signature checks and retained pairing |

## PR sequence

1. Reproducible native Mac experiment harness and XPC evidence.
2. Build and CI infrastructure for Mac experiments, followed by app/service packaging experiments.
3. Protocol and state-machine implementation, driven by shared Swift/Kotlin conformance vectors.
4. Privileged authority and transport integration after the relevant evidence gates pass.
5. Prompt adapters, Android approval flow, push, and ADB in separate vertical changes.

Each PR records its checks and limits. An experiment result does not certify an untested configuration. Device-dependent end-to-end tests are reserved for the user's next available computer session.

## Interactive session checklist

- Make the intended Apple signing identity available without exporting its private key.
- Confirm a macOS 26 test host and supported Pixel running Android 17+.
- Exercise service startup, lock/logout, reboot, and update replacement.
- Capture authorized 1Password and Little Snitch fixtures without submitting real approvals.
- Compare local use, Chrome Remote Desktop, Screen Sharing, dark displays, and manual Away.
- Test ADB with Wi-Fi off, mobile data on, then reconnect after update and restart.

Do not collect passwords, ADB payloads, notification tokens, or provider secrets in committed evidence.
