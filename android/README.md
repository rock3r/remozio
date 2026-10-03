# Android application

The native app targets Android 17 (API 37) and later. Supported-device validation targets Pixels. Other devices need capability checks.

## Build

Use JDK 21 and an Android SDK with `platforms;android-37.0` and `build-tools;37.0.0`. Set `ANDROID_HOME` to that SDK, then run:

```sh
./gradlew :android-app:testDebugUnitTest :android-app:assembleDebug :android-app:lintDebug
```

The debug APK is `android/app/build/outputs/apk/debug/android-app-debug.apk`. Its package ID is `dev.remozio.android.debug`. Production uses `dev.remozio.android` and needs a separately provisioned signing identity. The [release artifact procedure](releases.md) builds and verifies upload candidates. Production signing identity and publication still need configuration.

## Current scope

The launcher opens an empty Mac list and the app update status card. It uses native Compose, Material 3 Expressive, system light/dark colors, and a scrollable layout for large text. Pairing and request delivery are not connected yet. The update card can check GitHub releases and download a candidate after user selection. Update status uses app-private storage and installer callbacks.

Material 3 uses `1.5.0-alpha29` because the Expressive theme is not in the stable 1.4 release. Other Compose libraries use BOM `2026.09.00`. AGP supplies built-in Kotlin; the app does not apply a second Android Kotlin plugin.

The manifest declares notification permission, but the app does not request it at startup. Backup is disabled. Explicit rules exclude every storage domain from cloud backup and Android device transfers. Before adding secrets or enrollment state, validate those rules on supported devices and use installation-bound key storage.

Build and lint checks do not prove device behavior. Installation, accessibility, launch appearance, animation settings, biometrics, and background behavior need the planned Pixel test session. No device is installed or contacted by these build tasks.

References: [Android 17 setup](https://developer.android.com/about/versions/17/setup-sdk), [AGP 9.3](https://developer.android.com/build/releases/agp-9-3-0-release-notes), [Material 3 releases](https://developer.android.com/jetpack/androidx/releases/compose-material3), and [Android UX motion guidance](https://github.com/rock3r/android-ux-skills).

The [generic notification backend](../phone/core/PUSH.md) is available for future push integration. It is not connected to the launcher or Firebase yet.

## Command inspection

The debug build has a **Preview a sample command** entry and five static status scenes. It opens an invented, read-only capture in a bottom sheet below 600 dp window width, or a bounded dialog on wider windows. The sample is labelled and has no approval controls. Its fixture and entry are absent from the release source set.

The reusable inspection component renders the complete typed command capture. Invocation, target credentials, environment provenance, input, requester signing status, ancestry limits, and caller explanation have separate sections. Labels come from application resources. Request values cannot introduce UI labels or clickable links.

Values use quoted display notation, not shell syntax. Control and format characters, bidi controls, line separators, and non-ASCII spaces are escaped. Malformed UTF-8 becomes explicit byte escapes instead of replacement characters. A toggle shows every original byte in hex, including empty values and distinct Unicode spellings. Neither view truncates values. Ordinary Unicode remains readable; this does not eliminate Unicode glyph confusables.

Inspection state stays in composition memory and is not saved across process death. Closing details does not imply denial or cancellation. The authenticated session adapter supplies status and timing. Live enrollment identity, transport, and bound decision controls still need integration. The component alone establishes no trust in a capture.

Five Android-module JVM tests cover empty values, escaped syntax, controls, bidi, malformed UTF-8, Unicode spelling, full-byte round trips, and long values. Android unit tests now run in CI and the local PR gate. Build/lint checks do not establish layout, TalkBack reading order, large-font behavior, or sheet/dialog usability; those remain for the interactive Pixel session.

The layout uses native Material 3 components and their standard motion. There are no custom animations. Its breakpoint follows [window information](https://developer.android.com/reference/kotlin/androidx/compose/ui/platform/WindowInfo); the sheet uses [ModalBottomSheet](https://developer.android.com/develop/ui/compose/quick-guides/content/create-bottom-sheet).

The [status tracker](status-tracking.md) verifies signed updates against retained request bindings and preserves revision, outcome, and timing continuity. It remains separate from live transport and decision controls.

## Status presentation

The inspector can show request age, authorization time remaining, an optional target lifetime estimate, clock uncertainty, and an accepted phone decision. Status labels distinguish actual target timeout, Remozio expiry, disappearance with an unknown reason, and uncertain execution outcomes. An elapsed estimate never selects a terminal headline.

Only the outcome heading uses a polite accessibility live region. Timing text sits outside that node, so countdown updates do not request repeated announcements. Age rounds down and remaining time rounds up without unsigned overflow. The status uses native Material components and no custom animation.

A terminal status hides the capture and its byte toggle. The caller still owns capture disposal; hiding a view is not secure erasure or a history implementation. Pending views without a capture show that details are unavailable. Request identity keeps the sheet state stable across status revisions.

Six debug scenes cover a pending command, an elapsed target estimate, expired authorization, target disappearance, an unknown outcome, and clock uncertainty. They are explicitly labelled static previews. Generic status scenes do not load the command fixture. They do not enter a verifier or transport, grant authority, or infer a result from a timer. The release source set keeps its no-op development entry.

Five presentation tests cover the important outcome distinctions and duration rounding. Live transport, notifications, and interactive TalkBack/layout checks remain outstanding. No device was contacted by this change.

The announcement boundary follows [Compose accessibility semantics](https://developer.android.com/develop/ui/compose/accessibility/semantics): live regions should not wrap frequent countdown updates.

## Authenticated command session

`CommandRequestSession.open` verifies the issued-request signature with a key supplied by a trusted enrollment. It then checks the expected Mac/account, supported command contract, and capture semantics. The owner retains the typed capture and status tracker, without retaining the issued body. This signature check proves origin only. It does not establish freshness, current enrollment, or permission to execute.

A valid terminal status clears the owned capture before publishing its revision. Invalid signatures, conflicting revisions, and old updates cannot purge pending details or restore terminal details. An elapsed countdown alone does not clear the capture. The revision flow carries no capture data. Callers must replace old snapshots; managed memory does not provide a secure-erasure guarantee.

`CommandRequestInspection` connects that owner to the inspector. It samples `SystemClock.elapsedRealtime`, which includes deep sleep, once per second while the host lifecycle is started. Accepted status updates trigger an immediate refresh. The lifecycle cancels the timer and clears its UI snapshot when the host stops. The session remains in memory for the caller to own. Its identity keeps the sheet stable when the first status arrives.

The epoch is process-local, like the session. Neither survives process death. The future enrollment owner must discard sessions when keys or enrollment change. The adapter is not yet connected to the launcher or a transport; the debug scenes remain static. Seven phone-core JVM tests cover signed input, enrollment binding, capability checks, capture cleanup, and replay behavior. Device lifecycle, sleep, and layout checks remain deferred.

Clock and lifecycle behavior follow the [SystemClock contract](https://developer.android.com/reference/android/os/SystemClock) and [lifecycle coroutine guidance](https://developer.android.com/topic/libraries/architecture/coroutines).

The platform-independent request owner and tracker live in [phone-core](../phone/core/README.md). Android supplies lifecycle and elapsed-clock integration. Its shared core also runs against the native Swift peer in the device-free [approval-flow experiment](../docs/experiments/approval-flow.md).

The [sideload update verifier](updates.md) stages APKs privately, verifies their signatures and identity, and binds installer handoff to the verified bytes. A native installer backend now enforces verified copying and durable recording before commit. The application now owns pending update state and exposes installation, permission, cleanup, and confirmation controls. The launcher can check releases, download and verify a candidate, and then offer a separate install action. Update settings control foreground checks and prerelease discovery.

The [transport identity loader](transport-identity.md) validates an existing hardware-backed enrollment key and supplies its handle to the TLS client. Pairing, key creation, and native Pixel validation remain outstanding.

The [phone enrollment store](../phone/core/ENROLLMENTS.md) has an Android adapter with a dedicated hardware encryption key and a no-backup atomic file. It is available to the future enrollment host and does not initialize on app startup.
