# Android application

The native app targets Android 17 (API 37) and later. Supported-device validation targets Pixels. Other devices need capability checks.

## Build

Use JDK 21 and an Android SDK with `platforms;android-37.0` and `build-tools;37.0.0`. Set `ANDROID_HOME` to that SDK, then run:

```sh
./gradlew :android-app:assembleDebug :android-app:lintDebug
```

The debug APK is `android/app/build/outputs/apk/debug/android-app-debug.apk`. Its package ID is `dev.remozio.android.debug`. Production uses `dev.remozio.android` and needs a separately provisioned signing identity. This change does not configure production signing or update distribution.

## Current scope

The launcher opens an empty Mac list. It uses native Compose, Material 3 Expressive, system light/dark colors, and a scrollable layout for large text. Pairing, requests, notifications, networking, and persistent storage are not connected yet.

Material 3 uses `1.5.0-alpha29` because the Expressive theme is not in the stable 1.4 release. Other Compose libraries use BOM `2026.09.00`. AGP supplies built-in Kotlin; the app does not apply a second Android Kotlin plugin.

The app requests no device permissions. Backup is disabled. Explicit rules exclude every storage domain from cloud backup and Android device transfers. Before adding secrets or enrollment state, validate those rules on supported devices and use installation-bound key storage.

Build and lint checks do not prove device behavior. Installation, accessibility, launch appearance, animation settings, biometrics, and background behavior need the planned Pixel test session. No device is installed or contacted by these build tasks.

References: [Android 17 setup](https://developer.android.com/about/versions/17/setup-sdk), [AGP 9.3](https://developer.android.com/build/releases/agp-9-3-0-release-notes), [Material 3 releases](https://developer.android.com/jetpack/androidx/releases/compose-material3), and [Android UX motion guidance](https://github.com/rock3r/android-ux-skills).
