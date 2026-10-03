# Pixel notification setup observation

Device: Pixel 11 Pro, Android 17 / API 37.
Build: debug APK from commit `4a60e334e129a535e165f4a89874b643b03f3f6d`.

The app initially reported that notification permission was missing. Its setup button opened the Android permission dialog. After Allow, the app remained on “Checking notification settings…” across two UI observations. Manual Refresh recovered the allowed state.

The local test then created one active Android notification record for the app and its synthetic test tag. This establishes posting only. Visible presentation, background delivery and FCM delivery remain unverified.

The permission remains granted. No real approval or command was sent. After installing the lifecycle fix, returning from Android notification settings preserved the allowed state. Posting a local test and explicit Refresh also preserved it. The local test was cleared. The original permission-grant transition has not yet been repeated with the fix.
