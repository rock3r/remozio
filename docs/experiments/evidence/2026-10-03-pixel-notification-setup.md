# Pixel notification setup observation

Device: Pixel 11 Pro, Android 17 / API 37.
Original debug APK: PR #124 head `4a60e334e129a535e165f4a89874b643b03f3f6d`. Its complete tracked tree matches merged commit `c11bb31fce3b27e87a829a71fbb3e26f5817b2e7`; `git diff` between them is empty.

Fixed debug APK: source recorded in commit `812efd8891cc947142df10262cd288f54b26b904` (tree `0155daf0395a08416137176f3f9e5d22dcd86ce5`). The APK was built from the working tree before that commit. No app source changed between the build and commit.

The app initially reported that notification permission was missing. Its setup button opened the Android permission dialog. After Allow, the app remained on “Checking notification settings…” across two UI observations. Manual Refresh recovered the allowed state.

The local test then created one active Android notification record for the app and its synthetic test tag. This establishes posting only. Visible presentation, background delivery and FCM delivery remain unverified.

The permission remains granted. No real approval or command was sent. After installing the lifecycle fix, returning from Android notification settings preserved the allowed state. Posting a local test and explicit Refresh also preserved it. The local test was cleared. The original permission-grant transition was then repeated. After temporary permission revocation and Allow in the system dialog, the app reported the allowed state without manual Refresh. The screen timeout was restored to two minutes.
