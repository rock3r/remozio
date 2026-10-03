# Pixel platform experiments, 2026-10-03

Device: Pixel 11 Pro, Android 17 / API 37. Initial debug build: PR #124 head `4a60e334e129a535e165f4a89874b643b03f3f6d`, with the same tracked tree as merged commit `c11bb31fce3b27e87a829a71fbb3e26f5817b2e7`.

## Biometric key

The existing P-256 key reported StrongBox protection and per-operation authentication. Its reported authentication duration was zero. Enrollment invalidation was reported as true despite the requested retention policy.

Two biometric signatures verified. Fresh signing without a prompt was rejected before authentication and after the first signature. The second check did not measure an immediate, millisecond-scale reuse window.

The public key fingerprint stayed unchanged after force-stop and restart. Back cancelled a prompt with code 10 and accepted no signature. Backgrounding cancelled another prompt. A fresh biometric signature verified after both cancellations.

Enrollment retention, device reboot continuity and production approval integration remain untested. The key was preserved. Its public fingerprint also stayed unchanged after installing the debug APK from source recorded in `812efd8891cc947142df10262cd288f54b26b904`. The Android source for that build matches merged commit `0874a5dd031961331eb40d69bc80c2358b6e9148`; the Android subtree diff is empty. This establishes key identity continuity across that update, not post-update signing or biometric enrollment retention.

## Local ADB endpoints

The ordinary app connected to the existing legacy listener through IPv4 and IPv6 loopback. Each socket closed without sending payload data.

Android's service picker exposed the phone's own wireless-debugging advertisement. The selected candidate matched a local interface. Its discovered connection port also accepted IPv4 and IPv6 loopback connections.

These checks establish discovery and TCP reachability only. They do not establish ADB protocol identity, encrypted bridge operation, listener isolation, mobile-data fallback or foreground-service lifetime. Wi-Fi remained enabled; no debugging listener was enabled or reconfigured during these checks.

## Cleanup

The app's disposable key remains available for continuity checks. The original two-minute screen timeout was restored after testing. No production command or approval was sent.
