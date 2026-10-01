# Remozio

Approve requests from your Macs through one Android app. The idea covers privileged commands, 1Password, and Little Snitch, with request details and biometrics where needed.

Read the [Remozio specification](https://remozio-plan.seebrock3r.chatgpt.site/) for the proposed architecture, app experience, and open questions.

Remozio is building experiments, protocol foundations, and native app scaffolds. There is no production approval implementation yet.

See the [experiment sequence](docs/experiments/README.md) and the [Mac XPC experiment](docs/experiments/macos-xpc.md) for measured results and reproducible checks. The [protocol modules](protocol/README.md) share encoding fixtures across Swift and Kotlin. The [Android app](android/README.md) currently opens an empty Mac list.

Run `./scripts/check.sh` and `./gradlew :protocol-kotlin:test :android-app:assembleDebug :android-app:lintDebug` for the local gate. This requires Xcode, JDK 21, and the Android SDK described in the [Android build guide](android/README.md). Pull requests use the repository’s [babysit skill](.agents/skills/babysit-pr/SKILL.md), with Python checks, the Mac build, Kotlin protocol tests, the Android build and lint checks, and Codex review required.
