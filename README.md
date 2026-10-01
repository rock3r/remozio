# Remozio

Approve requests from your Macs through one Android app. The idea covers privileged commands, 1Password, and Little Snitch, with request details and biometrics where needed.

Read the [Remozio specification](https://remozio-plan.seebrock3r.chatgpt.site/) for the proposed architecture, app experience, and open questions.

Remozio is building experiments and protocol foundations. There is no production approval implementation yet.

See the [experiment sequence](docs/experiments/README.md) and the [Mac XPC experiment](docs/experiments/macos-xpc.md) for measured results and reproducible checks. The [protocol modules](protocol/README.md) share encoding fixtures across Swift and Kotlin.

Run `./scripts/check.sh` and `./gradlew :protocol-kotlin:test` for the local gate (Xcode and JDK 21 on macOS). Pull requests use the repository’s [babysit skill](.agents/skills/babysit-pr/SKILL.md), with Python checks, the Mac build, Kotlin protocol tests, and Codex review required.
