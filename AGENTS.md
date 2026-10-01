# Remozio agent workflow

Use the repository's [babysit-pr skill](.agents/skills/babysit-pr/SKILL.md) for every open PR. Its watcher is the readiness authority. Follow its review triage, batching, and cleanup rules.

Run `./scripts/check.sh` and `./gradlew :protocol-kotlin:test :android-app:assembleDebug :android-app:lintDebug` before each push. Use JDK 21 and set `ANDROID_HOME` to an Android SDK with platform 37.0 and build tools 37.0.0. When the XPC experiment changes, also run its live checks on a supported Mac GUI session and retain the evidence. CI builds and unit tests do not substitute for live experiment results.

Keep PRs focused. Record what an experiment proves and what remains untested. Do not collect secrets in committed evidence. Device-dependent end-to-end checks wait for the user's interactive session.
