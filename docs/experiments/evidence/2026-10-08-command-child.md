# Private command child evidence

Local validation ran on 2026-10-08 on an Apple Silicon Mac running macOS 27.0.1.
All native builds selected the macOS 26 deployment target.

Ten focused native tests passed with zero failures.
They cover raw argv/environment bytes, empty values, custom argv[0], every frame truncation and trailing data.
They also check malformed counts, credentials, budget, umask, I/O mode, NULs, relative paths and environment ordering.
Decoder cleanup is idempotent. Its strings own their bytes after the input buffer is cleared.
Darwin group normalization preserves only the approved primary and supplementary IDs, with a maximum union of 16.

Debug and Release app builds passed strict embedded signature, hardened runtime, architecture and deployment-target checks.
Their standalone and embedded command children are byte-identical.
Both reject missing arguments. An ordinary caller receives status 77 before reading configuration or stdin.
The refusal check retains unread pipe input and observes no stdout or stderr output.

The helper was not run with root privileges. No command service or product app was activated.
These checks do not prove target credential transitions, current sudoers enforcement, PTY control or command supervision.
The parent spawner, durable dispatch handoff and actual exec/exit observations remain implementation work.
macOS 26 runtime and physical end-to-end validation remain open.

The complete `./scripts/check.sh` gate passed 1,113 core tests and 97 Swift protocol tests.
Python checks, disposable experiments, packaging and external ownership compiler probes also passed.
The mandatory Kotlin/Android gate passed with JDK 21 and Android platform/build tools 37.
Its reports contain 95 protocol, 195 phone-core, 59 approval-flow and 183 Android tests, with zero failures or errors.
APK assembly and lint passed. Sixty tasks were up to date; approval-flow validation and lint ran again.
