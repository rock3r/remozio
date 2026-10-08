# Command I/O channel evidence

Local validation ran on 2026-10-08 with the Apple Silicon macOS host and the macOS 26 deployment target.
The I/O profile uses wire 3 and carrier 4. Existing profiles retain their meanings.

The focused tests passed six terminal-codec cases, ten real Mach I/O cases, and fifteen readiness cases.
The readiness total includes twelve existing cases and three new I/O cases.
The Mach total includes import, capture, journal ownership, stream delivery, cleanup, cancellation and final-deadline checks.
Journal ownership was checked with ordinary and independently checkpointed disposable storage.

The full `./scripts/check.sh` gate passed 1,091 native core tests and 97 Swift protocol tests.
Packaging, disposable experiments and external command-ownership compiler probes also passed.
The probes reject handshake reuse and alias reuse after transfer. They also reject public construction of verified terminal results.

The complete Kotlin and Android gate passed with JDK 21, platform 37.0 and build tools 37.0.0.
Its reports contain 95 protocol, 195 phone-core, 59 approval-flow and 183 Android unit tests, with no failures or errors.
The APK and lint gates passed. Sixty tasks were up to date; approval-flow validation and lint ran again.

The tests use actual kernel carriers, pipes, private ports and the test user's code identity.
They execute no approved privileged command and install no service.
They do not prove Developer ID deployment, durable terminal emission, the child supervisor, CLI controls or physical device behavior.
Those integration gates remain required.
