# Native command process evidence

Local validation ran on 2026-10-08 on Apple Silicon, macOS 27.0.1, with the macOS 26 deployment target.
Eleven focused native tests passed with zero failures.
Clang static analysis reported zero diagnostics for the new process owner.

Tests compile an unprivileged C fixture. It emulates the private preparation exchange without changing credentials.
Its program role verifies raw non-UTF-8 argv/environment, empty values, retained directory and descriptor isolation.
Actual kernel exec/exit events and `waitpid` establish exit 7 and SIGTERM.
A failed exec yields launcher exit 70 without any program exec evidence.

The suite verifies unread pipe input before release, one release attempt, cancellation before exec, and process-group signal forwarding.
It rejects malformed configuration, unknown/truncated status and a missing launcher without reusing the command.
A 1 MiB private configuration reaches preparation through nonblocking progress. A stalled reader reaches its finite preparation deadline.
A closed release reader yields EPIPE; its failed release attempt stays consumed and the parent's signal mask remains unchanged.
An unexpected external reap yields ECHILD and prevents later PID signaling.

The anonymous PTY test verifies a fresh session, a controlling slave, its foreground group, output and exact program exit.
Its first version waited for exit before reading output and left the child in Darwin's exit path.
The observer had seen exec, but no exit; the owned child retained its original parent and process group.
Sampling could not inspect that exiting fixture. No privileged sampling was attempted.
Draining the master before waiting for exit resolved the stall. The passing test retains this ordering.
Cancellation tests accept either launcher exit 70 after release EOF or SIGKILL, while requiring no program exec.

No product service, privileged command, physical terminal or device was activated.
The fixture is test-only and never enters the app bundle.
These results do not establish target credential transitions, installation identity validation, durable dispatch wiring or sudoers compatibility.
Full terminal forwarding, resize and physical end-to-end checks remain open.

## Repository gates

`./scripts/check.sh` passed, including 1124 Mac core tests and 97 Swift protocol tests.
The packaging checks, Python checks, disposable experiments and compiler ownership checks passed.
The required Kotlin/Android gate passed. Its XML reports contain 95 protocol, 195 phone, 59 approval-flow and 183 Android tests.
All 532 tests report zero failures, errors and skipped tests. APK assembly and Android lint passed.
The Gradle run took 19.254 seconds, with 62 tasks: two executed and sixty up-to-date.
The compact workflow finished and removed its managed logs.

## Review fixes

The review found raw pipe endpoints without close-on-exec flags during spawn setup.
Both ends now receive those flags immediately after each pipe creation.
Raw child endpoints close before spawn setup once their owned duplicates exist.
The Darwin public pipe API leaves a short creation-to-marking interval; concurrent host launches must use close-on-exec defaults.
The PTY test now explicitly fails when poll returns without readable output.
The full native gate passed again, including all eleven process tests. Clang analysis again reported zero diagnostics.
The required Kotlin/Android gate passed again in 19.260 seconds.
