# Command terminal owner evidence

Local validation ran on 2026-10-08 on an Apple Silicon Mac with the macOS 26 deployment target.
The execution channel profile remains wire 3, submission schema 1 and input carrier 4.

The focused gate passed eight terminal-codec tests and ten terminal-owner tests.
Two codec tests check the retained capture constructor against the original envelope and reject malformed bindings and digests.

The owner tests use actual Mach messages and disposable ordinary or independently checkpointed journals.
They cover signed denial, cancellation, expiry, pending restart, disappeared targets and owner closure.
A client integration test verifies admission, an empty poll, committed cancellation or expiry, and the exact terminal binding.
It checks both journal configurations without resubmitting the command.

An injected audit rejection sends no result and keeps the request pending.
Injected checkpoint prepare and finalize failures report only unknown and release the retained channels.
A fatal storage lease failure also reports unknown.
A full private reply queue does not delay or undo committed cancellation.
Generic success and failure transitions do not invent child exit codes.

These fixtures use the test user's process and code identity through internal policy seams.
They prove no privileged deployment, child execution, signal forwarding, PTY control or physical device behavior.
The public Root policy guard and release identity requirements remain unchanged.
The complete `./scripts/check.sh` gate passed 1,103 core tests and 97 Swift protocol tests.
Packaging, disposable experiments and external ownership compiler probes also passed.

The mandatory Kotlin and Android gate passed with JDK 21, platform 37.0 and build tools 37.0.0.
Its reports contain 95 protocol, 195 phone-core, 59 approval-flow and 183 Android unit tests, with zero failures or errors.
The APK and lint gates passed. Sixty tasks were up to date; approval-flow validation and lint ran again.
