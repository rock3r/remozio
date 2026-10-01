# Phone request core

This Kotlin/JVM module owns authenticated command sessions and signed status tracking. The Android app uses these classes directly. They contain no Android platform APIs, storage, network client, approval controls, or private signing keys.

A session verifies a command against caller-supplied trusted enrollment identity. It retains the typed capture until a verified terminal status clears it. The status tracker preserves request bindings, revision ordering, outcome continuity, and elapsed-time bounds. The caller still owns enrollment invalidation and clock sampling.

Run `:phone-core:test` for the eighteen portable unit tests. They reuse the invented command fixture from the Android debug source set. The fixture is a declared test input, not a runtime dependency or production resource.

## Swift/Kotlin flow checks

On a Mac, run `python3 scripts/build-approval-flow.py` and then `:phone-core:approvalFlowTest`. The latter is a separate Gradle test task. It starts the compiled synthetic Swift peer and exchanges canonical signed payloads over child-process pipes. Missing native build output fails the task; it does not silently skip integration checks.

The [approval-flow experiment](../../docs/experiments/approval-flow.md) describes its trust setup, tested cases, and limits. The portable test task excludes that integration class, so Linux can run the shared state tests without a Mac peer.
