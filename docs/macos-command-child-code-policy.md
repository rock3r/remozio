# Installed command helper policy

The protected code policy records the command child as role 11 and the command monitor as role 12.
Each entry retains the team, signing identifier, code-directory hash, installed generation and minimum generation.
This metadata grants no permission to execute a command.

## Catalog formats

| Catalog format | Accepted roles | Use |
| --- | --- | --- |
| 1 | Original roles 1–10 | Read existing installations without changing their canonical bytes |
| 2 | Original roles and command child 11 | Read existing child policies with unchanged canonical bytes |
| 3 | Original roles, child 11 and monitor 12 | Write new policies and record both protected helpers |

Unknown formats and roles fail closed. Format 1 cannot carry roles 11 or 12. Format 2 cannot carry role 12.
New policy construction uses format 3. Decoding preserves the original format for canonical validation.
A successor cannot lower its catalog format, remove an existing role, change its identity or lower either generation floor.
Inactive roles retain their identity and floors.

```mermaid
flowchart LR
    A[Legacy catalog 1] --> B[Protected installation transaction]
    B --> C[Catalog 3 with child and monitor]
    C --> D[Checkpoint completes]
    D --> E[Later dispatch validates protected launcher]
    C -. rejected .-> A
```

## Stored policy compatibility

The catalog format is separate from the stored snapshot format.
Snapshot format 2 wraps a tagged catalog and the retained revision token for each role.
It can contain catalog 1, 2 or 3. Existing bare catalog 1 rows remain readable.
Bare catalog 2 and 3 are not legacy snapshots and are rejected.

An upgrade changes the global policy revision and the checkpointed authority digest.
Unchanged entries retain their existing role tokens. Each new helper role receives its own token.
The audit ledger and its head remain unchanged by this installation metadata update.
A rejected downgrade leaves the installed policy and checkpoint intact.

Older binaries reject catalogs above their supported maximum. They must not reinterpret it or reset the protected store.
The installer and update flow must respect this support boundary when choosing a runnable authority binary.

## Dispatch integration

The Root dispatch API reads the current active child, monitor and frontend entries from protected journal state.
It validates both retained protected helper paths with `SignedExecutableValidation` and their installed identities and floors.
It repeats those checks before and after the durable dispatch transition, before releasing the original prepared child.
A copied policy entry, receipt or caller-supplied path cannot authorize release.

The command process mechanics are described in [the native process owner](macos-command-process.md).
Protected installation, selected elevation policy and host-service wiring remain required before product execution.
The catalog change does not install or activate a service.

## Validation

Tests retain exact catalog 1 and 2 bytes, reject newer roles under older formats and reject unknown formats.
They preserve inactive floors and existing role tokens across the monitor upgrade. A downgrade or removal of the monitor role is rejected.
They check the stored wrapper separately from its catalog and reject bare catalog 2.
A journal test upgrades the legacy catalog, preserves old role tokens and floors, and creates both helper tokens.
It reopens the store, reconciles the completed checkpoint and rejects a format downgrade without changing persisted state.

Local validation on 2026-10-08 passed all nine focused tests.
The full native gate passed with 1127 core tests and 97 protocol tests on Apple Silicon, with the macOS 26 deployment target.
The required Kotlin/Android gate passed in 26.660 seconds, including 532 tests, APK assembly and lint.
These checks do not establish a protected installation or a connected product executor.
