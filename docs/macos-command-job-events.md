# Native command job observations

Local wire 6 extends the PTY stream. Local wire 7 extends separate stdio controls.
Both use carrier 4 and submission schema 1. Each requires an explicit offer from both peers.

```mermaid
sequenceDiagram
    participant F as Original frontend
    participant R as Serialized Root owner
    participant M as Owned native monitor
    participant T as Original target
    F->>R: Explicit wire 6 or 7; original submission and stdio
    R-->>F: Bound admission and opened control right
    R->>M: One committed release
    M->>T: Execute original command
    F->>R: Authenticated stop control
    R->>M: Apply control through retained native ownership
    M-->>R: Native revision and original target snapshot
    R->>R: Check current policy; coalesce only unsent observations
    R-->>F: Ordered, request-bound stopped observation
    F->>R: Authenticated continue control
    M-->>R: Higher native revision; continued snapshot
    R-->>F: Ordered, request-bound continued observation
    Note over R,M: Exec, exit and actual wait evidence remain independent
    R-->>F: Original terminal outcome
```

## Explicit compatibility

| Wire | Stdio | Job observations | Output acknowledgment |
| --- | --- | --- | --- |
| 3 | Separate fileports | None | None |
| 4 | Private PTY stream | None | Required |
| 5 | Separate fileports with controls | None | None |
| 6 | Private PTY stream with controls | Native target snapshots | Required |
| 7 | Separate fileports with controls | Native target snapshots | None |

Existing defaults and wire 3, 4 and 5 meanings remain unchanged.
A caller that requires observations offers `streamingJobExecution` or `pipeJobExecutionControls`.
It does not silently fall back to a profile without observations.
Wire 7 rejects PTY bytes, credit, resize, EOF and output acknowledgment.
Wire 6 retains the PTY input window and interruption marker.

## Exact observation fields

A job frame uses the existing canonical stream envelope with body tag 5.
It includes the original profile, Mac, account, submission, digest and admitted request binding.

| Body key | Meaning | Accepted values |
| --- | --- | --- |
| 0 | Native job revision | Positive UInt64 |
| 1 | State | 1 for stopped; 2 for continued |
| 2 | Stop signal; stopped only | Positive native signal below NSIG |
| 3 | Raw stop code; stopped only | CLD_STOPPED or CLD_TRAPPED |
| 4 | Tracing snapshot; stopped only | 0 unknown; 1 untraced; 2 traced |

A continued body contains only keys 0 and 1.
Unknown keys, tags, tracing values and invalid fields fail closed.
The observation exposes no PID, birth identity, release permission or retry authority.

The tracing value describes the stop snapshot. It does not establish the historical stop cause.
Unknown remains unknown. Neither raw stop code proves that the stop came from a debugger.
The target can emit a continued snapshot after its initial release.
A nested foreground job has its own owner and does not imply that the original shell stopped.

## Bounded delivery and authentication

```mermaid
flowchart LR
    N[Latest accepted native record] --> A[Active original target and successful release]
    A --> P[Current protected policy and original caller checks]
    P --> C[One pending observation]
    C --> Q{Private queue has capacity?}
    Q -- No --> C
    Q -- Yes --> E[Emit next channel sequence]
    E --> V[Verify original Root sender and exact request binding]
    V --> J[Require a strictly higher native revision]
```

Root retains one unsent observation. A newer native revision replaces that pending value under queue pressure.
Native revisions can skip. Emitted channel sequences remain consecutive.
A full queue advances no sequence. Repeated identical native snapshots produce no additional frame.
Policy is checked before pending delivery, not during idle polling after delivery.
Known target exit or an uncertain observation discards the unsent snapshot.
A frame already queued can describe an earlier state.
These observations are not a complete history of every kernel transition.

The frontend authenticates Root before decoding the frame.
It checks the original binding, direction, channel sequence and increasing native revision.
Failure closes that original session without resubmitting the command.
Only this verified path constructs `VerifiedCommandExecutionJobObservation`.
External callers can read the observation but cannot construct it through the public API.

PTY output EOF ends bytes and credit. It still permits later job observations.
This does not reopen output or remove the required output acknowledgment.
Pipes retain their original separate descriptors and require no stream acknowledgment.
Job frames cannot prove execution, exit or successful cleanup.

## Validation and remaining integration

Tests exchange real anonymous Mach messages and exercise the four-message queue.
They verify unsent coalescing, repeated revision rejection, exact binding and observations after PTY EOF.
Codec tests reject malformed fields, wrong directions and incompatible profiles.
External compiler probes check that verified observation construction remains private.

Native tests stop and continue disposable commands in both I/O modes.
They then cancel the original target and verify its actual SIGKILL outcome and cleanup.
The monitor fixture substitutes only its UID guard. The launcher changes no credentials.
These tests grant no production elevation and install no service.

The local runtime is macOS 27.0.1. The build targets arm64 macOS 26.
The installed frontend, terminal restoration and macOS 26 runtime remain separate gates.
The frontend must not suspend itself from a queued historical snapshot alone.
Debugger attach and ownership changes remain tracked in [issue 250](https://github.com/rock3r/remozio/issues/250).
Physical device and privileged end-to-end checks wait for the interactive handoff.

## Fresh target state

The native parent now provides a read-only query for its original retained target.
It checks the target's birth identity and monitor parent before and after reading task information.
It acquires a task-name right, reads the suspension count twice, and releases that right.
It acquires no task-control right and consumes no target wait event or status record.
Missing, retired, unstable, or unavailable evidence remains unknown.
Queued signal controls also keep the result unknown until the monitor acknowledges their application.
The acknowledgment uses [private monitor wire version 2](macos-command-monitor-protocol.md). It does not change historical frontend profiles.

```mermaid
flowchart TD
    O[Original retained monitor owner] --> A{All queued controls acknowledged?}
    A -->|No| U[Unknown]
    A -->|Yes| B[Check target birth and parent]
    B --> N[Acquire read-only task-name right]
    N --> M[Read task suspension count twice]
    M --> R[Release name right and recheck target]
    R --> K{Stable evidence available?}
    K -->|No| U[Unknown]
    K -->|Yes| C[Compare BSD state with actual suspension]
    C --> S[Current stopped or running observation]
```

BSD status alone does not establish current suspension on the local runtime.
A disposable child can resume through SIGCONT inside `sigwait` while BSD status remains SSTOP.
Its actual continuation marker proves resumed execution; the task suspension count becomes zero.

| Owned-child probe | Before SIGCONT: BSD / suspension count | After continuation marker: BSD / suspension count |
| --- | --- | --- |
| Returning handler | SSTOP / 1 | SRUN / 0 |
| `sigwait` | SSTOP / 1 | SSTOP / 0 |

Both children were explicitly reaped on macOS 27.0.1, with an arm64 macOS 26 deployment target.
The repository fixture is `sigwait-current-state.c`; `FrontendRuntimeTests` runs it in disposable processes.
The first local measurement is retained in `/tmp/remozio-sigwait-state-probe.jsonl`.
This does not establish behavior on the supported macOS 26 runtime or signed installed targets.

Apple's current source resumes the task in its SIGCONT wait branch without assigning SRUN there.
That difference suggests the bookkeeping explanation; it does not identify the exact running kernel source.
See the [SIGCONT wait branch in XNU](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_sig.c).

The fresh query requires actual suspension as well as BSD stopped status before reporting a current stop.
A zero suspension count can disprove the retained BSD stopped status.
The returned stop signal belongs to the retained native revision; it does not prove a historical stop cause.

The monitor fixture verifies a current stop, then queues SIGCONT through the original control pipe.
The query remains unknown before Root consumes the application acknowledgment. Once acknowledged, fresh kernel evidence must report running.
The fixture also pauses its owned monitor before queuing SIGCONT. This makes the delayed application window explicit in both I/O modes.
An acknowledgment for an unqueued control closes the original status channel and leaves the query unknown.
A negative control replaces the query with cached state; that control fails this probe and still reaps its owned monitor.

The `sigwait` target also resisted SIGTERM retirement in the measured sequence.
The fixture explicitly uses SIGKILL for final retirement and verifies that actual signal outcome.
This changes no production signal policy and introduces no automatic substitution of SIGKILL for SIGTERM.

The [fresh confirmation transport](macos-command-current-job.md) now uses explicit profiles 10 and 11.
It binds a query nonce and rechecks the original caller and current protected policy.
The CLI selects these profiles and reconciles the fresh result with its local signal ticket and terminal foreground ownership.
The [frontend runtime](macos-command-frontend-runtime.md) records its disposable stop/resume composition checks and remaining installed-service gates.
A Root control-pipe write does not establish that the monitor has applied an earlier SIGCONT.
The native query now preserves that control order through the application watermark.
Current profiles and their historical snapshot meanings remain unchanged.
