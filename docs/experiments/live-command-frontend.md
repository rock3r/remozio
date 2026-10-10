# Live command frontend experiment

Run `python3 scripts/run-macos-live-frontend.py` on an Apple Silicon Mac without elevation.
The repository gate runs this experiment on macOS.
Evidence appears in `.build/live-command-frontend/evidence.json`.

The authority, supervisor, frontend, monitor and target are separate processes.
The authority uses `CommandReceiveHost`, the journal and `CommandExecution`.
The frontend uses the authenticated execution session and the product main loop.
The monitor and launcher include product sources through explicit fixture wrappers.
Each caller terminal belongs to a private session created by the runner.

```mermaid
sequenceDiagram
    participant Supervisor
    participant Frontend
    participant Authority
    participant Monitor
    participant Target
    Frontend->>Authority: Handshake and mapped terminal submission
    Authority->>Authority: Capture, admit and consume fixture approval
    Authority->>Monitor: Prepare target and commit dispatch
    Authority->>Monitor: Release once
    Target->>Target: Stop with SIGTSTP
    Monitor->>Authority: Actual wait observation
    Authority->>Frontend: Authenticated historical stop
    Frontend->>Authority: Fresh current-job query
    Authority->>Frontend: Real BSD/Mach stopped state
    Frontend->>Frontend: Restore terminal and suspend
    Supervisor->>Frontend: Resume in background
    Frontend->>Authority: Original authenticated SIGCONT control
    Authority->>Target: Resume owned foreground job
    Target->>Supervisor: Private resumption marker
    Supervisor->>Frontend: Set foreground ownership
    Frontend->>Authority: Fresh terminal dimensions
    Target->>Monitor: Exit 13
    Monitor->>Authority: Reaped target result
    Authority->>Frontend: Durable verified result
```

The runner repeats each case three times and requires matching observations.

| Case | Actual behavior | Required observation |
| --- | --- | --- |
| Original job | The target stops itself. The frontend suspends after a fresh query. | Restored caller attributes, background target resumption, new dimensions and one admission. |
| Overtaken stop | A real continuation resumes the target before the frontend receives the historical stop. | A fresh query reports running. The supervisor observes no frontend suspension. |
| Nested shell | Typed Ctrl-Z stops an owned nested target. Typed `fg` resumes it. | A query reports unknown during nested ownership and running after Bash regains the terminal. Bash and the frontend never stop. |

All cases require actual owner reaping and the journal's revision-two verified outcome.
Exit 13 produces a verified failure phase. It is the fixture's expected command result.
The supervisor checks terminal attributes after the frontend exits.
The nested target waits for an actual continuation and an explicit keyboard release.
It cannot finish because a short sleep expires before the query completes.
Cancellation asks the supervisor to retire its own frontend.
The authority stays alive while the product owner cancels and reaps its monitor and target.
If graceful cancellation stalls twice, the runner freezes its own authority child before collecting descendants.
It freezes each parent before enumerating that parent's children, so a captured child cannot be reaped and reused.
Signals to descendants use kernel-checked audit tokens. No descendant is signalled through a borrowed PID or group.
Cleanup proceeds from children to parents. Native owners receive time to reap their children before forced termination.
The runner requires exit events for every captured descendant before resuming and reaping its own authority child.
A partial snapshot restores cooperative cleanup and reports failure. It grants no authority over unobserved processes.
This cleanup belongs to the unprivileged fixture. It does not change product cancellation or elevate the runner.
Source hashes cover compilation inputs before the build and are checked after compilation and the trials.

The runner also forces a second timeout after the real frontend has stopped and restored terminal attributes.
The authority remains stopped while its supervisor, frontend, monitor and target occupy their original sessions.
Retained evidence requires all four descendant exit events and the runner's actual authority wait.
This failure case cannot claim that the runner reaped grandchildren. Each direct child's parent owns that wait.
Independent tests verify a real child-wait boundary and reject a changed audit-token incarnation.
The [Apple signal wrapper](https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/libproc/libproc.c)
and [kernel implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/proc_info.c) define the audit-token path.

The overtaken-stop case delays an already authenticated frontend observation.
It does not replace the authority's current-job callback.
Nested input enters through the private caller terminal and passes through the real frontend relay.
The nested queries are explicit fixture probes on the original execution session.
These probes do not add application behavior.

Credential operations are fixture substitutes restricted to the current user.
The enrollment uses disposable software keys. It proves no Android biometric property.
The fixture policy uses the actual executable hash with synthetic role metadata.
The authority right passes through an owned child's special port. No bootstrap service is registered.
These seams prove no protected installation, production signing, cross-user elevation or service discovery.

The local runtime is macOS 27.0.1. The compilation target is macOS 26.
A compilation target does not prove behavior on that runtime.
CI must run the same cases on macOS 26 before merge.
This experiment uses no user terminal and installs no services.
Its deadlines bound fixture runs. They add no product command runtime limit.
Physical device tests remain pending.
