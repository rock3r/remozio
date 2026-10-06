# Command caller identity experiment

The experiment receives a kernel audit trailer from a disposable peer. It ignores identity claims in the message payload.

## Reproduce

On an Apple Silicon Mac with Xcode:

~~~sh
python3 scripts/run-macos-command-caller-experiment.py
~~~

The normal Mac check runs this experiment, including the macOS 26 CI job.

The runner builds a minimal peer and a separate Security.framework probe. It signs the peer with a disposable ad-hoc identity and pins its CodeDirectory hash.

The probe creates an anonymous Mach endpoint. It passes that endpoint through the peer's task bootstrap port during spawn.
This handoff is a fixture technique. It does not install a launchd service or select the production command transport.

The peer sends deliberately false PID and audit-token fields. The receiver uses the kernel trailer instead.
Public libbsm functions expose the PID, effective UID, and process incarnation.
proc_pidpath_audittoken and SecCodeCopyGuestWithAttributes use that same audit token.

~~~mermaid
sequenceDiagram
    participant R as Receiver
    participant K as macOS kernel
    participant P as Disposable peer
    R->>P: Spawn with anonymous endpoint and control pipe
    P->>K: Send false identity claims
    K->>R: Message with kernel audit trailer
    R->>K: Resolve path and code with trailer token
    K-->>R: Current peer identity
    R->>P: Continue through exec
    P->>K: Send from new incarnation
    K->>R: New audit trailer, same PID
    R->>K: Recheck old token and retained code
    K-->>R: Reject old incarnation
    R->>P: Close control pipe
    R->>R: Reap peer and reject exited identity
~~~

## Local evidence

The [retained report](evidence/2026-10-06-command-caller.json) records macOS 27.0.1, build 26A434, arm64, and SDK 27.0.
Both binaries use a macOS 26 deployment target. This local run does not prove macOS 26 runtime behavior.

All 23 identity observations passed. Four additional rejection cases passed.

The [CI report](evidence/2026-10-06-command-caller-ci.json) records the same observations on macOS 26.6.2, arm64, with SDK 26.5.
Its source hashes match commit `9d6c4e93b05b2e6d316208d96bd02adf0050bc1e`.
The [source job](https://github.com/rock3r/remozio/actions/runs/37518929508/job/112458952522) provides the report provenance.
This proves the fixture behavior on macOS 26. It does not prove installed privileged service behavior.


| Check | Observed result |
| --- | --- |
| Kernel PID and effective UID | Match the spawned peer and current account |
| False payload PID and token | Differ from the kernel identity used for lookup |
| Audit-bound path and signing information | Available for the current peer |
| Known fixture identifier and CodeDirectory hash | Accepted |
| Wrong CodeDirectory hash | Rejected |
| Same peer after exec | Same PID, different process incarnation |
| Old token and retained old code after exec | Rejected while the peer remains alive |
| New token and pinned code after exec | Accepted |
| Token and retained code after peer exit | Rejected |
| Wrong pin, silent peer, wrong phase, or missing exec message | Reject the experiment and reap the peer |

Source hashes in the report bind the evidence to the C fixtures.
The runner emits host details and boolean outcomes. It does not emit tokens, PIDs, paths, or signing material.

## Cleanup and limits

All messages use bounded sizes and receive deadlines. Control waits and child exit waits are bounded.
The probe closes its descriptors, releases Mach rights and code objects, and reaps its peer on failure.
The runner uses a private temporary directory and kills the probe process group if its outer deadline expires.

The endpoint exists only in these disposable processes. No root service, system setting, phone, or network endpoint changes.

These observations establish a candidate for admission identity checks. They do not implement production admission or execution.
A production receiver must obtain the token from its actual authenticated IPC transport.
It must enforce the configured component identity and security generation, then recheck the retained identity at dispatch.

The fixture pin is not Developer ID trust or a production code floor.
Actual PID reuse, privileged service placement, caller ancestry, sudo policy, process I/O, and device E2E remain untested.
The exec check tests an incarnation change while keeping the PID. It does not force PID reuse.

The experiment uses public declarations from the installed Mach, libbsm, libproc, spawn, and Security headers.
It does not read a private NSXPCConnection audit-token property.
