# Original command execution resources

The request owner can transfer a command's original OS resources once, after a matching execute decision commits.
The internal resource owner is non-Sendable. It remains inside the same serialized Root boundary.
Transfer grants no permission to spawn, release or repeat an approved program.

```mermaid
sequenceDiagram
    participant Q as Request coordinator
    participant E as Execution resource owner
    participant T as Original terminal channel
    Q->>Q: Verify authorized request and durable matching decision
    Q->>E: Transfer original caller, streams, directory and terminal right
    Q->>Q: Remove command reference; retain lifecycle metadata and budget
    E->>E: Final current caller and filesystem recheck
    alt Recheck fails
        E->>E: Retire execution streams and caller
        Note over E,T: Original terminal right remains available
    end
    E->>T: One nonblocking established outcome attempt
    E->>E: Close resources independently of pending request retirement
```

## Exclusive transfer

Queued, declined, already-dispatched and previously transferred requests cannot supply resources.
The coordinator checks the persisted decision revision, action, digest and challenge against its original live request.
It constructs the terminal identity from that retained request. Incoming copies and receipts do not select resources.
The old capture becomes closed. An old alias cannot borrow input, perform another recheck or close the transferred resources.
The coordinator retains its request budget and lifecycle metadata until the ordinary terminal transition.

## Final checks and terminal lifetime

The execution owner rechecks the retained caller, executable, directory, input, output streams and original terminal right.
A failed check retires the execution resources. It keeps the original terminal right for the controller's established outcome.
No new capture, descriptor import, terminal endpoint or caller binding replaces an approved object.
Ordinary admission rechecks still require their own terminal right and reject a detached one.

Closing pending request state does not close resources already transferred to the execution owner.
The future dispatch controller must retain this owner and maintain its native child cleanup independently of storage availability.
It must not drop a live child owner when journal recovery closes admission or stops request-expiry maintenance.

The trusted controller supplies an established terminal observation after its required durable transition.
The private send never waits for queue capacity. A failed send consumes the attempt and closes its send right.
A second attempt is rejected. A lost reply cannot authorize a second execution.
This resource owner does not infer a program exit from generic lifecycle state.

## Evidence and remaining integration

Tests use original Mach submissions and real fileport-backed streams.
They verify one transfer after durable consumption, rejection paths, unchanged queued input and independence from pending-owner closure.
Final caller-policy failure and executable replacement retire execution resources while preserving exact terminal bindings.
A full terminal queue produces a bounded failed send, with no second attempt.

The native process owner, protected launcher validation, durable dispatch checkpoint, observed child result sink and runtime scheduling must still be connected.
PTY stream forwarding, resize and authenticated control messages also remain required.
No command executor or privileged service is activated by this handoff.

The complete local native gate passed with 1,133 core tests and 97 protocol tests.
The required Kotlin and Android gate passed with 532 tests, the debug APK build and lint.
These checks do not prove privileged installation or physical terminal behavior.
