# Nested PTY cancellation gap

The original fixture could exit 55 before monitor cancellation reached it.
It first reaped its killed foreground child, then returned from the cancellation mode check.
This produced a scheduling race in the wire-4 native test.
[Issue 261](https://github.com/rock3r/remozio/issues/261) records the failed CI run and diagnosis.

```mermaid
sequenceDiagram
    participant F as Test frontend
    participant R as Root execution owner
    participant M as Owned native monitor
    participant T as Original fixture target
    participant J as Nested foreground job
    F->>R: Bound foreground SIGKILL
    R->>J: Kernel TIOCSIG on retained private terminal
    J-->>T: Actual child wait status: SIGKILL
    T-->>F: CHILD_KILLED marker in regression mode
    Note over T: Remain alive; do not replace monitor cancellation with exit 55
    Note over F,T: Regression holds a 100 ms gap with no output EOF
    F->>R: Bound cancellation for the original request
    R->>M: Cancel the exclusively owned original target
    M->>T: SIGKILL
    M-->>R: Actual original target wait status
    R-->>F: Output EOF; then authenticated terminal result after acknowledgment
```

## Fixture change

| Case | Before | After |
| --- | --- | --- |
| Nested job receives SIGKILL | Original target could return 55 | Original target waits for monitor cancellation |
| Monitor cancels original target | Scheduling could change the test result | Actual SIGKILL remains the required result |
| Monitor cancellation is missing | Test did not isolate the gap | Fixture returns 61 after its finite deadline; test fails |
| Interrupt mode | Exact child and leader output; exit 7 | Same behavior and assertion |

The fixture requires a real SIGKILL wait status for its nested child.
The new regression mode emits its marker only after that child is reaped.
The existing cancellation mode emits no additional output.

The five-second wait bounds this disposable fixture only.
It changes no product command lifetime, cancellation policy, protocol profile or stream behavior.
The native owner still reports the actual target outcome. The assertion does not accept arbitrary exits.

## Regression

`testNativePTYCancellationGapRetainsOriginalTargetUntilMonitorCancellation` uses actual Mach channels and the current native monitor.
It resizes the private terminal, kills only its nested foreground job, and waits for the child-reaped marker.
It then verifies that no stream event or terminal result arrives during the cancellation gap.
It sends cancellation separately, drains output, acknowledges EOF, and requires the original target's actual SIGKILL result.
The test also verifies cleanup and rejection of another dispatch attempt.

The regression failed before the waiting fix with: “The original target must remain alive across the cancellation gap”.
After the fix, it passes alongside the existing interrupt and cancellation test.

Run the focused checks with:

```sh
swift test --package-path macos/core --filter 'testNativePTYCancellationGap|testNativePTYControlsResizeAndSignalTheCurrentForegroundJob'
```

These checks use private terminals and disposable targets on macOS 27.0.1, with an arm64 macOS 26 deployment target.
The monitor fixture substitutes only its UID guard. It changes no credentials and installs no privileged service.
They do not establish physical terminal behavior, production elevation or macOS 26 runtime behavior.
