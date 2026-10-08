# Authenticated local command streams

Wire version 4 adds ordered command IO to input carrier 4. Both peers must offer version 4 explicitly. Legacy offers stay unchanged.

The CLI retains the original Root handshake and admitted request. A new private control queue belongs to that request alone.

```mermaid
sequenceDiagram
    participant CLI
    participant Root
    CLI->>Root: Negotiate wire 4; submit original descriptors
    Root-->>CLI: Admit the bound request
    Note over Root: The native execution owner remains a separate gate
    Root-->>CLI: Open the stream; transfer its private control right
    CLI->>Root: Bounded input, signal, resize, cancellation
    Root-->>CLI: Ordered output and input credit
    Root-->>CLI: Output EOF
    CLI->>Root: Acknowledge consumed output
    Root-->>CLI: Original terminal result
```

The diagram shows the channel contract. This PR connects the CLI session APIs and the authenticated transport owner. It does not connect the native PTY pump.

## Binding and ownership

Every frame contains the negotiated profile, submission ID, submission nonce, submission digest, and original admitted request identity.

The receiver checks the actual kernel sender and its current code policy. It also requires the original process incarnation. Another accepted code identity cannot reuse that binding.

The frontend checks every event against its retained Root process. A ready event must carry exactly one private control right. Other stream events carry no rights.

The receive owner remains the queue's sole consumer. Imported rights stay owned through transfer, failure, and closure. Stream closure neither signals a process nor grants another execution.

## Bounds and ordering

Each frame contains at most 4096 data bytes. Its complete canonical payload has an 8192-byte limit. Each private queue holds at most four messages.

Each direction has its own monotonic sequence. A successful send advances it once. Queue saturation and send interruption preserve the sequence and original unsent body.

The frontend starts with 32768 bytes of input credit. Successful input sends consume that credit. Valid credit events restore only the outstanding amount.

The native pump must enforce the same credit before retaining input. It must restore credit only for consumed input. It must keep its input and output buffers bounded.

Input EOF prevents more input bytes. It leaves signal, resize, cancellation, and output acknowledgment available. Output EOF ends the output sequence.

The frontend acknowledges output after it consumes the bytes. The authority exposes that acknowledgment for its finish controller. This prevents a full output queue from losing the single terminal reply.

Stream messages never establish an exit or authorize release. The native process owner and durable journal remain the sources of those facts.

## Current integration boundary

The existing native pipe dispatcher rejects wire 4 before spawning a child. The marker test proves this boundary. Existing wire 3 pipe execution stays unchanged.

The next integration must connect the Root PTY pump, native controls, continuous drain, and final reply. It must preserve the selected disconnect behavior.

The CLI executable must restore its original terminal settings on every exit. It must read no input before admission and the opened event.

No approved command gains a hidden runtime limit. An empty stream poll only ends that poll. A disconnect never resubmits a command.

## Evidence

Codec tests cover explicit negotiation, exact request binding, binary bytes, direction, limits, replay, gaps, and EOF ordering.

Kernel tests cover private control rights, full queues, retry without sequence loss, actual signed sender rejection, ordered output, and drain acknowledgment.

The CLI test verifies signal, resize, input, input EOF, cancellation, output, and the original terminal result. These tests do not signal a privileged child.

The disposable cross-process probe transferred 524288 bytes in each direction for each of ten trials. Each trial rejected another process with the same signing identifier.

That probe used one-slot queues and a 4096-byte pending buffer. Its parent observed 18 queue timeouts in total. All child processes exited with status zero and were reaped.

The minimum build target was macOS 26 on ARM64. The measured runtime was macOS 27.0.1. The retained evidence contains no secrets.

Still unproven: installed Root service, cross-user policy, actual macOS 26 runtime, complete PTY pump, real terminal restoration, and physical device tests.
