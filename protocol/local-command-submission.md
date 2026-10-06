# Local command submission schema 1

`CommandSubmission` carries frontend claims between native Mac components. It does not grant elevation or prove OS provenance.
The caller supplies the exact schema selected by an authenticated local channel. Only schema 1 is implemented.
The payload schema, Mach carrier version, and phone capture schema are separate contracts.
This codec does not install a listener or advertise a completed frontend protocol.

Every map has exactly the documented keys. Unknown fields, versions, enum values, and malformed bindings fail.

| Key | Field | Encoding |
| --- | --- | --- |
| 0 | Submission schema | Unsigned 1 |
| 1 | Requested executable path | Absolute raw bytes, without NUL |
| 2 | Complete argv | Nonempty array of raw byte strings, without NUL |
| 3 | Requested working-directory path | Absolute raw bytes, without NUL |
| 4 | Requested target UID | UInt32 |
| 5 | Explicit environment additions | Array of maps described below |
| 6 | Requested I/O mode | Pipes 0, PTY 1 |
| 7 | Started-command disconnect behavior | Terminate 0, continue running 1 |
| 8 | Unverified rationale | Text or null |
| 9 | Submission binding | Map: ID16 at 0, nonce32 at 1, caller-channel binding16 at 2 |

Each environment addition is `{0: name bytes, 1: value bytes}`.
Names are nonempty and contain neither NUL nor `=`. They are unique and strictly ordered by unsigned byte lexicographic order.
Values can be empty and preserve non-UTF-8 bytes; they cannot contain NUL.
The frontend supplies the final unique additions. This codec does not select a minimal environment or resolve PATH.

The executable path and argv[0] remain separate. An empty individual argument, a custom argv[0], controls, and raw non-UTF-8 bytes remain intact.
The parser does not split arguments, add shell quoting, expand variables, or normalize paths.
Caller labels cannot supply requester identity, signing metadata, ancestry, file identity, executable hashes, or input classification.
Those fields are absent from this schema and cannot be added as unknown map keys.

The authority must compare the binding against its authenticated channel state. Copying the received binding into that state proves nothing.
Admission must enforce submission uniqueness, caller lifetime, deadlines, current elevation policy, and resource budgets.
A valid byte length or nonce is not proof of freshness. Automatic busy-state retries need the separate authenticated no-admission contract.
The frontend must authenticate Root before transferring input through the carrier.

Encoding and decoding use the same semantic checks and explicit CBOR byte, depth, and item limits.
Limit failures remain `CBORError.limitExceeded`; a host must map them to the distinct Request too large result without truncation.
No successful parse or capture construction substitutes for admission, user approval, or a durable execution permit.
