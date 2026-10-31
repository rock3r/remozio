# Update scheduling control

This codec implements the separate scheduling claim required by section 17 of the approved plan.
It supports Install when current work finishes, Defer update, and Cancel drain.
It does not install a release or authorize a command, credential release, or GUI action.

The body is a canonical CBOR map with exactly these integer keys:

| Key | Value |
| --- | --- |
| 0 | Schema version 1 |
| 1 | Mac identity, 16 bytes |
| 2 | Account identity, 16 bytes |
| 3 | Phone identity, 16 bytes |
| 4 | Enrollment epoch, 16 bytes |
| 5 | Operation identity, 16 bytes |
| 6 | Fresh scheduling challenge, 32 bytes |
| 7 | Decision key identity, 16 bytes |
| 8 | Verified update identity, 32 bytes |
| 9 | Expected scheduling generation, greater than zero |
| 10 | Expected scheduling revision |
| 11 | Issue time in Unix milliseconds |
| 12 | Expiry time in Unix milliseconds, later than the issue time |
| 13 | Action: 0 install when current work finishes, 1 defer update, 2 cancel drain |

The update identity binds one already-verified release. The generation identifies its retained scheduling offer.
The revision binds the current scheduling state. Neither field sets a component generation or a security floor.
All integer fields retain the full unsigned 64-bit range, subject to the constraints above.
No artifact URL, file path, executable, proposed floor, or target action can appear in the body.

The signature input is a canonical map with keys 0 through 4.
It contains the domain dev.remozio.update-scheduling, wire version 1, message type 1, purpose 1, and the exact body bytes.
The body must pass strict decoding before signature verification. Unknown fields, actions, schemas, and noncanonical encodings are rejected.
The signature uses the existing P-256 raw signature and uncompressed public-key formats.

## Authority checks still required

The authority must select the current enrolled decision key and bind the Mac, account, phone, epoch, and key identity.
It must compare the update identity, scheduling generation, revision, challenge, and lifetime with retained protected state.
It must consume the matching one-use scheduling challenge atomically with the scheduling change.
A valid signature alone cannot change scheduling state.

The future coordinator must serialize controls with request admission, permit dispatch, and activation.
Defer and Cancel drain resume ordinary admission before irreversible activation.
After irreversible activation starts, cancellation returns Too late and the current progress.
Neither control rolls back an install or revives an old process.
A long command can delay activation indefinitely. No new deadline or forced termination is introduced.

This component does not add a live endpoint, advertise a release capability, select Sparkle integration, or change admission behavior.
Root storage, replay handling, authenticated transport, local IPC, app controls, and installed update continuity remain separate work.

## Validation

Swift and Kotlin use the same five valid vectors and 102 malformed vectors.
The cases cover every action, unsigned boundaries, malformed but correctly signed claims, changed fields, domain separation, and resource limits.
Fixture signatures use disposable software keys. No private key is retained.
These tests do not qualify an installed updater or physical-device behavior.
