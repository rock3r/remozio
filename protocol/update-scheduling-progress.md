# Signed update progress

This codec supplies the observations required by section 17 of the implementation plan.
It preserves the existing scheduling control and status codecs.
It does not advertise a channel, change admission or enable a product control.

The canonical CBOR map has these exact keys:

| Key | Value |
| --- | --- |
| 0 | Schema 1 |
| 1 | Canonical scheduling status bytes, without a committed-control digest |
| 2 | Phase: unknown 0, ready 1, draining 2, activating 3, checking restart 4, finishing 5, completed 6, cancelled 7 |
| 3 | Designation: unknown 0, unassigned 1, this account 2, another account 3 |
| 4 | Security status: unknown 0, ordinary update 1, security update 2 |
| 5 | Update-ready age in milliseconds, or null when unknown |
| 6 | Action bits: install when work finishes 1, defer 2, cancel drain 4 |
| 7 | Ordered blocker tuples: kind, count, oldest age in milliseconds |
| 8 | This account's admission state: unknown 0, open 1, closed 2 |

Blocker kinds are pending requests 0, active commands 1, live GUI permits 2, and other accounts 3.
Each kind appears at most once, in increasing order.
A local blocker has a positive count. Its age can be unknown.
The other-accounts marker carries neither a count nor an age. It contains no account or request identity.
No blocker carries command text, application details, a file path or an artifact URL.

The nested status binds the enrolled Mac, account, phone, epoch, query nonce, candidate, generation and intent revision.
A progress observation cannot contain a committed-control digest or acknowledge a scheduling action.
A lost control reply remains uncertain after a later progress read.

The Root signature uses `dev.remozio.update-scheduling-progress`, with wire 1, message type 1 and purpose 1.
The signing input contains the exact canonical payload bytes.
The payload must pass strict decoding before signature verification.
An older status signature cannot authenticate progress.

The action bits describe the observation. They grant no scheduling or installation authority.
Unknown phase or admission permits no action bits.
Irreversible phases permit no action bits. The UI can show current progress beside a Too late result.
Install requires an open account and a ready or cancelled phase.
Defer requires this account's explicit designation.
Cancel drain requires closed account admission and the account's retained install-when-work-finishes intent.
Every action still needs a fresh Root challenge, the current enrollment, the decision signature and the serialized activation checks.

An observation's local elapsed age advances its reported ages.
Unknown clocks, unknown original ages and unsigned overflow produce unknown age.
They never produce zero age or extend a control lifetime.
No age implies an activation deadline. Existing work can delay activation indefinitely.

The producer must capture the candidate, intent, designation, phase and admission under their actual current owners.
It must recheck that scope before publishing the signature.
The current release manifest has no security-update classification. A producer cannot infer an ordinary update from that absence.
The security status must remain unknown until verified release metadata establishes it.
Historical intent alone cannot establish current admission, quiescence or restart health.

The shared Swift and Kotlin vectors use disposable software signatures.
They cover canonical bytes, signature domains, malformed signed values, privacy, unknown clocks, and contradictory action claims.
Native producers, authenticated routing, version negotiation, and product controls require separate integration.
This codec proves no installed or physical-device behavior.
