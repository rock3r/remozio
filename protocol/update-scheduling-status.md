# Signed scheduling status

This response binds one enrolled phone query to the Root's selected update and scheduling revision.
It grants no admission, execution, or installation authority.

The canonical CBOR map has these exact keys:

| Key | Value |
| --- | --- |
| 0 | Schema 1 |
| 1 | Mac ID, 16 bytes |
| 2 | Account ID, 16 bytes |
| 3 | Phone ID, 16 bytes |
| 4 | Enrollment epoch, 16 bytes |
| 5 | Query nonce, 32 bytes |
| 6 | Update ID, 32 bytes |
| 7 | Generation, greater than zero |
| 8 | Scheduling revision |
| 9 | Retained scheduling action, or null |
| 10 | Exact committed control digest, 32 bytes, or null |

Revision zero requires a null action.
A positive revision requires an action.
A committed control digest requires a positive revision and its retained action.
The digest does not supply an artifact or authorize activation.
The response limit is 2,048 bytes.
Unknown fields, invalid lengths, unsupported actions, and noncanonical encodings fail.

The Root signature uses `dev.remozio.update-scheduling-status` with wire 1, message type 1, and purpose 1.
It covers the exact canonical payload.
A phone control signature cannot authenticate this response.
Parsing does not authenticate the Root or establish freshness.
The consumer must verify its enrolled authority key, complete enrollment scope, original nonce, and query lifetime.
It must recheck current enrollment after verification.

A later observation cannot acknowledge an uncertain apply merely because its action and revision match.
Consumption acknowledgment also needs the exact committed control digest and the corresponding authenticated response.
Progress uses a separate domain and forbids that digest.
No codec in this slice advertises a channel or changes admission.
Native producers, authenticated routing, product controls, and physical-device checks remain separate work.
