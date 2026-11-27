# Mac audit retention

The Mac keeps audit history for each Remozio account. When the account has 110,000 audit records across all epochs, maintenance aims to reduce the count to 100,000. An epoch is a continuous period in the Mac's audit history.

The authority checks once a minute. It waits until there are no live approval requests, active command exchanges, or command executions. Each pass can remove up to 10,000 records. It starts with the oldest records it can verify. It keeps the records that link epochs, the latest record in the active epoch, and the records needed for recovery. If these rules prevent the Mac from reaching the target, the authority logs the excess and keeps those records.

Requests can wait while a batch commits. If retention cannot plan a safe batch, it logs the error and suspends maintenance until restart. The authority can still approve requests. Storage and integrity failures follow the authority's normal recovery procedure.

When the Mac transfers audit history to a phone, its signed status shows the sequence through which the Mac removed older records. A signed page reports a retention gap when the phone requests records before that boundary. A phone can still verify records and evidence that it saved before the Mac removed those records.

This limit applies to audit records. The Mac keeps its separate records of consumed decisions, command outcomes, and replay reservations.
