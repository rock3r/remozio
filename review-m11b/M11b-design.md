# M11b: status connection on the existing Setup listener

Proposal for Toni3795. Design only. No implementation or runtime result.
Source: clean Bepi852dff12 and the explicit snapshots in the M11/M12 audit.
Contract: `toni-gates/m11-m12-contract-20261116.md`.

## Decision proposed

Use the same Mach listener and a separate status selector. A connection becomes permanently status-only when it selects status first.
Use an authenticated facade to route calls. It holds no mutation capability until the unchanged normal endpoint construction and handshake succeed.
This avoids another service, another privilege boundary, dynamic interface replacement, or a second listener.
The facade is proposed code, not an existing endpoint.

A separate method alone is insufficient if connection construction still calls `owner.verifyCurrent()`.
That call reaches the blocked owner admission. Moving only the status handler would leave new connections unusable during an orphan.

## Connection states

| State | Permitted calls | Transition |
| --- | --- | --- |
| Undecided | A supported normal initial handshake, or status | Status selects StatusOnly; normal handshake selects OpeningNormal |
| StatusOnly | Status | No transition to normal |
| OpeningNormal | The already selected normal handshake | Success creates the private normal endpoint and enters Normal; failure closes |
| Normal | Existing protocol operations, with existing checks | Status is refused; use a separate status connection |
| Closed | None | Terminal |

The initial selector narrows capability. It never authorizes a mutation.
Latch the state under a short facade lock. Release that lock before any owner access or I/O.
An invalid normal handshake closes the connection. It must never fall back to status by catching a generic error.
An undecided connection cannot invoke an operation before a normal handshake.

Export one fixed protocol interface for the selected signed release. Add the typed status method with its own explicit format/version checks.
Keep existing normal versions, supported handshake selectors and handshake requirements unchanged.
Do not treat a status response as the existing normal handshake or set normal readiness flags from it.
No wildcard forwarding or runtime interface swapping is needed.

## Checks at accept

- Require the actual Root Setup process, unchanged protected configuration and installed signed release identity.
- Read the UID from the actual connection. Require a positive UID and the accepted signed app policy.
- Check the real connection credentials. Install the existing connection-lifetime retirement handling before activation.
- Reserve a bounded connection slot. Store the accepted policy and guard, without trusting request-supplied UID or account names.
- Create only the facade and status context. Do not call `owner.verifyCurrent()`, retry cleanup, open a mutable store, or borrow either reservation.

Listener startup still performs its existing full initialization checks before it first admits clients.
Accept-time status context uses the already pinned protected host identity. It fails closed on host retirement or configuration drift.
It does not validate installation changes by waiting for the busy owner's mutable machine reader.
Heavy fresh validation runs through the host's protected retirement mechanism; uncertain freshness makes status unavailable.

## Checks on every status call

1. Run `XPCInvocationGuard.verifyInvocation()` on the actual exported call stack, before asynchronous work.
2. Check process identity, connection lifetime, accepted signed policy and the actual peer UID again.
3. Select StatusOnly under the facade lock, or require that state already holds. Enforce the status request format and size bound.
4. Capture the connection-bound read context. Disclose only the reservation whose construction UID equals that peer's UID.
5. Validate the protected A/B binding and directory identity when available. Account A owns the caller; target B can have another UID.
6. Copy the bounded status projection, encode one reply, then recheck context lifetime before sending.

No administrator prompt is needed to read one's own status. M12 still imports fresh administrator rights separately.
A lost binding is unavailable scope, never permission to enumerate other accounts.
Never export rights, code requirements, paths, cleanup closures or arbitrary error text.

## Why a mutation cannot use StatusOnly

The facade owns a private optional normal endpoint. Only successful normal construction can set it.
Every normal selector requires immutable Normal state and that endpoint before it decodes privileged payloads, imports rights or starts tasks.
The endpoint retains every existing per-call peer, rights, owner-admission, handshake, busy and store check.
StatusOnly never acquires that object. Status reads cannot mutate mode, readiness, reservation or an operation token.
A status-capable context cannot satisfy a normal endpoint capability parameter.

Check every exported selector, including alternate hello methods, asynchronous imports, cancellation and reply paths.
A test must enumerate the interface selectors and attempt every normal selector before and after status selection.
A new selector without a route must fail closed. Status selection racing a normal handshake has one winner under the facade lock.

## Bounds while the owner lock is occupied

M11a publishes a small immutable projection separately from the owner lock. Publication performs no I/O and holds no worker or cleanup lock.
It contains record identity, authenticated ownership, a revision/freshness marker and the five separate status fields.
Status never calls `withMachine`, `retainedInvocationState()` under a blocking lock, or a body/cleanup join.
A nonblocking projection snapshot may report a field unavailable. Weak-owner absence reports orphan only for that exact current record generation.
It never proves settlement.

A protected durable read is optional and nonblocking. Even read-only SQLite obtains the existing exclusive writer lease.
If that lease or the projection publication lock is busy, return authenticated partial status immediately.
Do not enqueue a later store read, add a polling worker, or return an earlier value as current.
An earlier receipt may appear only with its exact revision and explicit stale provenance.

Proposed resource limits: one status call in flight per status connection, one bounded record in the response, 1KiB request and16KiB reply.
Keep the existing five-second undecided handshake timeout. Add no new executor, worker thread or listener.
A cancelled or disconnected call drops its reply owner. It cannot wait for the body or initiate cleanup.
OS credential validation has its own platform latency; this design promises no wait on the body or owner lock, not a hard wall-clock syscall limit.

**Connection accounting needs a contract decision.** To prevent normal connections consuming every slot, reserve capacity within the existing total of eight:
maximum six Normal/OpeningNormal, one StatusOnly, and one Undecided. A mode change atomically transfers the slot or refuses.
Undecided exhaustion lasts at most the existing handshake timeout. Saturation returns bounded unavailability; it cannot wait for a body.
This changes slot accounting and needs Toni's acceptance before code. It does not increase the total or establish new routing.

## Required evidence

Hold the owner lock behind a real test gate. On another accepted connection, status must complete before that gate opens.
Test reserved operation/reply tokens and a held writer lease independently. All must return bounded partial status without mutation.
Prove peer, directory and configuration drift refusal; stale projection labelling; one reply owner; selector races; and bounded connection exhaustion.
Preserve existing normal handshake and operation tests. Native installed behavior remains unqualified until its own attended gate.
