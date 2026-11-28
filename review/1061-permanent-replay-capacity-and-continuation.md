# Permanent replay capacity and account continuation

Refs #1061. Related: #1005, #1059, #1065. Source baseline: `9b7155e78f1494b6d02322ea84a0206e45e16985`. Both parts are proposals. Part A needs Toni's approval. Part B needs Saturn's design review and a separate decision before implementation.

## Part A. Show the limit and make a full account diagnosable

The installed cap is **1,000,000 consumed request IDs** and **1,000,000 command submissions with their paired nonces** per account. Each reservation consumes one submission slot. The nonce is a second lookup key for the same slot. The live receipt count is a separate limit. Retirement can free receipt detail, while permanent counts continue to accumulate. The two-million-entry fixtures from #1065 measured scale and did not raise the installed cap.

### Where the user sees it

- **Mac Unified Log.** Use the existing Authority logging path under `dev.sebastiano.remozio.macos.authority`, with a dedicated `replay-capacity` category. A support technician can find the events in Console. Emit a notice at 80% and 95%, and an error at the cap. Use separate counters for `consumed_requests` and `command_submissions`. Each event contains a fixed reason, current count, limit, and band. Leave account IDs, request IDs, nonces, keys, payloads, and paths out of the event.
- **Mac command caller.** When it receives a verified `capacityExceeded` admission result, show “Approval capacity reached. See Remozio diagnostics.” Keep the existing exit status and no-retry behavior. That result can also signal temporary capacity. The text deliberately covers both. The Authority log identifies permanent exhaustion after verifying the exact counter.
- **Setup, Paired Phones, and the phone.** Use the log for this slice. A banner would need a trusted, account-scoped status source that these screens do not currently carry. If Console proves insufficient, propose one account-level capacity row in Setup through an existing verified status read once available. Keep phone frames unchanged. The signed decision refusal frame has no capacity reason, so it cannot carry a precise new phone error in this slice.

### Observation and refusal

1. Read the scoped `PermanentReplayCounters` in the existing verified startup read and in the existing validated admission or consumption transaction. Use the exact bounds enforced by each guard. Do not add a full journal scan or a second checkpoint read to successful hot paths. Capture the current reason at the guard to distinguish exhausted permanent keys from live receipts or transient in-memory limits.
2. Prepare an observation in the transaction and emit it only after its outcome is proved. A threshold crossing from an increment needs the durable commit and checkpoint. A rejection needs the existing proved no-write or rollback path. A storage or integrity failure has its own outcome. It does not provide a capacity observation.
3. Compare integer counts with inclusive 80%, 95%, and 100% boundaries. At steady state, report each newly reached band once per counter per Authority lifetime. On startup, report only the highest band already reached. Rate-limit repeated refusals from the same full counter. Suppression is memory-only and resets on verified startup.
4. On a full command set, retain the existing authenticated `capacityExceeded` result where supported. On a full consumed-request set, keep the current fail-closed decision path and report the stable local diagnostic. Do not report success or retry from the diagnostic. A format 19 journal cannot supply permanent counts. Report no permanent band for it and leave its existing limits in place.

No changes to SQLite format, stored rows, signatures, wire types, or the numerical limit. Relevant seams are `InstalledAuthorityCommandRegistration.swift:163–185`, `PermanentReplayCounters.swift:65–87`, `ConsumptionJournalTables.swift:69–119`, `CommandSubmissionReplayTables.swift:72–116`, `ApprovalRequestCoordinator.swift:605–648,796–821`, and `CommandFrontendMain.swift:279–290`.

### Tests for the small PR

- Verify both counters just below and at each band. Use low fixture limits and cover a threshold that is not an integer count. Verify the fixed text, field allowlist, highest startup band, and bounded repeat reports.
- Verify that a rolled-back increment and an unverified counter emit no success-derived warning. Exercise the full-store restart and show that a fresh request or submission cannot add a key, a receipt, an outcome, or a reservation beyond the cap. Check that prior IDs and nonce-only repeats still refuse and that the existing authenticated caller contract holds.
- Reuse `ConsumptionJournalTablesTests`, `CommandSubmissionReplayTablesTests`, `CheckpointedJournalTests`, the capacity and retirement fixtures in `MachCommandCallerReceiverTests`, and `CommandFrontendReadinessPresentationTests`. Include the existing finalized-gap fixture. Send compiled selectors, forecast, and caps before the test gate.

## Part B. Design a successor account scope

A full account needs an operator-authorized succession workflow. Recommend a fresh account ID, a new journal and continuity scope, explicit routing to the new account, and fresh enrollment. Re-pair within the same account leaves the same quota keys. An audit recovery epoch is also insufficient on its own. The current `ChannelScope` binds Mac, account, phone and enrollment epoch, and `DecisionVerifier` checks the retained request and challenge in addition to scope.

### Proof and durability requirements

- **Bind authorization to the successor.** Close old admission and resolve or fence in-flight work before changing the route. The old scope may serve authorized historical reads. It cannot admit new work or accept old authorizations. Do not move an old active request, signed decision, command grant, or execution permit. A new pairing and caller capture must bind to the successor scope. Reject former-scope proofs even if presented on a current channel. Preserve revocation, policy, and audit history. A fresh account does not reactivate a retired phone.
- **Preserve replay membership.** A new account ID is sufficient to separate previously signed proofs, but its scoped indexes alone do not reject an old raw ID or nonce presented in a new envelope. Retain the old complete sets as sealed, authenticated membership evidence. Require exact negative lookup in the active scope and every predecessor before admitting the successor's relevant request ID, command submission ID, or nonce. Root must own the check and insertion boundary. Do not depend on an unverified cache, a copied summary, or a probabilistic negative. Keep all older keys in a supported succession. Missing predecessor evidence keeps admission closed. Start by measuring a single predecessor, with a bounded successor chain until lookup and startup costs are measured.
- **Recover the cutover.** Review how the protected account registry, the old drain and the new store share a durable transition record. That record must bind both store identities and the predecessor's final checkpoint. Reopening requires the successor's validated state and routing plus a monotonic indication that old admission cannot reopen. Exercise restart after drain, after writing the successor, before and after routing changes, and before admission opens. A partial transfer cannot activate both journals. An older binary or stale snapshot must fail closed through the supported reader floor. Keep the predecessor readable so the user can still inspect prior audit and state.
- **Define the user action.** Document what is carried into the new account, which phones need fresh enrollment, and how the old history is opened. Review caller and Gateway scope ownership and the order of revocation and replacement. This design is not a reset button or a supported procedure today.

### Relationship to #1059

A format 19 journal with a recorded gap cannot prove a complete lifetime set. `CheckpointedJournal.installPermanentReplay` skips it and `PermanentReplayJournal.seed` independently refuses it. A successor design that depends on complete historical raw membership does not solve this case. Never label a seed of the surviving rows complete. Preserve all available predecessor evidence.

If product policy permits a separately versioned, authenticated namespace that guarantees refusal of old **proofs**, define the exact identity boundaries and the wording of that guarantee with #1059. A fresh prefix inside the existing random ID width cannot prove disjointness from unknown old raw IDs. If the requirement stays “refuse every pre-gap raw value,” keep the legacy migration guard until there is verified complete evidence. Document the format 19 fallback separately from supported succession.

### Review and evidence before implementation

Saturn should review raw ID and nonce reuse across scopes, predecessor corruption, missing history, stale routing, rollback, restart, and how the plan preserves already-committed effects. Measure admission and startup with both sets near the supported cap, including nonce-only lookup. Start with the permanent replay loss/restart fixtures in `CheckpointedJournalTests` and `ApprovalRequestCoordinatorTests`, and reuse the protected pairing replacement fixtures for enrollment and routing. Add a small signed test matrix for old-scope proofs and re-enveloped raw keys. Validate installed account transition separately.
