# Pairing lifecycle

Source review on main `2d2b1fb6839801b0ad47dd43eb87a2be228acc57`. This plan covers #831, #840, #851 and #834. The source findings below need tests on the implementation commits.

## #851 — Keep revocation available when push delivery is full

`GatewayAuthorityJournal.capacity()` counts push delivery rows alongside revocations, recovered revocations and trust restrictions. `JournalDatabase.revokeApprovalEnrollment` changes enrollment, writes the signed gateway control and appends the audit event in one transaction. If the gateway insert fails for lack of capacity, SQLite rolls back the removal.

Give trust controls capacity that push delivery cannot consume. Reserve enough protected capacity to revoke admitted enrollments. Plan how to retain verified evidence for recovered epochs and trust restrictions. Base any retention or bounded compaction on checkpoint and reconciliation rules. Preserve the highest applicable restriction and the evidence required to check it after restore. Apply the storage change to existing databases, including those already at the old limit. Keep revocation, audit and pending gateway delivery atomic. Preserve the existing signed control and replay rules.

**Platforms.** Mac Authority storage and its gateway delivery owner. The gateway consumes the existing signed revocation. Android has no new contract in this change.

**Tests.** Fill the push budget in local journal fixtures. Verify that live and recovered revocations and trust restrictions can still commit. Cover migration from a full database, signed controls, wrong scope, stale revision, duplicate evidence, rollback on actual write failure, restart, and delayed gateway delivery. Verify that an old delivery cannot reactivate a revoked epoch.

## #840 — Give the Mac owner a reachable revocation and re-pair flow

The active Mac pairing exchange reaches `AuthorityPairingSetup`, which rejects replacement. `PairingEnrollmentAttempt` has a replacement branch but the current pairing exchange does not select it. Android `StoredPairingHost.remove` removes the local row. It makes no remote revocation claim. `AndroidPairingAttempt` also refuses a new active pairing for the same Mac and account.

Add an account-scoped Mac action to revoke a specific phone, including a lost or offline phone. Recheck authenticated administrator authorization and the current enrollment revision at commit. Use the durable Authority transaction and audit checkpoint. Close the old enrollment's live sessions and admission at the documented commit boundary. Cover LAN and relay traffic, pending approvals, snapshots, routing, audit sync and push. Report local revocation and gateway delivery separately.

Use the existing restricted pairing invitation, comparison and receipt for re-pairing. Start re-pairing only after the owner revokes the old enrollment. If the old transport or approval key is unavailable, use the authenticated Mac flow and the new phone's pairing proof. Give the phone a fresh epoch and key references. Bind local cleanup to the exact old or pending row, and close affected Android leases before changing active state. Preserve `PREPARED` across an ambiguous receipt and recover it through the existing checked path. Clearly label local removal. An eventual phone-initiated revocation would need its own authorized, scope-bound request and confirmation of durable Mac revocation.

**Platforms.** Mac app, Authority and enrolled transport. Android setup, enrollment store and UI. Gateway delivery reuses the existing control, and must retire old mappings for the exact epoch.

**Tests.** Revoke a lost phone with no phone response. Check wrong caller, wrong account, stale revision, repeat requests and already-open sessions. Verify that reconnects with the old epoch cannot read commands, submit decisions or change routing. Cover phone removal while offline, re-pair on the same phone, new keys, cancellation, lost receipt, restart, stale token callbacks, and gateway delivery retry.

## #831 — Recover from transport certificate expiration

`AndroidPairingAttempt` creates a one-year certificate. On expiry, `AndroidTransportIdentities.load`, `ClientTLSKeyManager` and Mac `PinnedTLSPeer` prevent its use. The app collapses the failure into a connection error and offers no renewal path.

Show a dated renewal prompt before expiry and a specific recovery action afterward. Renew the enrollment through the #840 re-pair flow. The restricted pairing listener accepts the new setup identity after the user authenticates the invitation. It does not need a working session on the expired identity. Keep certificate expiry checks and retire the old session at the authorized enrollment transition. Plan a separate provider and protocol review if same-key renewal becomes a requirement. The current loader is read-only, and support for replacing the stored certificate while keeping hardware custody is unverified.

**Platforms.** Android clock, identity loader, enrollment and UI. Mac pairing and enrolled transport. Gateway routing and push move to the newly committed epoch through the existing enrollment contract.

**Tests.** Inject time around expiry in Android and Kotlin TLS tests, including a certificate that has already expired. Cover a valid certificate with the wrong key, clock skew, process restart, the Android renewal message and accessible action, and re-pair from an expired credential. Verify the old epoch cannot resume and a valid replacement can reconnect.

## #834 — Invalidate the approval key when biometrics change

`AndroidBiometricKeyCreation` requests biometric retention. The inspection and request-specific signer initialize a signing operation, so permanent invalidation can surface in either path. The owner decided that keys must be invalidated when new biometrics are enrolled. The key continues to require hardware-enforced strong biometric authentication at every use.

Set `setInvalidatedByBiometricEnrollment(true)`. Translate `KeyPermanentlyInvalidatedException` at key load and signing preparation into a distinct pairing state. Preserve distinctions for user cancellation, temporary lockout, missing hardware and ordinary connection failure. Stop the affected approval flow immediately, withdraw failed prompt state, and lead the user into the #840 re-pair flow. Keep the old reference until the durable transition or explicit removal. Never generate a replacement on a failed approval.

Show the Mac that the specific enrollment needs re-pairing. Accept an authenticated, enrollment-scoped transition over a still-live enrolled channel or use the local administrator flow if that channel is unavailable. A signal can restrict only the sender's enrollment and cannot create trust. The Mac must show an explicit action once it has verified evidence. It cannot infer biometric changes from a connection failure.

**Migration proposal.** Record the key policy revision on newly enrolled rows and treat existing rows without that evidence as legacy. On the first upgraded approval use, require explicit re-pair for each affected Mac before signing. Do not attempt to change a Keystore key in place or infer its policy from a successful operation. Preserve pairing metadata and allow the re-pair action while approval is blocked. The user must complete the fresh biometric check for each pairing. Review this cutoff with the owner before implementation.

**Platforms.** Android Keystore, enrollment storage and approval UI. Mac pairing and phone status. Gateway observes normal revocation and fresh enrollment. It does not receive biometric details.

**Tests.** Inject permanent invalidation during inspection and signing. Verify the distinct Android message, re-pair action and absence of a signature. Test stale and forged status, exact Mac/account/epoch binding, legacy upgrade, failed migration and restart. Follow with attended Pixel and Mac checks for adding a fingerprint or face, re-enrollment, key invalidation and working re-pair. JVM fixtures cannot prove the provider behavior.

**Documentation.** Update `docs/android-biometric-keys.md` to describe the policy and recovery. Record the owner decision, threat, re-pair cost, migration and rejected retention alternative in `docs/design-decisions.md`. Update user help and localized Android and Mac strings. Suggested Android text below.

> Approvals stopped because your phone’s fingerprint or face settings changed. This protects your Macs from approvals using a newly added biometric. Pair this phone again with each Mac to restore approvals.

## Pull request order

| PR | Behavior | Depends on |
| --- | --- | --- |
| 1 | #851 protects trust controls and migrates existing journals. | Current main |
| 2 | #840 gives the Mac owner durable phone revocation and closes live admission. | PR 1 |
| 3 | #840 adds the shared re-pair flow and clarifies local removal. | PR 2 |
| 4 | #831 adds expiry detection and guided renewal through re-pairing. | PR 3 |
| 5 | #834 ships invalidation, the legacy migration and status, re-pair UX and documentation together. | PR 3 |

PRs 4 and 5 share the re-pair entry point. Reconcile their diff and tests against actual main before each gate. Keep exact source, selector inventory and test cap in each pre-gate handoff. For wire changes, qualify the Swift and Kotlin formats and the paired end-to-end path before a push. Installed service and biometric behavior require attended validation.
