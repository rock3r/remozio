# Shared re-pair plan · 3b Mac and 3c Android

[Issue #840 plan request](https://github.com/rock3r/remozio/issues/840#issuecomment-7095643580) · [Part 3a](https://github.com/rock3r/remozio/pull/899)

Source reviewed at part 3a commit `251a3d065d22a65a90d9f7f8282e80eb7f0ccb54`. Part 3a checks the revoked predecessor at staging and again at checkpointed commit. The phone currently sends an ordinary proposal before saving an enrollment. Its PREPARED record requires the returned transcript, and its replacement path assumes that the predecessor is locally active. This is a review plan. The baseline entries describe proposed witnesses and source observations.

## Part 3b · Mac invitation and pairing sheet

- Add **Re-pair** to **Paired phones** for eligible retained rows. Resolve the exact Mac ID, account ID, phone ID, and old epoch against the current Root projection through the existing authenticated local channel. Refuse active, missing, stale, or restricted selections and a phone ID with another active epoch. A locally revoked row remains eligible while gateway delivery is pending. Recheck eligibility at export so a stale row selection cannot create a re-pair session.
- For QR and text, wrap the canonical ordinary invitation and the predecessor tuple in a bounded, versioned envelope. Reject malformed, noncanonical, unsupported, and cross-scope inputs. Reuse the existing out-of-band channel. Keep the ordinary invitation byte-compatible and the existing setup exchange. The envelope is unsigned and carries selection data only.
- The Mac session stores the selected predecessor from its own local selection. In re-pair mode it accepts only version 2 candidates naming that predecessor and offering a different epoch for the same phone ID. Reject ordinary proposals and proposals naming another row before staging. Recheck the selection when the returned transcript arrives. Identify the phone and the re-pair action in the pairing sheet before confirmation. Preserve the existing administrator authorization, human comparison, proof, commit, and receipt steps. An ordinary session continues to pair with a normal version 1 invitation.
- Test the complete Mac path with a synthetic phone peer that understands the envelope and sends a version 2 proposal. Part 3b can ship without changing a phone app or enabling its Re-pair action.

### Why the envelope can remain unsigned

The phone keeps the authority and transport pins from its retained enrollment. An imported envelope must match those pins and the exact local tuple. The pins authenticate the Mac setup channel and the commit receipt, respectively. A changed pin, foreign scope, or unknown tuple fails on the phone.

A modified tuple that happens to match another retained row can put the phone on the wrong setup attempt. The Mac checks the tuple against its independent local selection and refuses the proposal. Root also checks revocation at staging and commit. The user must compare the transcript on both devices, and the phone can activate and retire rows only after verifying the Root receipt for that transcript. A stale or changed envelope can therefore interrupt setup without creating authority or retiring a local row. The initial phone UI can offer the guarded re-pair attempt, while only the Mac's checked setup exchange establishes eligibility to continue. The live setup deadline and transcript checks provide the freshness bound.

### Part 3b files and witnesses

Planned files:

- Add `RePairInvitation.swift` and `RePairInvitation.kt` beside the existing protocol invitation codecs, shared vectors, and Swift and Kotlin pairing setup test coverage.
- Update `macos/core/Sources/RemozioCore/PairedPhoneManagement.swift`, `AuthorityPairingSetup.swift`, `AuthorityPairingXPCEndpoint.swift`, `AuthorityPairingChannel.swift`, and `MacPairingSession.swift` for the eligible-row projection and session mode. Update `macos/app/App/PairingSheet.swift` and `macos/app/App/en.lproj/Localizable.strings`.
- Update `protocol/pairing-setup.md` and the synthetic Mac/JVM setup peer fixtures for the new invitation mode.

Run these baseline witnesses after part 3a merges:

| Candidate test | Baseline witness |
| --- | --- |
| Swift and Kotlin decode and re-encode the same envelope bytes. Reject malformed tuples, Mac/account mismatch, an unknown version, and oversized input. Verify ordinary invitation compatibility. Use the existing `PairingSetupTests` and `PairingSetupTest`. | Feed the new envelope to the existing invitation import path. Only the ordinary invitation is understood. Verify that the existing ordinary vectors still pass. |
| Export the chosen revoked epoch. Refuse active, missing, stale, restricted, and duplicate-active selection. Allow a locally revoked row with pending gateway delivery. Extend `AuthorityPairingSetupTests.swift`. | The current Paired phones list projects active rows. Its status read can describe a known revoked epoch, but the app can only export an ordinary invitation. |
| Bind the session to one selected predecessor. Refuse an ordinary proposal and a proposal for a different revoked predecessor. Complete the matching proposal through comparison and receipt. Keep the ordinary pairing case. Extend `MacPairingSessionTests.swift`, the Mac sheet presentation checks, and synthetic `PairingSetupInteropTest.kt`. | Feed two different valid version 2 candidates to a part 3a setup fixture. Root can check whether either row is revoked, while the Mac session has no export-selected predecessor or re-pair presentation to enforce. Confirm the ordinary path still works. |

## Part 3c · Android persistence, recovery, and retirement

### Preflight and durable setup

1. Offer **Re-pair** only when the imported envelope, both existing pins, and the full predecessor tuple match one retained local enrollment. The row may still be locally active or already marked REMOVED. Local removal and transport failures supply no revocation signal. A mismatch stops this attempt. Ordinary pairing remains a separate explicit action that generates a new phone ID.
2. Bind the attempt to the predecessor record ID and archive revision. Keep its phone ID and allocate a fresh record ID, epoch, and three hardware key references. Never copy relay credentials or old keys. Persist a PREPARED re-pair entry in the encrypted archive before the channel writes the canonical version 2 proposal. Retain the chosen predecessor, parsed invitation, exact proposal, and key references. Model the pre-transcript state explicitly and keep it outside active use, signing, and receipt lookup. Preserve legacy ordinary records. A reader that cannot parse the new pending format must refuse it without replacing the archive.
3. Validate the returned transcript against the stored proposal, pins, predecessor, and policy. Save it to the same PREPARED entry before comparison and proof. Persist a proof-may-have-been-sent marker before the first proof write. Failure to confirm a durable write stops network output. Only clean up unreferenced keys owned by the failed attempt.
4. After restart, allow cancellation of an entry that cannot have sent proof. A new explicit attempt allocates fresh keys. Once proof might have been sent, recover only the receipt for the saved setup ID and digest over the authenticated new transport binding. Missing, ambiguous, or mismatched receipts preserve PREPARED and its keys. Never replay the setup write or biometric proof. Setup expiry does not discard a receipt lookup.

### Activation and local removal

Verify the Root commit receipt for the exact saved transcript. In one archive write, check the revision, the matching PREPARED entry, the exact predecessor, and the absence of a conflicting active row. Activate the new entry and retire only the pinned predecessor. An already-REMOVED predecessor is acceptable if the retained row still matches. Repeating a successful recovery returns the current result. A stale or changed row leaves the archive unchanged.

After the commit, invalidate affected enrollment owners and retire only unreferenced aliases. Reconcile from the archive after interruption. Keep Root's old-epoch evidence and existing gateway projection. Label the local removal action **Remove from this phone** and explain that revocation happens in **Paired phones** on the Mac. Apply removal to the selected record ID and revision, with no revocation request or effect on other rows.

### Part 3c files and witnesses

Planned files:

- Shared archive under `phone/enrollment/src/commonMain/kotlin/dev/remozio/phone/enrollment/` includes `PhoneEnrollment.kt`, `EncryptedEnrollmentStore.kt`, and `PhonePairingAttempt.kt`. Add the pre-send checkpoint to `phone/pairing/src/commonMain/kotlin/dev/remozio/pairing/PairingSetupChannel.kt`.
- Android under `android/app/src/main/kotlin/dev/sebastiano/remozio/android/enrollment/` includes `AndroidPairingAttempt.kt`, `StoredPairingHost.kt`, `PairingReceiptRecovery.kt`, `PairingViewModel.kt`, `PairingSetupSheet.kt`, `StoredMacInventory.kt`, and `StoredMacList.kt`. Update `android/app/src/main/res/values/strings.xml` and reuse the receipt wire and hardware key owners.
- Update the shared and native test fixtures below. On iOS, `NativePhoneServices.swift` and `PairingNetwork.swift` currently supply the shared connection preview. That preview saves nothing and closes before proof. Exercise shared codecs and persistence where applicable. Keep the iOS feature disabled until a durable enrollment owner supports proof and receipt recovery.

Run these baseline witnesses after part 3b merges:

| Candidate test | Baseline witness |
| --- | --- |
| Offer re-pair for one exact active or retained REMOVED local row when tuple and pins match. Refuse a changed or unknown tuple and changed pins. Confirm that **Remove from this phone** acts on the selected row only. Extend `StoredMacInventoryTest.kt` and Android UI tests. | The existing phone path cannot consume the re-pair envelope. It generates a new phone ID, rejects an already-enrolled Mac, and hides removed rows. Local removal is an archive operation with no re-pair action. |
| Inject archive failure and restart before proposal. Confirm zero proposal writes until PREPARED is durable. Recover the same record ID and key references. Extend `StoredPairingHostTest.kt`, `EnrollmentStoreOwnershipTest.kt`, and `PairingSetupChannelCommonTest.kt`. | The current owner sends the proposal in connect and saves PREPARED only after receiving the transcript and confirming comparison. |
| Refuse a transcript that differs from the retained proposal. Restart across the proof marker and perform receipt lookup without replay. Extend the Android pairing owner test coverage and `PairingReceiptChannelTest.kt`. | Existing recovery avoids replay for a retained prepared transcript. The current proof-submission flag is in memory, and the archive cannot distinguish the pre-proposal and possibly-submitted states. |
| Recover a matching receipt exactly once. Preserve PREPARED on missing or wrong receipt. Admit an already-removed exact predecessor, refuse stale and unrelated rows, and retain referenced aliases. Extend `PhonePairingAttemptTest.kt`, `EncryptedEnrollmentStoreTest.kt`, and `StoredPairingHostTest.kt`. | The current activation path expects the replacement pointer to name the one locally active row. A retained REMOVED predecessor does not satisfy that rule. |
| Exercise a real version 2 proposal with synthetic peers, drop the immediate receipt after commit, reopen the phone archive, and recover using the new key. Observe one commit and one retirement. Extend `PairingSetupInteropTest.kt` and `AuthorityPairingReceiptTests.swift`. | Part 3a proves the immediate version 2 exchange and Root commit. Part 3b adds a Mac session with a synthetic client. Neither path recovers from a persisted phone archive after restart. |

Use test-only fixtures for each baseline. When a proposed API is absent on the baseline, record the observable boundary through the existing path. Keep baseline and candidate evidence separate. For each PR, reconcile main after its prerequisite merges and send the compiled selection, baseline witness, and updated forecast before the gate. Part 3b covers shared Swift/Kotlin vectors, Mac Core and app builds, Linux protocol checks, and synthetic interop. Part 3c adds phone archive, Android owner and UI coverage, and restart recovery interop. Installed Mac administrator consent, hardware keys, QR and text import, and real gateway delivery remain attended checks.

Issues #831, #834 and #898 stay outside both slices. Preserve the part 3a gateway control ordering and the physical-device qualification boundary.
