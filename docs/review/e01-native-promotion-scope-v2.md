# Native promotion scope design for E01 review v2

Draft for Toni and chiacchiersaturn. This revision implements Toni's design decision in message 1708.
It supersedes v1's unresolved concurrency choice and its machine-reader reopening sequence. The original v1 remains unchanged.

Hold one actual machine store across the publishing commit, file operations and final marker.
Its existing protected `writer.lock` is the common exclusive owner. Keep the connection open between transactions, without a long SQL transaction or drain.
Read fresh snapshots through that held store. G4 must never reopen it while the owner holds it.
Keep separate sealed scopes for read-only callback observation and file operations outside transactions.

No native implementation or execution is authorized by this document. Review the revised contract and W4 closure before coding the native adapter.

## Source and decision

The reviewed source is commit `65b912db7db6ed0e7876d80d33824232c79666d9`, tree `5e1399a0dc8da093ba217140ebeed65889df9678`.
V1 was published unchanged at `914b83c0b24d4dae9b9a580febf5855cb3c6963b`, document SHA256 `01f01b7e098ac1b70dfb0e91bdf22e7c4ad7f3a3d77996a63f07f04adeab786e`.
Review 1707 identified the existing store lock. Toni selected it in 1708.
Reconcile every call path against the eventual integration commit before implementation.

PreparationIntentStore acquires InstallationStorageLease when it opens. ProtectedStorageLease opens `writer.lock` and takes `LOCK_EX | LOCK_NB`.
It retains that descriptor until closure or invalidation. A second independent acquisition returns busy, including another acquisition in the same process.
The lock covers the whole machine store, so another account cannot bypass it through a different account ID.
Validate the protected lock file and directory identities throughout use. A path string alone is not ownership evidence.

Ordinary admission still uses a shared lock. ReleaseDestinationLease still pins ancestry without serializing publishers.
Their roles do not change. Do not upgrade them to drain or exclusive activity to obtain the publication lock.

## Closed writer inventory

Review 1707 traced these routes at the pinned source. This inventory must be reconciled after W4 closure and before native reachability.

| Route | Six-file responsibility | Protection and required lifetime |
| --- | --- | --- |
| W1 `prepareRuntime` | Transport, gateway host and three clients through RuntimePublicationController | Setup holds its machine store; publication creates with `RENAME_EXCL` and retains shared activity |
| W2 `activateRuntime` | Command host through RuntimeActivationFiles | Setup holds its machine store; publication creates with `RENAME_EXCL` |
| W3 audit upgrade | Command host, transport and gateway host | Expected bytes and inode; exclusive activity; machine store remains open |
| W4 MachineUpdateConfigurationFiles | Six-file replacement through `publishNative` and `publishInLease` | No production caller at this source; its unused native capability must be removed as proposed below |
| W5 machine update completion | Six-file replacement through `replaceMachineUpdateCompletion` | Drain and held machine store are required; no production caller at this source; every future caller must preserve the contract |
| W6 G7 | Six-file replacement and selected-file retention | Owned-only today; the future native adapter must require this held-store scope |

The promotion row has one private INSERT/UPDATE primitive, revision CAS and adjacent phase validation. The reviewed routes contain no promotion DELETE or DROP.
The settled-state gate blocks unrelated ordinary machine writes. Keep those checks; writer.lock does not replace them.
The reviewed six-file routes contain no deletion route. Any later deletion or replacement route must join this inventory.

Settings, import and backend paths must be classified by their actual file targets and machine-store acquisition, not their names.
Any path found to target one of these six files joins the invariant before it becomes reachable.
A native positive result cannot rely on an incomplete writer inventory.

## Required ownership invariant

Every production writer of these six files holds the same protected machine-store writer lease while it writes.
The native promotion owner keeps one machine connection from before its `.publishing` commit through file operations and the `.filesPublished` commit.
It also keeps that connection through the final checked read and before-return validation.

The outer provider owns the connection and closes it on every return. Borrowers never close it or release its lease.
An entry already inside Setup's `Machines.scoped` operation borrows that existing store. It must not acquire a second connection.
A standalone owner opens its single store once and retains it through the same bounded operation.
There is no gap where a per-step provider closes the store between the publishing commit and file operations.
The G8 provider contract must reflect this whole-operation lifetime. It must still reject double invocation, escaped bodies and an unclosed final connection.

Inside this lifetime, each G6 write or fresh read has its own short transaction.
All replacement, file fsync and parent fsync happen with machine-store autocommit restored and no active machine transaction.
Do not keep a read transaction open across file operations either.

Reject process, thread, store identity, lock identity, ownership and lifetime changes. A failure revokes its scope and stops the operation.
A closed or retired store cannot lend a valid scope even if a caller retains its object.
No operation body, unknown commit or uncertain swap is retried automatically. Existing bounded acquisition-only retries remain separate.

## Borrow G4 resources and the held machine reader

G4 retains its actual destination, ordinary admission owner and installed placement leases.
A sealed machine-lease facade lends bounded validation and synchronous operation entry. Its initializer remains in G4's implementation file.
It exposes no close, unlock, raw descriptor or replacement-lease constructor.
Keep machine-directory identity comparison, exact admission identity, placement validation and installed-copy identity checks.

G6 enters an admission operation through the existing owner once per store operation.
External G7 file work enters a separate admission operation after G6 returns.
Never nest `withMachineAdmission` scopes. Successive scopes reuse the held admission owner; they do not reopen its tokens.

Add a separate sealed held-machine read loan, issued by the actual PreparationIntentStore owner.
It binds that exact store, protected native location, lease, process, thread and enclosing lifetime.
It grants no native custody by itself. G4 still checks Root, fixed paths, executing code, signed release, owner, services, material and activity.
Owned Controls and caller-supplied snapshots or verification closures cannot construct NativeContext.

The native held-store G4 entry installs this loan before its first snapshot verification.
Outside a transaction, its fresh reader uses the held store's real snapshot and compatibility readers in successive short read transactions.
Directory lookup remains outside those transactions. The reader never closes the borrowed store.
It compares exact actual state before and after external evidence checks, as the existing G4 path does.

The existing `fresh()` and `readFresh()` path opens a new store and would return busy while writer.lock is held.
Do not use that path during the held operation. Do not catch busy and continue without the check.
Do not choose the borrowed path with a public Boolean or an arbitrary callback.
The held-store entry requires the sealed loan and validates its fixed native store identity before G4 issues custody proof.

## Actual frames inside G6

The long-lived held-machine reader is distinct from G6's transaction-bound frame loan.
The latter continues to read `authorization.capture(in: self)` while the writer transaction is active.
It preserves producer preflight, actual writer identity, admission, catalog, other-account digest and transition checks.
Do not extend its transaction-only authorization into the external file phase.

Extend the private G6 loan to compare the actual full promotion snapshot and callback stage, not completion alone.
Its constructor stays private to PreparationIntentStore. Bind it to the same store as the held-machine loan.
G4 uses that transaction loan during callbacks, rather than its outside-transaction reader.
Never call a public transaction-opening snapshot reader from an active callback transaction.

| Stage | Actual frame | Permissions |
| --- | --- | --- |
| `beforeTransaction` | Current row in G6's initial read transaction | Observation only |
| `inTransaction` | Current row before mutation | Observation only |
| `afterMutation` | Newly adopted row, revision and digest | Observation only |
| `afterCommit` | Committed row in G6's final read transaction | Observation only |

The callback's NativePairScope is created inside G6's existing G3 pair callback, after the complete boundary and recorded classification pass.
Do not open a second journal/continuity pair while that callback holds the first pair's leases.
Pass the scope with the same actual full frame. Expire both the pair scope and frame loan before returning from the callback.
Never capture the initial publishing frame for all later stages.

Keep G4's current approval rules, including only the already admitted metadata changes. No 27-to-28 admission is added.
Keep exact policy, completion and promotion row comparisons. G4 custody alone cannot authorize a G6 write.

## Distinct NativePairScope permissions

Only actual G4 custody plus a checked G3 read-only pair can construct the sealed NativePairScope.
It binds the candidate, account, initialization, complete boundary, recorded classification, exact publication and applicable actual machine frame.
It expires with its enclosing callbacks. Reject fork, cross-thread use, reentry, owner closure and failed verification.

The callback form can create Observation only. It exposes no replacement or retained-file synchronization operation.
The external publishing form requires a fresh exact durable `.publishing` row through the held-store reader, outside all machine transactions.
Use distinct sealed types. A caller-controlled mode flag cannot turn Observation into publication authority.

Compare the complete expected and actual promotion snapshots, record ID, revision, phase and publication bytes.
Check the publication source binding and recorded pair. ID, phase or digest alone is insufficient.
Expected operands are comparison inputs, not a claim that their values came from the database.

G7's owned helpers retain their Root refusal. Add a separate native adapter only after this contract passes review.
It must use fixed native directories, existing Root metadata checks, expected bytes, directory identities and the required `retainSelected` operation.

## Publication sequence with one held store

1. Borrow or acquire the single machine store under the outer owner. Establish its sealed read loan and G4 custody scope.
2. Run G6 to retain the exact `.publishing` row. Check its commit and final frame before file work. An uncertain result stops.
3. Leave every machine transaction and G6 pair callback. Through the held store, read a fresh full promotion snapshot in a short read transaction, then finish that transaction.
4. Open the external G3 read-only pair and create the publishing scope. Observe all six protected files before replacement.
5. Before each replacement, repeat the full durable publishing comparison through the held-store loan. Complete each read transaction before the file operation. Revalidate G4/G3 evidence and exact protected source bytes.
6. Replace through the existing guarded primitive, read back exact selected bytes and repeat the checks. Any uncertain result stops the call.
7. Confirm every selected file through `retainSelected`: exact bytes and metadata, file fsync, parent fsync and exact read-back. Never exchange an already selected file.
8. Read all six selected files again. Revoke the external publishing scope and close its G3 pair before G6's next pair callback. Keep the machine store and writer.lock held.
9. Request the adjacent `.filesPublished` transition through G6. Its new callback Observation uses each actual full writer frame. It performs no replacement or fsync inside SQL.
10. Check the final committed frame and files under the held owner. Expire all loans, close the connection and return only through the checked outer provider.

Steps 3 and 5 use no `open()` or G4 `fresh()`. A fresh read means new actual state from the held store, not a new connection.
The marker cannot reuse an expired external publishing scope.
An existing `.publishing` row may resume only with a new checked scope and its exact retained operands.
Unknown bytes, changed identities or lost custody refuse without repair. A `.filesPublished` row grants no further replacement.

## Why the interleavings are excluded

While the operation holds the protected writer.lock, a second independent machine-store acquisition cannot succeed.
This excludes another Setup process and same-process independent acquisition, including another account's writer.
W1 and W2 additionally cannot replace an existing target. W3's exclusive activity and W5's drain add their existing exclusions.
The revision CAS and expected-byte swap remain required defenses. No file or SQL check is removed because the lock exists.

The lock proof depends on closing W4's unused native route and retaining the store across every native file callback.
It does not depend on Mach service listener uniqueness or on a process-local mutex.
Uncooperative privileged code outside the closed application writer inventory is not controlled by a cooperative writer lock.
Keep protected ownership and identity validation; do not claim writer.lock defeats arbitrary Root modification.

## Proposed small W4 closure slice

Remove the unused `MachineUpdateConfigurationFiles.publishNative` mutation entry.
Keep `publishInLease` for the existing owned fixtures, with an early ordinary-owner guard: nonzero matching real and effective UIDs.
Reject Root before verification, archive work or file access. Keep all existing compare-and-swap and fault behavior for ordinary owners.
Leave read-only `requirePublishedNative` unchanged. No new native replacement route or store opener is needed.

At the pinned source, an independent scan found three qualified calls to `publishInLease`, all in MachineUpdateReplacementTests, and no call to `publishNative`.
Recheck the entire call graph before removal, including aliases and unqualified references. This proposal is not an applied change.
Measure the complete production delta against the 240-line cap before adding tests. Do not compress guards to meet it.

Add an owned regression that passes owner zero and observes refusal before verification or publication callbacks.
That ordinary-process control does not prove execution of a native Root path or isolate every underlying ownership guard.
Keep the existing owned replacement positive control and its swap/read-back cases.
Add an owned-store lifetime test: a second independent lease acquisition returns busy before, during and after file publication while the first store remains open.
After the first owner closes, acquisition must succeed. Use the existing subprocess lock test support for a separate-process control where available.
Do not use an inherited duplicate descriptor as evidence of independent acquisition.

The future native owner test must also prove that no close occurs between publishing and marker, and that an escaped loan fails after close.
W4 removal does not substitute for those owner tests or for the closed writer inventory.

## Validation and remaining unknowns

Required tests cover sealed construction, scope expiry, cross-thread/fork/reentry refusal, lease identity loss and borrowed-owner closure.
They must prove that every G6 stage uses its actual full frame and opens no nested machine reader.
Outside SQL, prove a fresh durable read uses the held connection and that every file operation sees autocommit restored.
Test stale row ID/revision/phase/bytes, changed pair or candidate, mixed recovery, read-back failure and retention failure.
Exercise competing processes and the whole-operation store lifetime. Keep the existing phase CAS, protected digest and catalog regressions.

Unknown: whether a second NSXPCListener on the same MachService fails or stays silent. The writer.lock proof must cover both outcomes.
Unknown: the future production caller of W5. It must enter the held-store invariant before it becomes reachable.
W4 closure, the revised G4 reader, the owner lifetime and native integration remain unimplemented and untested here.

G7's owned recovery test proves separate retention and unchanged inode. Cleanup may already have synchronized the parent; it does not isolate every earlier fsync failure.
Actual producer evidence, the complete native positive path and canonical acceptance above the ordinary SQLite record limit remain separate E01/C06 obligations.
This note covers promotion ownership. The PLAN's retained-enrollment inventory projection still needs its own accepted-image design before that separate E01 implementation.

Review must approve this v2, its held-reader construction and the W4 closure proposal before native code starts.
Toni retains all build, test, publication and merge ownership. This document changes no code, schema, declaration or product entry point.
