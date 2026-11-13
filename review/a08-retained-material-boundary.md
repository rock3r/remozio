# A08: proposed retained material write boundary

**Review only.** Base: `70e0d246`. No A08 code is implemented or approved.
This proposal extends the permitted stable writes to one retained account case.
The existing current-release entry must keep its origin restriction.

## 1. Why the flow needs a durable reference

In the private donor, `MachineUpdateRetainedSetupRuntimeSequence.swift:104–117` prepares material before it records the startup policy or publishes consumer files.
It requires a retained reference with `configurationPublished == false` before the policy step.
`MachineUpdateRetainedSetupRuntimeNative.swift:45` calls the material producer.
`MachineUpdateRetainedSetupMaterialPreparation.swift:135–157` restores or creates material, retains its reference, then rereads and compares the actual state.
The current writer and transition comparator reject retained accounts. The donor call therefore cannot be ported unchanged.
The proposed entry makes that identity durable for recovery. It does not report published files or running services.

## 2. Exact permitted change

Accept only a typed retained frame: the account has retained provenance, no inventory membership, prepared storage, complete initialization, and a complete service plan.
The archived completion intent must identify an unconfigured retained account. The foreground activation plan must be absent and its registered flag false.
The runtime configuration must remain unpublished.

Permit one `INSERT` into `runtime_preparation_v1` for that account, with `complete = 0`.
Bind the account, material ID, transport public key, material digest, and canonical reference bytes.
If the exact reference already exists, permit an unchanged result. Never replace it or mark it complete.
Keep uniqueness and capacity checks. Add no schema migration, update, delete, repair, or retry after an uncertain commit.

The private authorization must pin the actual frame, catalog, and every other row before and after the write.
Inventory, preparation, initialization, service claims, policies, activation, admission, import state, installed archives, and seal bytes must stay exact.
No account enrollment, publication acknowledgement, consumer publication, registration, or authority follows from this write.

## 3. Disjoint entries

Keep `retainStableRuntimeMaterial` and its current-release comparator closed to retained accounts.
The new entry must reject current-release accounts, including unenrolled ones.
Its typed frame must derive provenance from the actual archived completion intent. A caller cannot select an origin flag.
Use private authorization and fresh actual reads. Add no boolean bypass or relaxation of ordinary decoders.
This extension needs review before code. Any conflict with the sealed historical state remains a blocker for the lead to escalate.

## 4. Native proof remains separate

Owned tests can prove row isolation, stale refusal, rollback, callback lifetime, and ordinary UID refusal.
They do not prove protected file custody, installed code identity, hardware-backed keys, service identities, provider compatibility, or native startup.
Root checks must precede native access. Bepi will not execute privileged operations or access real secrets or signing identities.
Toni owns compilation, tests, publication, and merge. After A08, source work stops. A09 is outside this assignment.
