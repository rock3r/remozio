import Darwin
import Foundation

/// Reuses the material owner within actual authority and custody loans. It adds no caller or repair path.
enum MachineUpdateRetainedSetupRuntimeNativeMaterial {
    typealias Native = MachineUpdateRetainedSetupRuntimeNativeContext
    typealias Snapshot = MachineUpdateRetainedSetupMaterialSnapshot
    typealias Verify = () throws -> Void
    static func prepare(context: Native.NativeContext, authority: MachineUpdateRetainedSetupRuntimeNativeAuthority.HeldScope,
        expected: Snapshot, candidate: SignedReleaseEvidence,
        verifyCurrent: @escaping (Snapshot) throws -> Void) throws -> RuntimePreparationState {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try context.verification.verifyMaterial(expected)
        return try context.withResources { directory, admission in
            try authority.withCurrentCodePolicy { policy in
                func custody() throws { try context.withResources { _, _ in } }
                return try withMachine(expected: expected, candidate: candidate, verifyCustody: custody, openMachine: {
                    let machine = try PreparationIntentStore(lease: InstallationStorageLease.acquire(directoryPath: MachineBootstrap.machineDirectory),
                        macID: expected.runtime.preparation.macID, maximumRecords: 64, initialize: false, opening: .retainedPolicyVerification)
                    do { try machine.validateStorageLease(nativeDirectory: MachineBootstrap.machineDirectory); return machine }
                    catch { try? machine.close(); throw error }
                }) { machine in
                    try MachineUpdateRetainedSetupMaterialPreparation.prepareNative(machine: machine, expected: expected,
                        candidate: candidate, currentCodePolicy: policy, directory: directory, admission: admission,
                        fileCustodyAccepted: true, verifyCurrent: { actual in
                            try context.verification.verifyMaterial(actual); try verifyCurrent(actual)
                        }, verifyFileCustody: custody)
                }
            }
        }
    }
    /// Owned tests can lend an actual machine. They cannot construct a native context or held authority scope.
    static func withMachine(expected: Snapshot, candidate: SignedReleaseEvidence, verifyCustody: Verify,
        openMachine: () throws -> PreparationIntentStore,
        prepare: (PreparationIntentStore) throws -> RuntimePreparationState) throws -> RuntimePreparationState {
        try verifyCustody()
        let machine = try openMachine()
        do {
            try machine.validateStorageLease(); try expected.requireCurrent(machine: machine, candidate: candidate)
            let result = try prepare(machine)
            try verifyCustody()
            guard !result.configurationPublished, let reference = result.reference else { throw RuntimePreparationError.changedScope }
            try expected.requireReference(reference)
            try machine.close(); return result
        } catch { try? machine.close(); throw error }
    }
}
