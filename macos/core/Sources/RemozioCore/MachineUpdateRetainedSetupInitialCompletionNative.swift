import Darwin
import Foundation

/// Uses the retained completion writer. It observes exact files and never publishes, repairs or registers a job.
enum MachineUpdateRetainedSetupInitialCompletionNative {
    typealias Native = MachineUpdateRetainedSetupRuntimeNativeContext
    typealias Authority = MachineUpdateRetainedSetupRuntimeNativeAuthority
    typealias Files = MachineUpdateRetainedSetupRuntimeNativeFiles
    typealias Completion = MachineUpdateRetainedSetupInitialCompletion
    typealias Observer = MachineUpdateRetainedSetupInitialObservation
    typealias Snapshot = MachineUpdateRetainedSetupPolicySnapshot
    typealias Boundary = AuthorityJournal.MachineUpdatePolicyBoundary
    struct Callbacks {
        let verifyCurrent: (Snapshot) throws -> Void
        let verifyServices: (ServiceAccountPlan) throws -> Void
        let readMaterial: (Observer.Scope) throws -> RuntimePreparationMaterial
        let verifyActivity: (ServiceReleaseActivityReference, Observer.Scope) throws -> Void
        let readArtifact: (Observer.Artifact, Observer.Scope) throws -> Data?
        let didStorageStage: (PreparationIntentStore.CompletionIntentStorageStage, Completion.Scope) throws -> Void
    }
    static func complete(context: Native.NativeContext, authority: Authority.HeldScope, expected: Snapshot,
        candidate: SignedReleaseEvidence, verifyCurrent: @escaping (Snapshot) throws -> Void) throws -> Snapshot {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try context.verification.verifyPublication(expected)
        let entry = try Native.Entry(runtime: expected.activation.runtime, activation: expected.activation.state,
            intent: expected.intent, candidate: candidate)
        return try context.withResources { directory, admission in
            try Authority.withTargetPair(scope: authority, expected: entry) { read in
                try context.withMachine(expected: entry, opening: .mutable) { machine in
                    try withD2(machine: machine, expected: expected, candidate: candidate, directory: directory,
                        admission: admission, readPolicyBoundary: read,
                        callbacks: callbacks(context: context, expected: expected, verifyCurrent: verifyCurrent))
                }
            }
        }
    }
    /// Owned controls exercise the same retained owner. They cannot supply native custody or approval.
    static func withD2(machine: PreparationIntentStore, expected: Snapshot, candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease,
        readPolicyBoundary: @escaping () throws -> Boundary, callbacks: Callbacks) throws -> Snapshot {
        try Completion.complete(machine: machine, expected: expected, candidate: candidate, directory: directory,
            admission: admission, fileCustodyAccepted: true, readPolicyBoundary: readPolicyBoundary,
            verifyCurrent: callbacks.verifyCurrent, verifyServices: callbacks.verifyServices,
            readMaterial: callbacks.readMaterial, verifyActivity: callbacks.verifyActivity,
            readArtifact: callbacks.readArtifact, didStorageStage: callbacks.didStorageStage)
    }
    private static func verify(_ scope: Observer.Scope, context: Native.NativeContext) throws {
        try scope.requireActive(); try context.verification.verifyPublication(scope.snapshot)
        try context.withResources { _, _ in }; try scope.requireActive()
    }
    private static func callbacks(context: Native.NativeContext, expected: Snapshot,
        verifyCurrent: @escaping (Snapshot) throws -> Void) -> Callbacks {
        Callbacks(verifyCurrent: { actual in
            try context.verification.verifyPublication(actual); try verifyCurrent(actual)
        }, verifyServices: { plan in
            guard plan == expected.activation.runtime.plan else { throw RuntimePreparationError.changedScope }
            try context.withResources { _, _ in }
        }, readMaterial: { scope in
            try scope.withActive {
                try Files.readMaterial(runtime: scope.snapshot.activation.runtime,
                    verifyCurrent: { try verify(scope, context: context) })
            }
        }, verifyActivity: { activity, scope in
            try scope.withActive {
                try Files.verifyActivity(activity, runtime: scope.snapshot.activation.runtime,
                    verifyCurrent: { try verify(scope, context: context) })
            }
        }, readArtifact: { artifact, scope in
            try scope.withActive {
                guard let material = scope.material, let bundle = scope.bundle else { throw RuntimePreparationError.incomplete }
                return try Files.readArtifact(artifact, bundle: bundle, material: material,
                    runtime: scope.snapshot.activation.runtime, verifyCurrent: { try verify(scope, context: context) })
            }
        }, didStorageStage: { _, scope in
            try scope.requireActive(); let actual = try scope.read()
            try context.verification.verifyPublication(actual.snapshot); try scope.requireActive()
        })
    }
}
