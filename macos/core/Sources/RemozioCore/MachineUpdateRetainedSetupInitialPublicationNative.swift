import Darwin
import Foundation

/// Publishes the eight fixed initial files. Completion, import ACK and job registration remain separate owners.
enum MachineUpdateRetainedSetupInitialPublicationNative {
    typealias Native = MachineUpdateRetainedSetupRuntimeNativeContext
    typealias Authority = MachineUpdateRetainedSetupRuntimeNativeAuthority
    typealias Files = MachineUpdateRetainedSetupRuntimeNativeFiles
    typealias Publication = MachineUpdateRetainedSetupInitialPublication
    typealias Snapshot = MachineUpdateRetainedSetupPolicySnapshot
    typealias Selection = MachineUpdateRetainedSetupInitialSelection
    typealias Boundary = AuthorityJournal.MachineUpdatePolicyBoundary
    struct Callbacks {
        let verifyCurrent: (Snapshot) throws -> Void
        let verifyServices: (ServiceAccountPlan) throws -> Void
        let readMaterial: (Publication.Scope) throws -> RuntimePreparationMaterial
        let verifyActivity: (ServiceReleaseActivityReference, Publication.Scope) throws -> Void
        let readArtifact: (RuntimePublishedArtifactValidation.Artifact, Publication.Scope) throws -> Data?
        let publish: (Publication.Scope) throws -> Void
    }
    static func prepare(context: Native.NativeContext, authority: Authority.HeldScope, expected: Snapshot,
        candidate: SignedReleaseEvidence, verifyCurrent: @escaping (Snapshot) throws -> Void) throws -> Selection {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try context.verification.verifyPolicy(expected)
        let entry = try Native.Entry(runtime: expected.activation.runtime, activation: expected.activation.state,
            intent: expected.intent, candidate: candidate)
        return try context.withResources { directory, admission in
            try Authority.withTargetPair(scope: authority, expected: entry) { read in
                try context.withMachine(expected: entry, opening: .retainedPolicyVerification) { machine in
                    try withC2(machine: machine, expected: expected, candidate: candidate, directory: directory,
                        admission: admission, readPolicyBoundary: read,
                        callbacks: callbacks(context: context, expected: expected, verifyCurrent: verifyCurrent))
                }
            }
        }
    }
    /// Shares C1 and C2 orchestration with owned controls. These controls grant no native custody or code approval.
    static func withC2(machine: PreparationIntentStore, expected: Snapshot, candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease,
        readPolicyBoundary: @escaping () throws -> Boundary, callbacks: Callbacks) throws -> Selection {
        guard let record = expected.intent, record.phase == .recorded else { throw RuntimeActivationError.incomplete }
        let startup = try AuthorityCodePolicy.decode(record.startupPolicy)
        return try Publication.prepare(withSelection: { body in
            try Selection.withCurrent(machine: machine, expected: expected, candidate: candidate,
                recordedStartupPolicy: startup, readPolicyBoundary: readPolicyBoundary,
                verifyCurrent: callbacks.verifyCurrent, body: body)
        }, machine: machine, expected: expected, candidate: candidate, directory: directory, admission: admission,
            fileCustodyAccepted: true, verifyCurrent: callbacks.verifyCurrent, verifyServices: callbacks.verifyServices,
            readMaterial: callbacks.readMaterial, verifyActivity: callbacks.verifyActivity,
            readArtifact: callbacks.readArtifact, publish: callbacks.publish)
    }
    private static func verify(_ scope: Publication.Scope, context: Native.NativeContext, expected: Snapshot) throws {
        try scope.requireActive(); try context.verification.verifyPolicy(expected)
        try context.withResources { _, _ in }; try scope.requireActive()
    }
    static func publish(_ scope: Publication.Scope, context: Native.NativeContext, expected: Snapshot) throws {
        try RuntimePublicationController.publishRetainedInitialNative(scope, verifyCurrent: {
            try verify(scope, context: context, expected: expected)
        })
    }
    private static func callbacks(context: Native.NativeContext, expected: Snapshot,
        verifyCurrent: @escaping (Snapshot) throws -> Void) -> Callbacks {
        let runtime = expected.activation.runtime
        return Callbacks(verifyCurrent: { actual in
            try context.verification.verifyPolicy(actual); try verifyCurrent(actual)
        }, verifyServices: { plan in
            guard plan == runtime.plan else { throw RuntimePreparationError.changedScope }
            try context.withResources { _, _ in }
        }, readMaterial: { scope in
            try scope.withActive {
                try Files.readMaterial(runtime: runtime, verifyCurrent: { try verify(scope, context: context, expected: expected) })
            }
        }, verifyActivity: { activity, scope in
            try scope.withActive {
                try Files.verifyActivity(activity, runtime: runtime, verifyCurrent: { try verify(scope, context: context, expected: expected) })
            }
        }, readArtifact: { artifact, scope in
            try scope.withActive {
                guard let material = scope.material else { throw RuntimePreparationError.incomplete }
                return try Files.readArtifact(artifact, bundle: scope.selection.configuration.bundle, material: material,
                    runtime: runtime, verifyCurrent: { try verify(scope, context: context, expected: expected) })
            }
        }, publish: { try publish($0, context: context, expected: expected) })
    }
}
