import Darwin
import Foundation

/// Advances one held import journal through its existing owner. It never publishes files, changes machine rows or registers jobs.
enum MachineUpdateRetainedSetupImportAcknowledgementNative {
    typealias Native = MachineUpdateRetainedSetupRuntimeNativeContext
    typealias Authority = MachineUpdateRetainedSetupRuntimeNativeAuthority
    typealias Owner = MachineUpdateRetainedSetupImportAcknowledgement
    typealias Files = MachineUpdateRetainedSetupRuntimeNativeFiles
    typealias Frame = PreparationIntentStore.RetainedImportFrame
    typealias Result = (frame: Frame, advanced: Bool)
    struct Callbacks {
        let verifyCurrent: (Owner.Scope) throws -> Void
        let verifyServices: (ServiceAccountPlan) throws -> Void
        let readMaterial: (Owner.Scope) throws -> RuntimePreparationMaterial
        let verifyActivity: (ServiceReleaseActivityReference, Owner.Scope) throws -> Void
        let readArtifact: (Owner.Artifact, Owner.Scope) throws -> Data?
    }
    static func acknowledge(context: Native.NativeContext, authority: Authority.HeldScope, expected: Frame,
        candidate: SignedReleaseEvidence, verifyCurrent: @escaping (Frame) throws -> Void) throws -> Result {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try context.verification.verifyFrame(expected)
        return try context.withResources { directory, admission in
            try Authority.withTargetPair(scope: authority, expected: expected.entry) { read in
                try context.withMachine(expected: expected.entry, opening: .mutable) { machine in
                    try withA10c(machine: machine, expected: expected.entry, candidate: candidate, directory: directory,
                        admission: admission, readPolicyBoundary: read,
                        callbacks: callbacks(context: context, expected: expected, verifyCurrent: verifyCurrent))
                }
            }
        }
    }
    /// Owned controls exercise the same owner and machine interval. They cannot construct native custody or code approval.
    static func withA10c(machine: PreparationIntentStore, expected: Owner.Entry, candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease,
        readPolicyBoundary: () throws -> AuthorityJournal.MachineUpdatePolicyBoundary, callbacks: Callbacks) throws -> Result {
        try Owner.acknowledge(machine: machine, expected: expected, candidate: candidate, directory: directory,
            admission: admission, fileCustodyAccepted: true, readPolicyBoundary: readPolicyBoundary,
            verifyCurrent: callbacks.verifyCurrent, verifyServices: callbacks.verifyServices,
            readMaterial: callbacks.readMaterial, verifyActivity: callbacks.verifyActivity, readArtifact: callbacks.readArtifact)
    }
    private static func verify(_ scope: Owner.Scope, context: Native.NativeContext) throws -> Frame {
        try scope.requireActive(); let actual = try scope.read()
        try context.verification.verifyAcknowledgement(actual)
        try context.withResources { _, _ in }; try scope.requireActive(); return actual
    }
    private static func callbacks(context: Native.NativeContext, expected: Frame,
        verifyCurrent: @escaping (Frame) throws -> Void) -> Callbacks {
        Callbacks(verifyCurrent: { scope in
            try scope.withActive {
                let actual = try verify(scope, context: context); try verifyCurrent(actual); try scope.requireActive()
            }
        }, verifyServices: { plan in
            guard plan == expected.entry.runtime.plan else { throw RuntimePreparationError.changedScope }
            try context.withResources { _, _ in }
        }, readMaterial: { scope in
            try scope.withActive {
                let actual = try scope.read()
                return try Files.readMaterial(runtime: actual.entry.runtime,
                    verifyCurrent: { _ = try verify(scope, context: context) })
            }
        }, verifyActivity: { activity, scope in
            try scope.withActive {
                let actual = try scope.read()
                try Files.verifyActivity(activity, runtime: actual.entry.runtime,
                    verifyCurrent: { _ = try verify(scope, context: context) })
            }
        }, readArtifact: { artifact, scope in
            try scope.withActive {
                let actual = try scope.read()
                guard let material = scope.material, let bundle = scope.bundle else { throw RuntimePreparationError.incomplete }
                return try Files.readArtifact(artifact, bundle: bundle, material: material, runtime: actual.entry.runtime,
                    verifyCurrent: { _ = try verify(scope, context: context) })
            }
        })
    }
}
