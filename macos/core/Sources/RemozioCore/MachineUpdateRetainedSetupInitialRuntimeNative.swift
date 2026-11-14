import Darwin
import Foundation

/// Supplies the publication provider after P04 returns. It uses the original C2 and D2 owners and closes every machine.
enum MachineUpdateRetainedSetupInitialRuntimeNative {
    typealias Native = MachineUpdateRetainedSetupRuntimeNativeContext
    typealias Authority = MachineUpdateRetainedSetupRuntimeNativeAuthority
    typealias Runtime = MachineUpdateRetainedSetupInitialRuntime
    typealias Publication = MachineUpdateRetainedSetupInitialPublicationNative
    typealias Completion = MachineUpdateRetainedSetupInitialCompletionNative
    typealias Snapshot = Runtime.Snapshot
    typealias Boundary = AuthorityJournal.MachineUpdatePolicyBoundary
    typealias WithTargetPair = (_ body: (@escaping () throws -> Boundary) throws -> Snapshot) throws -> Snapshot
    static func prepare(context: Native.NativeContext, authority: Authority.HeldScope, expected: Snapshot,
        candidate: SignedReleaseEvidence, verifyCurrent: @escaping (Snapshot) throws -> Void) throws -> Snapshot {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        var current = expected
        let completion = Completion.callbacks(context: context, expected: expected, verifyCurrent: { actual in
            try verifyCurrent(actual); current = actual
        })
        let publication = Publication.callbacks(context: context, expected: expected, verifyCurrent: verifyCurrent)
        func entry() throws -> Native.Entry {
            try .init(runtime: current.activation.runtime, activation: current.activation.state,
                intent: current.intent, candidate: candidate)
        }
        return try context.withResources { directory, admission in
            try withA10d(expected: expected, candidate: candidate, directory: directory, admission: admission,
                withTargetPair: { body in
                    try Authority.withTargetPair(scope: authority, expected: entry(), perform: body)
                }, useMachine: { body in
                    try context.withMachine(expected: entry(), opening: .mutable, closing: .owner, perform: body)
                }, publication: publication, completion: completion)
        }
    }
    /// The recorded frame comes from the completed P04 provider. The target pair cannot span its startup writer.
    static func withA10d(expected: Snapshot, candidate: SignedReleaseEvidence, directory: ReleaseDestinationLease,
        admission: UpdateOrdinaryAdmissionLease, withTargetPair: WithTargetPair, useMachine: @escaping Runtime.UseMachine,
        publication: Publication.Callbacks, completion: Completion.Callbacks) throws -> Snapshot {
        guard expected.intent?.phase == .recorded else { throw RuntimeActivationError.incomplete }
        try completion.verifyCurrent(expected)
        return try withTargetPair { read in
            try Runtime.prepare(expected: expected, candidate: candidate, directory: directory, admission: admission,
                fileCustodyAccepted: true, useMachine: useMachine, readPolicyBoundary: read,
                verifyCurrent: completion.verifyCurrent, verifyServices: completion.verifyServices,
                readMaterial: { scope in
                    try scope.withOwner(publication: publication.readMaterial, observation: completion.readMaterial)
                }, verifyActivity: { activity, scope in
                    try scope.withOwner(publication: { try publication.verifyActivity(activity, $0) },
                        observation: { try completion.verifyActivity(activity, $0) })
                }, readArtifact: { artifact, scope in
                    try scope.withOwner(publication: { try publication.readArtifact(artifact, $0) },
                        observation: { try completion.readArtifact(artifact, $0) })
                }, publish: { scope in
                    try scope.withOwner(publication: publication.publish,
                        observation: { _ in throw JournalLeaseError.invalidated })
                }, didCompletionStorageStage: completion.didStorageStage)
        }
    }
}
