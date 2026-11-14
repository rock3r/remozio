import Darwin
import Foundation

/// Assembles providers inside existing custody loans. A future authenticated caller must supply its verified HeldScope.
/// This entry selects no authority and grants no request, enrollment, activation, consent or ordinary-ready authority.
enum MachineUpdateRetainedSetupRuntimeNativeEntry {
    typealias Native = MachineUpdateRetainedSetupRuntimeNativeContext
    typealias Authority = MachineUpdateRetainedSetupRuntimeNativeAuthority
    typealias Sequence = MachineUpdateRetainedSetupRuntimeSequence
    typealias Frame = Sequence.Frame
    typealias Policy = Sequence.Policy
    typealias Files = MachineUpdateRetainedSetupRuntimeNativeFiles
    static func prepare(context: Native.NativeContext, authority: Authority.HeldScope,
        owner: LocalAccountIdentity, candidate: SignedReleaseEvidence) throws -> Frame {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try authority.requireActive()
        return try context.withResources { directory, admission in
            let providers = Sequence.Providers(material: { expected, verify in
                try MachineUpdateRetainedSetupRuntimeNativeMaterial.prepare(context: context, authority: authority,
                    expected: expected, candidate: candidate, verifyCurrent: verify)
            }, policy: { expected, verify in
                try resumePolicy(context: context, expected: expected, candidate: candidate,
                    directory: directory, admission: admission, verifyCurrent: verify)
            }, publication: { expected, verify in
                try MachineUpdateRetainedSetupInitialRuntimeNative.prepare(context: context, authority: authority,
                    expected: expected, candidate: candidate, verifyCurrent: verify)
            }, acknowledgement: { expected, verify in
                try MachineUpdateRetainedSetupImportAcknowledgementNative.acknowledge(context: context, authority: authority,
                    expected: expected, candidate: candidate, verifyCurrent: verify)
            })
            let result = try withSequence(context: context.verification, owner: owner, candidate: candidate,
                directory: directory, admission: admission, useMachine: { body in
                    try context.withMachine(opening: .retainedPolicyVerification, closing: .owner, perform: body)
                }, providers: providers)
            try authority.requireActive(); return result
        }
    }
    /// Owned providers exercise the same outer sequence and host checks. They cannot construct a native token or HeldScope.
    static func withSequence(context: Native.Context, owner: LocalAccountIdentity, candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease,
        useMachine: @escaping Sequence.UseMachine, providers: Sequence.Providers) throws -> Frame {
        try Sequence.prepare(owner: owner, candidate: candidate, directory: directory, admission: admission,
            fileCustodyAccepted: true, useMachine: useMachine, providers: providers,
            verifyCurrent: context.verifyEntry, verifyMaterialCurrent: context.verifyMaterial, didCapture: context.verifyFrame)
    }
    private static func resumePolicy(context: Native.NativeContext, expected: Policy, candidate: SignedReleaseEvidence,
        directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease,
        verifyCurrent: @escaping (Policy) throws -> Void) throws -> Policy {
        let initial = try MachineUpdateRetainedSetupPolicyNativeContext.requireExpected(expected, candidate: candidate)
        let paths = try MachineUpdateRetainedSetupPromotionNativeSupport.Paths(accountID: initial.accountID,
            journalPath: initial.journalPath, continuityPath: initial.continuityPath)
        var current = expected
        func host(_ actual: Policy) throws { try context.verification.verifyPolicy(actual) }
        func checked(_ actual: Policy) throws {
            try host(actual)
            let runtime = actual.activation.runtime
            let first = try Files.readMaterial(runtime: runtime, verifyCurrent: { try host(actual) })
            guard let activity = first.serviceActivity else { throw RuntimePreparationError.incomplete }
            try Files.verifyActivity(activity, runtime: runtime, verifyCurrent: { try host(actual) })
            let second = try Files.readMaterial(runtime: runtime, verifyCurrent: { try host(actual) })
            guard try second.encoded == first.encoded else { throw RuntimePreparationError.conflictingMaterial }
            current = actual
        }
        func verify(_ actual: Policy) throws { try checked(actual); try verifyCurrent(actual) }
        return try MachineUpdateRetainedSetupPolicyOwner.resume(expected: expected, candidate: candidate,
            directory: directory, admission: admission, useMachine: { body in
                try context.withMachine(opening: .mutable, perform: body)
            }, openJournal: { access in
                try MachineUpdateRetainedSetupPolicyNativeEntry.openJournal(access: access, initial: initial,
                    openJournalLease: { try ProtectedJournalLease.acquire(directoryPath: paths.journalDirectory) },
                    openContinuityLease: { try ProtectedContinuityLease.acquire(directoryPath: paths.continuityDirectory, excludingDirectory: $0) },
                    verifySelf: { _ in try checked(current) })
            }, verifySnapshot: verify)
    }
}
