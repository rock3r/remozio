import Darwin
import Foundation

/// Owned controls prove verification and loan lifetime. A11c supplies the production constructor; no native caller exists here.
enum MachineUpdateRetainedSetupRuntimeNativeContext {
    typealias Entry = MachineUpdateRetainedSetupInitialRuntimeEntry
    typealias Frame = PreparationIntentStore.RetainedImportFrame
    typealias Material = MachineUpdateRetainedSetupMaterialSnapshot
    typealias Policy = MachineUpdateRetainedSetupPolicySnapshot
    typealias Verify = () throws -> Void
    struct Controls {
        let validateCustody: Verify
        let validateRelease: (Entry) throws -> Void
        let validateExecutingCode: Verify
        let lookupOwner: (UInt32) throws -> LocalAccountIdentity
        let validateServices: (ServiceAccountPlan) throws -> Void
    }
    final class Context {
        private let processID = getpid(), thread = pthread_self()
        private let candidate: SignedReleaseEvidence
        private var approved: Frame?
        private var body: ((Entry, Verify) throws -> Void)?
        private var executing = false
        fileprivate init(expected: Frame, candidate: SignedReleaseEvidence, body: @escaping (Entry, Verify) throws -> Void) {
            approved = expected; self.candidate = candidate; self.body = body
        }
        private func requireActive() throws {
            guard getpid() == processID, pthread_equal(pthread_self(), thread) != 0, body != nil else {
                throw JournalLeaseError.invalidated
            }
        }
        private func entry(_ value: Policy) throws -> Entry {
            try .init(runtime: value.activation.runtime, activation: value.activation.state, intent: value.intent, candidate: candidate)
        }
        private func accept(_ next: (Frame) throws -> Frame) throws {
            try requireActive()
            guard !executing, let body, let approved else { expire(); throw JournalLeaseError.invalidated }
            executing = true; defer { executing = false }
            do {
                let actual = try next(approved); try actual.inputs.requireSource(actual.entry.runtime)
                try body(actual.entry, requireActive); try requireActive(); self.approved = actual
            } catch { expire(); throw error }
        }
        func verifyEntry(_ actual: Entry) throws {
            try accept { before in try actual.requireSame(as: before.entry); return (actual, before.inputs) }
        }
        func verifyFrame(_ actual: Frame) throws {
            try accept { before in
                try actual.entry.requireSame(as: before.entry); try actual.inputs.requireSame(as: before.inputs); return actual
            }
        }
        func verifyMaterial(_ actual: Material) throws {
            try accept { before in
                let value = try Entry(runtime: actual.runtime, activation: actual.activation,
                    intent: before.entry.intent, candidate: candidate)
                if actual.runtime.state == before.entry.runtime.state { try value.requireSame(as: before.entry) }
                else if let reference = actual.runtime.state.reference { try value.requireMaterial(reference, from: before.entry) }
                else { throw PreparationStoreError.staleRevision }
                return (value, before.inputs)
            }
        }
        func verifyPolicy(_ actual: Policy) throws {
            try accept { before in
                let value = try entry(actual)
                if actual.intent == before.entry.intent { try value.requireSame(as: before.entry) }
                else if let record = actual.intent {
                    if before.entry.intent == nil { try value.requirePolicyRetention(record, from: before.entry) }
                    else { try value.requirePolicyTransition(record, from: before.entry) }
                } else { throw PreparationStoreError.staleRevision }
                return (value, before.inputs)
            }
        }
        func verifyPublication(_ actual: Policy) throws {
            try accept { before in
                let value = try entry(actual)
                if value.runtime.state == before.entry.runtime.state { try value.requireSame(as: before.entry) }
                else {
                    guard let reference = before.entry.runtime.state.reference else { throw RuntimePreparationError.incomplete }
                    try value.requirePublication(from: before.entry, reference: reference)
                }
                return (value, before.inputs)
            }
        }
        func verifyAcknowledgement(_ actual: Frame) throws {
            try accept { before in
                if actual.inputs == before.inputs { try actual.entry.requireSame(as: before.entry) }
                else { try actual.entry.requireAcknowledgement(inputs: actual.inputs, from: before.entry, previousInputs: before.inputs) }
                return actual
            }
        }
        fileprivate func verifyLast() throws {
            try requireActive(); guard let approved else { throw JournalLeaseError.invalidated }; try verifyFrame(approved)
        }
        fileprivate func expire() { body = nil; approved = nil }
    }
    /// Performs no machine, policy, import or relay query. The owner lends actual frames, including transaction frames.
    static func withOwnedContext<Value>(expected: Frame, candidate: SignedReleaseEvidence, controls: Controls,
        perform: (Context) throws -> Value) throws -> Value {
        try RuntimeRetainedSetupReleaseBinding.requireFormats(candidate)
        try Entry(runtime: expected.entry.runtime, activation: expected.entry.activation,
            intent: expected.entry.intent, candidate: candidate).requireSame(as: expected.entry)
        try expected.inputs.requireSource(expected.entry.runtime)
        let context = Context(expected: expected, candidate: candidate) { actual, active in
            func metadata() throws {
                try active(); try controls.validateCustody(); try active()
                try controls.validateRelease(actual); try controls.validateCustody(); try active()
                try controls.validateExecutingCode(); try controls.validateCustody(); try active()
                try actual.runtime.setup.requireOwner(controls.lookupOwner(actual.runtime.setup.owner.uid))
                try controls.validateCustody(); try active()
                try controls.validateServices(actual.runtime.plan); try controls.validateCustody(); try active()
            }
            try metadata()
        }
        defer { context.expire() }
        try context.verifyLast(); let result = try perform(context); try context.verifyLast(); return result
    }
}
