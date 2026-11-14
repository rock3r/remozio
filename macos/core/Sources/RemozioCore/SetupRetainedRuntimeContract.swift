import Foundation
import RemozioProtocol

/// Bounded observations only. Decoding grants no authority, consent, activation or command readiness.
public enum SetupRetainedRuntimeContract {
    public static let version = AdministrativeSetupInterface.retainedRuntimeVersion
    public static let maximumBytes = 1024
    private static let limits = try! CBORLimits(maxBytes: maximumBytes, maxDepth: 2, maxItems: 48)
    public struct Progress: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
        public var description: String { "SetupRetainedRuntimeContract.Progress(redacted)" }
        public var debugDescription: String { description }
        public static let formatName = "setup.retained-runtime-progress"
        public enum Stage: UInt64, CaseIterable, Sendable {
            case materialPending = 1, policyPending, publicationPending, importAcknowledgementPending, retainedComplete
        }
        public let macID: Data, installationID: Data, targetID: Data, targetRevision: Data, stateDigest: Data
        public let stage: Stage
        /// The server supplies a fresh digest. A client value is only a stale-state observation.
        public init(macID: Data, installationID: Data, targetID: Data, targetRevision: Data, stateDigest: Data, stage: Stage) throws {
            guard [macID, installationID, targetID, targetRevision].allSatisfy({ $0.count == 16 }), stateDigest.count == 32 else {
                throw AdministrativeSetupChannelError.invalidMessage
            }
            self.macID = macID; self.installationID = installationID; self.targetID = targetID
            self.targetRevision = targetRevision; self.stateDigest = stateDigest; self.stage = stage
        }
        public var bytes: Data { get throws {
            try encode([0: .unsigned(1), 1: .text(Self.formatName), 2: .bytes(macID), 3: .bytes(installationID),
                4: .bytes(targetID), 5: .bytes(targetRevision), 6: .bytes(stateDigest), 7: .unsigned(stage.rawValue)])
        } }
        public static func decode(_ bytes: Data) throws -> Self {
            let f = try fields(bytes, count: 8, name: formatName)
            guard let stage = Stage(rawValue: try integer(f[7])) else { throw AdministrativeSetupChannelError.invalidMessage }
            let value = try Self(macID: data(f[2], count: 16), installationID: data(f[3], count: 16),
                targetID: data(f[4], count: 16), targetRevision: data(f[5], count: 16), stateDigest: data(f[6], count: 32), stage: stage)
            try exact(value.bytes, bytes); return value
        }
    }
    public struct Request: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
        public var description: String { "SetupRetainedRuntimeContract.Request(redacted)" }
        public var debugDescription: String { description }
        public static let formatName = "setup.retained-runtime-request"
        public let requestID: Data
        public let expected: Progress
        public init(requestID: Data, expected: Progress) throws {
            guard requestID.count == 16, expected.stage != .retainedComplete else { throw AdministrativeSetupChannelError.invalidMessage }
            self.requestID = requestID; self.expected = expected
        }
        /// Compare with protected server state before mutation. This never selects the current authority or target.
        public func requireCurrent(_ actual: Progress) throws {
            guard expected == actual else { throw AdministrativeSetupError.staleProgress }
        }
        public var bytes: Data { get throws {
            try encode([0: .unsigned(1), 1: .text(Self.formatName), 2: .bytes(requestID), 3: .bytes(expected.bytes)])
        } }
        public static func decode(_ bytes: Data) throws -> Self {
            let f = try fields(bytes, count: 4, name: formatName)
            let value = try Self(requestID: data(f[2], count: 16), expected: Progress.decode(data(f[3])))
            try exact(value.bytes, bytes); return value
        }
    }
    public struct Result: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
        public var description: String { "SetupRetainedRuntimeContract.Result(redacted)" }
        public var debugDescription: String { description }
        public static let formatName = "setup.retained-runtime-result"
        public enum Operation: UInt64, CaseIterable, Sendable { case notStarted = 1, committed, failed, unknown }
        public enum Restoration: UInt64, CaseIterable, Sendable { case notNeeded = 1, pending, restored, needsOwnerRecovery }
        public enum Failure: UInt64, CaseIterable, Sendable { case busy = 1, stale, unavailable, operationFailed, outcomeUnknown, restorationFailed, repairRequired }
        public let requestID: Data
        public let progress: Progress?
        public let operation: Operation
        public let restoration: Restoration
        public let failure: Failure?
        public let cancelled: Bool, expired: Bool
        public init(requestID: Data, progress: Progress?, operation: Operation, restoration: Restoration,
                    failure: Failure? = nil, cancelled: Bool = false, expired: Bool = false) throws {
            guard requestID.count == 16,
                  ![Operation.failed, .unknown].contains(operation) || failure != nil,
                  restoration != .needsOwnerRecovery || failure != nil else { throw AdministrativeSetupChannelError.invalidMessage }
            self.requestID = requestID; self.progress = progress; self.operation = operation; self.restoration = restoration
            self.failure = failure; self.cancelled = cancelled; self.expired = expired
        }
        public func requireReply(to request: Request) throws {
            guard requestID == request.requestID, progress == nil || (progress?.macID == request.expected.macID
                && progress?.installationID == request.expected.installationID && progress?.targetID == request.expected.targetID) else {
                throw AdministrativeSetupChannelError.invalidMessage
            }
        }
        public var bytes: Data { get throws {
            try encode([0: .unsigned(1), 1: .text(Self.formatName), 2: .bytes(requestID),
                3: try progress.map { .bytes(try $0.bytes) } ?? .null, 4: .unsigned(operation.rawValue),
                5: .unsigned(restoration.rawValue), 6: failure.map { .unsigned($0.rawValue) } ?? .null,
                7: .boolean(cancelled), 8: .boolean(expired)])
        } }
        public static func decode(_ bytes: Data) throws -> Self {
            let f = try fields(bytes, count: 9, name: formatName)
            guard let operation = Operation(rawValue: try integer(f[4])), let restoration = Restoration(rawValue: try integer(f[5])),
                  case .boolean(let cancelled) = f[7], case .boolean(let expired) = f[8] else { throw AdministrativeSetupChannelError.invalidMessage }
            let failure: Failure?
            if f[6] == .null { failure = nil }
            else { guard let value = Failure(rawValue: try integer(f[6])) else { throw AdministrativeSetupChannelError.invalidMessage }; failure = value }
            let value = try Self(requestID: data(f[2], count: 16), progress: f[3] == .null ? nil : Progress.decode(data(f[3])),
                operation: operation, restoration: restoration, failure: failure, cancelled: cancelled, expired: expired)
            try exact(value.bytes, bytes); return value
        }
    }
    /// Codec agreement only. Native admission and release capability checks remain separate.
    static func validate(_ release: SignedReleaseEvidence, policy: AuthorityCodePolicy) throws {
        let requirements = try [AuthorityCodeRole.app, .setupController].flatMap { role in
            try [(AdministrativeSetupInterface.formatName, version), (Request.formatName, 1), (Progress.formatName, 1), (Result.formatName, 1)].map {
                try RetainedReleaseFormat(role: role, name: $0.0, readVersions: [$0.1], writeVersions: [$0.1])
            }
        }
        try ReleaseCompatibilityPreflight.validate(release, policy: policy, requirements: .init(formats: requirements, requests: []))
    }
    private static func encode(_ fields: [UInt64: CBORValue]) throws -> Data { try DeterministicCBOR.encode(.map(fields), limits: limits) }
    private static func fields(_ bytes: Data, count: UInt64, name: String) throws -> [UInt64: CBORValue] {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)..<count),
              f[0] == .unsigned(1), f[1] == .text(name) else { throw AdministrativeSetupChannelError.invalidMessage }; return f
    }
    private static func data(_ field: CBORValue?, count: Int? = nil) throws -> Data {
        guard case .bytes(let value) = field, count == nil || value.count == count else { throw AdministrativeSetupChannelError.invalidMessage }; return value
    }
    private static func integer(_ field: CBORValue?) throws -> UInt64 {
        guard case .unsigned(let value) = field else { throw AdministrativeSetupChannelError.invalidMessage }; return value
    }
    private static func exact(_ canonical: Data, _ original: Data) throws {
        guard canonical == original else { throw AdministrativeSetupChannelError.invalidMessage }
    }
}

/// Declaration only. The existing daemon does not export these selectors or advertise this version.
@objc public protocol RetainedRuntimeSetupXPCProtocol {
    func retainedRuntimeHello(reply: @escaping @Sendable (UInt64) -> Void)
    func retainedRuntimeProgress(reply: @escaping @Sendable (Data?) -> Void)
    func prepareRetainedRuntime(_ request: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void)
}
