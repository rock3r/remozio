import CryptoKit
import Foundation
import RemozioProtocol

/// A single configured signer, clock contract, and payload budget for all root request operations.
public struct AuthorityRequestProviders: Sendable {
    let configurationBytes: Data
    let requestFrame: AuthorityRequestFrameProvider
    let pendingRequestIDs: AuthorityPendingRequestsProvider
    let exchangeRequest: AuthorityRequestExchangeProvider
    let receiptTime: @Sendable () -> UInt64?

    /// Production requires a restored device-bound key. Callbacks must not reenter the service, journal, or request owner.
    public init(configuration: AuthorityServiceConfiguration, signer: EnclaveAuthorityRequestSigner,
                routing: @escaping @Sendable () throws -> PresenceRouting,
                receiptTime: @escaping @Sendable () -> UInt64? = { nil }) throws {
        guard signer.macID == configuration.macID, signer.accountID == configuration.accountID else {
            throw AuthorityRequestSignerError.wrongIdentity
        }
        try self.init(configuration: configuration, publicKey: signer.publicKey,
            signing: { try signer.sign($0) }, routing: routing, receiptTime: receiptTime)
    }

    /// Software signing exists only in internal component fixtures, never as a public custody fallback.
    init(configuration: AuthorityServiceConfiguration, publicKey: Data,
         signing: @escaping @Sendable (Data) throws -> Data,
         routing: @escaping @Sendable () throws -> PresenceRouting,
         receiptTime: @escaping @Sendable () -> UInt64? = { nil }) throws {
        guard publicKey.count == 65, publicKey.first == 4,
              (try? P256.Signing.PublicKey(x963Representation: publicKey)) != nil,
              configuration.maximumPayloadBytes > ApprovalMessage.overheadBytes else {
            throw AuthorityServiceConfigurationError.invalidConfiguration
        }
        configurationBytes = configuration.canonicalBytes
        self.receiptTime = receiptTime
        let bodyBudget = configuration.maximumRequestBodyBytes
        let statusBudget = min(bodyBudget, AuthorityRequestExchange.maximumFrameBytes - ApprovalMessage.overheadBytes)
        requestFrame = { owner, binding, id, clock in
            try Self.requireScope(binding, configuration: configuration)
            return try owner.retainedDeliveryFrame(binding: binding, requestID: id, authorityPublicKey: publicKey,
                maximumBodyBytes: bodyBudget, now: clock, routing: routing, receiptTimeMs: receiptTime(), signer: signing)
        }
        pendingRequestIDs = { owner, binding, clock in
            try Self.requireScope(binding, configuration: configuration)
            return try owner.pendingDeliveryRequestIDs(binding: binding, routing: routing(), now: clock())
        }
        exchangeRequest = { owner, binding, id, decision, clock in
            try Self.requireScope(binding, configuration: configuration)
            return try owner.exchangeRequest(binding: binding, requestID: id, decisionFrame: decision, authorityPublicKey: publicKey,
                maximumBodyBytes: statusBudget, now: clock, receiptTimeMs: receiptTime(), signer: signing)
        }
    }
    func expirePending(_ owner: ApprovalRequestCoordinator, clock: @Sendable () throws -> AuthorityMoment) throws -> [ApprovalRequestState] {
        try owner.expirePending(now: clock(), receiptTimeMs: receiptTime())
    }
    func requireConfiguration(_ configuration: AuthorityServiceConfiguration) throws {
        guard configuration.canonicalBytes == configurationBytes else { throw AuthorityServiceConfigurationError.invalidConfiguration }
    }
    private static func requireScope(_ binding: AuthorityPeerBinding, configuration: AuthorityServiceConfiguration) throws {
        guard binding.scope.macID == configuration.macID, binding.scope.accountID == configuration.accountID else {
            throw AuthorityRequestSignerError.wrongIdentity
        }
    }
}
