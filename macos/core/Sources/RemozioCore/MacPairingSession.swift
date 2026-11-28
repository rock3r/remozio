import Foundation
import RemozioHostCore
import RemozioProtocol
import Synchronization

public enum MacPairingSessionError: Error {
    case invalidConfiguration, invalidState, closed, expired, changedCandidate, ineligiblePredecessor
    case comparisonMismatch, comparisonAttemptsExhausted
}
public enum MacPairingSessionPhase: Sendable {
    case idle, connecting, waitingForPhone, authorizing, comparing, waitingForBiometric, committing
    case registeredOnMac, receiptSent, expired, comparisonFailed, unavailable, unavailableInterface, newPairingRequired, outcomeUnknown, closed
}

/// Display data only. A receipt write never claims that the phone activated its enrollment.
public struct MacPairingSessionSnapshot: Sendable {
    public let phase: MacPairingSessionPhase
    public let invitation: PairingInvitation?
    public let rePairInvitation: RePairInvitation?
    public let invitationV2: PairingInvitationV2?
    public let usesLoopbackOnlyV2: Bool
    public let candidates: [TransportPairingCandidate]
    public let selectedPhoneID: Data?
    public let comparisonCodePrefix: String?
    public let remainingMilliseconds: UInt64?
    public let phoneProofAvailable: Bool
}

protocol MacPairingRootControl: Sendable {
    func start() async throws -> AuthorityPairingContext
    func canRePair(_ selection: PairedPhoneSelection) async throws -> Bool
    func requiresNewPairing(_ selection: PairedPhoneSelection) async throws -> Bool
    func stage(_ proposal: PairingPhoneProposal, authorization: Data) async throws -> PairingTranscript
    /// Call onSend immediately before submitting the commit to Root.
    func commit(confirmedDigest: Data, biometricProof: Data, authorization: Data,
                onSend: @Sendable () -> Void) async throws -> Data
    func commit(confirmedDigest: Data, phoneProof: PairingPhoneProof, authorization: Data,
                onSend: @Sendable () -> Void) async throws -> Data
    nonisolated func abort()
    func close() async
}
extension MacPairingRootControl {
    func commit(confirmedDigest: Data, phoneProof: PairingPhoneProof, authorization: Data,
                onSend: @Sendable () -> Void) async throws -> Data {
        guard phoneProof.decision == nil else { throw AuthorityPairingChannelError.unsupportedVersion }
        return try await commit(confirmedDigest: confirmedDigest, biometricProof: phoneProof.biometric,
                                authorization: authorization, onSend: onSend)
    }
}
protocol MacPairingTransportControl: Sendable {
    func start(invitation: PairingInvitation) async throws -> UInt16
    func start(rePair: RePairInvitation) async throws -> UInt16
    func current() async throws -> TransportPairingSnapshot
    func stage(candidateID: Data, transcript: PairingTranscript) async throws
    func deliverReceipt(candidateID: Data, signature: Data) async throws
    nonisolated func abort()
    func close() async
}
struct MacPairingV2PublicWindow: Sendable {
    let id: Data
    let invitation: PairingInvitation
    let replacement: PairingReplacement?
    let lifetimeMilliseconds: UInt64
}

/// The logical fixture binds the same Authority and Transport owners as the v2 listener.
struct MacPairingV2Control: Sendable {
    let open: @Sendable (String, PairedPhoneSelection?) async throws -> PairingInvitationV2
    let listen: @Sendable (MacPairingV2PublicWindow) async throws -> Void
    let stage: @Sendable (PairingPhoneProposal, UUID, Data) async throws -> PairingTranscript
}

protocol MacPairingAdministrator: Sendable {
    func authorization() async throws -> Data
    func close() async
}
extension AuthorityPairingChannel: MacPairingRootControl {}
extension TransportPairingChannel: MacPairingTransportControl {}

actor NativePairingAdministrator: MacPairingAdministrator {
    private var session: SetupAdministratorSession?
    private var closed = false
    func authorization() throws -> Data {
        try Task.checkCancellation()
        guard !closed else { throw MacPairingSessionError.closed }
        if session == nil { session = try SetupAdministratorSession() }
        let session = session!
        try session.authorize()
        try Task.checkCancellation()
        return try session.externalForm()
    }
    func close() { closed = true; session?.close(); session = nil }
}

/// One explicit app-owned enrollment. Only the authenticated Root transcript is confirmable; commits never retry.
public actor MacPairingSession {
    private let rootOwner: Mutex<any MacPairingRootControl>
    private nonisolated var root: any MacPairingRootControl { rootOwner.withLock { $0 } }
    private let transport: any MacPairingTransportControl
    private let administrator: any MacPairingAdministrator
    private let predecessor: PairedPhoneSelection?
    private var v2: MacPairingV2Control?
    private var installedLAN = false
    private var requiresDecisionProof = false
    private let openInstalledRoot: (@Sendable () throws -> AuthorityPairingChannel)?
    private let installedTransport: TransportPairingChannel?
    private let cancellation = ChannelCancellation()
    private let unixMilliseconds: @Sendable () -> UInt64
    private let elapsedMilliseconds: @Sendable () throws -> UInt64
    private var phase = MacPairingSessionPhase.idle
    private var context: AuthorityPairingContext?
    private var invitation: PairingInvitation?
    private var rePairInvitation: RePairInvitation?
    private var invitationV2: PairingInvitationV2?
    private var candidates: [TransportPairingCandidate] = []
    private var selected: TransportPairingCandidate?
    private var transcript: PairingTranscript?
    private var deadline: UInt64?
    private var proof: PairingPhoneProof?
    private var busy = false
    private var commitAttempted = false
    private static let maximumComparisonMismatches = 3
    private var comparisonMismatches = 0
    private var humanConfirmed = false
    private var closingForRePair = false
    private var commitWaiters: [CheckedContinuation<Void, Never>] = []

    /// Both inputs must come from protected installation metadata. This opens no channel until start is called.
    public init(rootConfiguration: AuthorityPresenceClientConfiguration, transportConfiguration: TransportPairingControlConfiguration,
                predecessor: PairedPhoneSelection? = nil) throws {
        guard rootConfiguration.macID == transportConfiguration.macID,
              rootConfiguration.accountID == transportConfiguration.accountID,
              rootConfiguration.ownerUID == transportConfiguration.ownerUID,
              rootConfiguration.serviceName != transportConfiguration.serviceName else { throw MacPairingSessionError.invalidConfiguration }
        let clock = try SleepInclusiveClock()
        try self.init(openInstalledRoot: { try AuthorityPairingChannel(configuration: rootConfiguration) },
            installedTransport: TransportPairingChannel(configuration: transportConfiguration),
            administrator: NativePairingAdministrator(), predecessor: predecessor,
            unixMilliseconds: { UInt64(max(0, Date().timeIntervalSince1970 * 1000)) },
            elapsedMilliseconds: { try clock.milliseconds() })
    }

    // Run the installed session sequence with alternate native endpoints in the wire tests.
    init(openInstalledRoot: @escaping @Sendable () throws -> AuthorityPairingChannel, installedTransport: TransportPairingChannel,
         administrator: any MacPairingAdministrator, predecessor: PairedPhoneSelection? = nil,
         unixMilliseconds: @escaping @Sendable () -> UInt64, elapsedMilliseconds: @escaping @Sendable () throws -> UInt64) throws {
        rootOwner = Mutex(try openInstalledRoot() as any MacPairingRootControl)
        self.openInstalledRoot = openInstalledRoot
        self.installedTransport = installedTransport
        self.transport = installedTransport
        self.administrator = administrator
        self.predecessor = predecessor
        v2 = nil
        self.unixMilliseconds = unixMilliseconds; self.elapsedMilliseconds = elapsedMilliseconds
    }

    // Logical drivers cannot establish installed identity, native administrator consent or hardware custody.
    init(root: any MacPairingRootControl, transport: any MacPairingTransportControl, administrator: any MacPairingAdministrator,
         predecessor: PairedPhoneSelection? = nil, v2: MacPairingV2Control? = nil,
         unixMilliseconds: @escaping @Sendable () -> UInt64, elapsedMilliseconds: @escaping @Sendable () throws -> UInt64) {
        rootOwner = Mutex(root); self.transport = transport; self.administrator = administrator
        self.predecessor = predecessor
        self.v2 = v2
        openInstalledRoot = nil; installedTransport = nil
        self.unixMilliseconds = unixMilliseconds; self.elapsedMilliseconds = elapsedMilliseconds
    }
    deinit { root.abort(); transport.abort() }

    private func startRoot() async throws -> AuthorityPairingContext {
        let root = root
        let context = try await root.start()
        guard let openInstalledRoot, let transport = installedTransport, let channel = root as? AuthorityPairingChannel else {
            return context
        }
        try active()
        let negotiation: InstalledPairingNegotiation?
        do { negotiation = try await channel.negotiateInstalledPairing() }
        catch AuthorityPairingChannelError.setupDiscoveryUnavailable {
            // Only the optional capability probe can lead to a fresh legacy channel.
            await channel.close()
            try active()
            let legacy = try openInstalledRoot()
            rootOwner.withLock { $0 = legacy }
            try active()
            return try await legacy.start()
        }
        if let negotiation {
            let rendezvousID = negotiation.rendezvousID
            installedLAN = negotiation.requiresLAN
            requiresDecisionProof = negotiation.requiresDecisionProof
            v2 = MacPairingV2Control(open: { label, predecessor in
                try await transport.prepareV2(rendezvousID: rendezvousID)
                return try await channel.openV2(label: label, predecessor: predecessor, rendezvousID: rendezvousID)
            }, listen: { try await transport.beginV2($0, requiresLAN: negotiation.requiresLAN,
                                                   requiresDecisionProof: negotiation.requiresDecisionProof) }, stage: {
                try await channel.stageV2($0, connection: $1, authorization: $2)
            })
        }
        return context
    }

    public func start(label: String) async throws -> MacPairingSessionSnapshot {
        try active(); guard phase == .idle, !busy else { throw MacPairingSessionError.invalidState }
        busy = true; phase = .connecting; defer { busy = false }
        do {
            let context = try await startRoot(); try active()
            let invitation = try context.invitation(label: label)
            if let v2 {
                let elapsed = try elapsedMilliseconds()
                let exported = try await v2.open(label, predecessor); try active()
                guard try exported.invitation.encode() == invitation.encode(),
                      exported.replacement == (try predecessor?.predecessor),
                      exported.lifetimeMilliseconds == context.lifetimeMilliseconds else {
                    throw MacPairingSessionError.invalidState
                }
                let result = elapsed.addingReportingOverflow(exported.lifetimeMilliseconds)
                guard !result.overflow else { throw MacPairingSessionError.expired }
                deadline = result.partialValue
                try checkDeadline()
                try await v2.listen(.init(id: exported.windowID, invitation: invitation, replacement: exported.replacement,
                                          lifetimeMilliseconds: exported.lifetimeMilliseconds))
                try active(); try checkDeadline()
                invitationV2 = exported
                if let replacement = exported.replacement {
                    rePairInvitation = RePairInvitation(invitation: invitation, predecessor: replacement)
                }
            } else if let predecessor {
                guard try await root.canRePair(predecessor) else { throw MacPairingSessionError.ineligiblePredecessor }
                try active()
                let rePair = try RePairInvitation(invitation: invitation, predecessor: predecessor.predecessor)
                _ = try await transport.start(rePair: rePair)
                try active()
                guard try await root.canRePair(predecessor) else { throw MacPairingSessionError.ineligiblePredecessor }
                try active()
                rePairInvitation = rePair
            } else {
                _ = try await transport.start(invitation: invitation)
            }
            try active()
            self.context = context; self.invitation = invitation; phase = .waitingForPhone
            return snapshot()
        } catch { await fail(error); throw error }
    }
    public func current() async throws -> MacPairingSessionSnapshot {
        try active()
        guard !busy, phase == .waitingForPhone || phase == .comparing || phase == .waitingForBiometric else { return snapshot() }
        busy = true; defer { busy = false }
        do {
            try checkDeadline()
            let current = try await transport.current(); try active(); try checkDeadline()
            candidates = current.candidates.filter { matchesSession($0.proposal) }
            if !candidates.isEmpty { invitationV2 = nil }
            if let selected {
                guard let candidate = candidates.first(where: { $0.id == selected.id }),
                      try candidate.proposal.encode() == selected.proposal.encode() else { throw MacPairingSessionError.changedCandidate }
                if let phoneProof = candidate.phoneProof, let transcript {
                    do { try phoneProof.verify(in: transcript, requiresDecisionProof: requiresDecisionProof) }
                    catch { throw MacPairingSessionError.changedCandidate }
                    proof = phoneProof
                }
            }
            return snapshot()
        } catch { await fail(error); throw error }
    }
    /// The user selects this current phone. Administrator rights are requested only after the Root handshake.
    public func select(candidateID: Data) async throws -> MacPairingSessionSnapshot {
        try active(); guard !busy, phase == .waitingForPhone, let context, let invitation,
              let candidate = candidates.first(where: { $0.id == candidateID && $0.phase == .proposed }) else {
            throw MacPairingSessionError.invalidState
        }
        busy = true; phase = .authorizing; defer { busy = false }
        do {
            try checkDeadline()
            let authorization = try await administrator.authorization(); try active(); try checkDeadline()
            let current = try await transport.current(); try active(); try checkDeadline()
            guard let actual = current.candidates.first(where: { $0.id == candidateID && $0.phase == .proposed }),
                  matchesSession(actual.proposal),
                  try actual.proposal.encode() == candidate.proposal.encode() else { throw MacPairingSessionError.changedCandidate }
            if let predecessor {
                guard try await root.canRePair(predecessor) else { throw MacPairingSessionError.ineligiblePredecessor }
                try active(); try checkDeadline()
            }
            let staged: PairingTranscript
            if let v2 {
                staged = try await v2.stage(actual.proposal, GatewayHostSnapshot.uuid(candidateID), authorization)
            } else {
                staged = try await root.stage(actual.proposal, authorization: authorization)
            }
            try active(); try checkDeadline()
            try actual.proposal.validate(staged); try invitation.validateMacClaims(in: staged)
            if let predecessor, GatewayHostSnapshot.bytes(predecessor.revision) != staged.expectedTrustRevision {
                throw MacPairingSessionError.ineligiblePredecessor
            }
            let wall = unixMilliseconds(), elapsed = try elapsedMilliseconds()
            guard wall >= staged.issuedAtUnixMillis, wall < staged.expiresAtUnixMillis else { throw MacPairingSessionError.expired }
            let remaining = min(context.lifetimeMilliseconds, staged.expiresAtUnixMillis - wall)
            let (end, overflow) = elapsed.addingReportingOverflow(remaining)
            guard !overflow else { throw MacPairingSessionError.expired }
            selected = actual; transcript = staged; deadline = min(deadline ?? end, end); proof = nil; humanConfirmed = false
            comparisonMismatches = 0
            try await transport.stage(candidateID: candidateID, transcript: staged); try active(); try checkDeadline()
            phase = .comparing
            return snapshot()
        } catch SetupAdministratorAuthorizationError.cancelled {
            do {
                try active(); try checkDeadline()
                phase = .waitingForPhone
            } catch { await fail(error); throw error }
            throw SetupAdministratorAuthorizationError.cancelled
        }
        catch { await fail(error); throw error }
    }
    /// The staging phone displays the last group. The Mac snapshot exposes only the preceding groups.
    public func confirmComparison(enteredGroup: String) async throws -> MacPairingSessionSnapshot {
        try active()
        guard !busy, phase == .comparing, let transcript else { throw MacPairingSessionError.invalidState }
        _ = try await current()
        try active()
        guard !busy, phase == .comparing, self.transcript?.setupID == transcript.setupID else {
            throw MacPairingSessionError.invalidState
        }
        let expected = try transcript.verificationCode().suffix(5)
        guard enteredGroup.utf8.count == 5, enteredGroup.utf8.allSatisfy({ $0 < 0x80 }),
              enteredGroup.uppercased() == expected else {
            comparisonMismatches += 1
            if comparisonMismatches == Self.maximumComparisonMismatches {
                let error = MacPairingSessionError.comparisonAttemptsExhausted
                await fail(error)
                throw error
            }
            throw MacPairingSessionError.comparisonMismatch
        }
        humanConfirmed = true; phase = .waitingForBiometric; return snapshot()
    }
    /// Requires the explicit human confirmation and the current phone proof. A lost Root reply is never retried.
    public func commit() async throws -> MacPairingSessionSnapshot {
        try active()
        guard !busy, phase == .waitingForBiometric, humanConfirmed, !commitAttempted,
              let transcript, let selected, let proof else { throw MacPairingSessionError.invalidState }
        let submitted = Mutex(false)
        busy = true
        defer {
            busy = false
            let waiters = commitWaiters
            commitWaiters.removeAll()
            for waiter in waiters { waiter.resume() }
        }
        do {
            try checkDeadline()
            let authorization = try await administrator.authorization(); try active(); try checkDeadline()
            let current = try await transport.current(); try active(); try checkDeadline()
            guard let candidate = current.candidates.first(where: { $0.id == selected.id }),
                  candidate.phase == .proofReady, candidate.phoneProof == proof,
                  try candidate.proposal.encode() == selected.proposal.encode() else { throw MacPairingSessionError.changedCandidate }
            do { try proof.verify(in: transcript, requiresDecisionProof: requiresDecisionProof) }
            catch { throw MacPairingSessionError.changedCandidate }
            guard !closingForRePair else { throw MacPairingSessionError.closed }
            let digest = try transcript.digest()
            try checkDeadline()
            phase = .committing; commitAttempted = true
            let receipt = try await root.commit(confirmedDigest: digest, phoneProof: proof, authorization: authorization,
                onSend: { submitted.withLock { $0 = true } })
            guard try transcript.verify(signature: receipt, publicKey: transcript.macAuthorityKey, purpose: .macCommit) else {
                throw MacPairingSessionError.invalidState
            }
            phase = .registeredOnMac
            try active()
            do {
                try await transport.deliverReceipt(candidateID: selected.id, signature: receipt)
                try active(); phase = .receiptSent
            } catch { /* Root returned a verified durable receipt; phone delivery remains uncertain. */ }
            await releaseChannels()
            return snapshot()
        } catch {
            // Keep the attempted flag during the call so re-pair waits for it to drain.
            if !submitted.withLock({ $0 }) { commitAttempted = false }
            await fail(error)
            throw error
        }
    }
    private func matchesSession(_ proposal: PairingPhoneProposal) -> Bool {
        if let rePairInvitation { return rePairInvitation.matches(proposal) }
        return proposal.replacement == nil
    }

    /// Finish a submitted commit before closing this generation. An unknown result blocks a replacement.
    public func closeForRePair() async -> Bool {
        closingForRePair = true
        if commitAttempted && busy {
            await withCheckedContinuation { commitWaiters.append($0) }
        }
        await close()
        return phase != .outcomeUnknown
    }

    public nonisolated func abort() { cancellation.cancel(); root.abort(); transport.abort() }
    /// Cancels admission immediately. Native authorization cleanup may wait for its actual OS call to return.
    public func close() async {
        abort()
        if phase != .registeredOnMac && phase != .receiptSent && phase != .outcomeUnknown { phase = commitAttempted ? .outcomeUnknown : .closed }
        await releaseChannels()
    }
    private func active() throws {
        try Task.checkCancellation()
        guard cancellation.ifActive({}) else { throw MacPairingSessionError.closed }
    }
    private func checkDeadline() throws {
        if try remainingTime() == 0 { throw MacPairingSessionError.expired }
    }
    private func remainingTime() throws -> UInt64? {
        guard let deadline else { return nil }
        let elapsed = try elapsedMilliseconds()
        return deadline > elapsed ? deadline - elapsed : 0
    }
    private func fail(_ error: any Error) async {
        if phase != .registeredOnMac && phase != .receiptSent {
            if commitAttempted { phase = .outcomeUnknown }
            else if !cancellation.ifActive({}) { phase = .closed }
            else if error as? MacPairingSessionError == .comparisonAttemptsExhausted ||
                        error as? MacPairingSessionError == .expired || (try? remainingTime()) == 0 {
                phase = error as? MacPairingSessionError == .comparisonAttemptsExhausted ? .comparisonFailed : .expired
                invitation = nil; rePairInvitation = nil
                candidates = []; selected = nil; transcript = nil; proof = nil; humanConfirmed = false
            }
            else if error as? TransportPairingControlError == .unavailableInterface { phase = .unavailableInterface }
            else { phase = .unavailable }
        }
        await releaseChannels()
        if phase == .unavailable, let predecessor, await refreshRePairRestriction(predecessor),
           cancellation.ifActive({}) {
            phase = .newPairingRequired
            invitation = nil
            rePairInvitation = nil
            candidates = []
            selected = nil
            transcript = nil
            proof = nil
            humanConfirmed = false
        }
    }

    private func refreshRePairRestriction(_ selection: PairedPhoneSelection) async -> Bool {
        guard let openInstalledRoot else { return (try? await root.requiresNewPairing(selection)) == true }
        guard let channel = try? openInstalledRoot() else { return false }
        let restricted: Bool
        do {
            _ = try await channel.start()
            restricted = try await channel.requiresNewPairing(selection)
        } catch {
            restricted = false
        }
        await channel.close()
        return restricted
    }

    private func releaseChannels() async {
        invitationV2 = nil
        root.abort()
        // A new re-pair awaits the helper's drain for that predecessor before beginning setup.
        transport.abort()
        await root.close()
        await transport.close()
        await administrator.close()
    }
    public func snapshot() -> MacPairingSessionSnapshot {
        let remaining = phase == .expired || phase == .comparisonFailed ? 0 : (try? remainingTime()) ?? deadline.map { _ in 0 }
        let comparisonCodePrefix = phase == .comparing && remaining != 0 && cancellation.ifActive({}) ?
            (try? transcript?.verificationCode()).map { String($0.dropLast(6)) } : nil
        return .init(phase: phase, invitation: v2 == nil ? invitation : nil, rePairInvitation: v2 == nil ? rePairInvitation : nil,
            invitationV2: phase == .waitingForPhone ? invitationV2 : nil,
            usesLoopbackOnlyV2: installedTransport != nil && v2 != nil && !installedLAN, candidates: candidates, selectedPhoneID: selected?.proposal.phone.scope.phoneID,
            comparisonCodePrefix: comparisonCodePrefix, remainingMilliseconds: remaining, phoneProofAvailable: proof != nil && remaining != 0)
    }
}
