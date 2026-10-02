import Darwin
import Foundation
import RemozioProtocol

public enum GatewayDeliveryError: Error, Equatable {
    case invalidConfiguration, stopped, capacityExceeded, alreadyRunning, unknownEnrollment, invalidClock
}

/// Local limits for one gateway process. Waiting for OAuth or a retry occupies a flight slot.
public struct GatewayDeliveryPolicy: Sendable {
    public let maximumFlights: Int
    public let minimumSendIntervalMillis: UInt64
    public let retryBaseDelayMillis: UInt64
    public let maximumRetryBackoffMillis: UInt64
    public init(maximumFlights: Int, minimumSendIntervalMillis: UInt64, retryBaseDelayMillis: UInt64 = 1000,
                maximumRetryBackoffMillis: UInt64 = 60_000) throws {
        guard (1...64).contains(maximumFlights), (1...3_600_000).contains(minimumSendIntervalMillis),
              (1...3_600_000).contains(retryBaseDelayMillis),
              (retryBaseDelayMillis...3_600_000).contains(maximumRetryBackoffMillis) else {
            throw GatewayDeliveryError.invalidConfiguration
        }
        self.maximumFlights = maximumFlights; self.minimumSendIntervalMillis = minimumSendIntervalMillis
        self.retryBaseDelayMillis = retryBaseDelayMillis; self.maximumRetryBackoffMillis = maximumRetryBackoffMillis
    }
}

/// Owns the database and probe tasks. Trusted setup methods are local APIs, never submission endpoints.
public actor GatewayDeliveryCoordinator {
    private let database: GatewayDatabase
    private let identity: GatewayRegistrationIdentity
    private let tokens: FCMTokenSource
    private let policy: GatewayDeliveryPolicy
    private let sample: @Sendable () throws -> Sample
    private let sleep: @Sendable (UInt64) async throws -> Void
    private let send: @Sendable (FCMTokenProbe, FCMAccessToken) async throws -> FCMDeliveryResult
    private var enrollments: [Data: GatewayPhoneEnrollment] = [:]
    private var trustRevision = UUID()
    private var active = true
    private var stopped = false
    private var shutdownTask: Task<Void, any Error>?
    private var nextSend: UInt64
    private var lastMoment: AuthorityMoment
    private var flights: [Data: Flight] = [:]

    struct Sample: Sendable { let wall: UInt64; let moment: AuthorityMoment }
    private struct Flight {
        let id: UUID
        let phone: Data
        let enrollmentEpoch: Data
        let task: Task<GatewayProbeProgress?, any Error>
    }

    public init(database: sending GatewayDatabase, identity: GatewayRegistrationIdentity, tokens: FCMTokenSource,
                sender: FCMWakeSender, policy: GatewayDeliveryPolicy, clockEpoch: UUID) throws {
        try self.init(database: database, identity: identity, tokens: tokens, policy: policy, sample: {
            let wall = Date().timeIntervalSince1970 * 1000
            guard wall.isFinite, wall >= 0, wall < Double(UInt64.max) else { throw GatewayDeliveryError.invalidClock }
            var timebase = mach_timebase_info_data_t()
            guard mach_timebase_info(&timebase) == KERN_SUCCESS, timebase.denom != 0 else { throw GatewayDeliveryError.invalidClock }
            let millis = Double(mach_continuous_time()) * Double(timebase.numer) / Double(timebase.denom) / 1_000_000
            guard millis.isFinite, millis >= 0, millis < Double(UInt64.max) else { throw GatewayDeliveryError.invalidClock }
            return Sample(wall: UInt64(wall), moment: AuthorityMoment(epoch: clockEpoch, milliseconds: UInt64(millis)))
        }, sleep: { try await Task.sleep(for: .milliseconds($0)) }, send: { try await sender.send($0, accessToken: $1) })
    }

    init(database: sending GatewayDatabase, identity: GatewayRegistrationIdentity, tokens: FCMTokenSource,
         policy: GatewayDeliveryPolicy, sample: @escaping @Sendable () throws -> Sample,
         sleep: @escaping @Sendable (UInt64) async throws -> Void,
         send: @escaping @Sendable (FCMTokenProbe, FCMAccessToken) async throws -> FCMDeliveryResult) throws {
        let first = try sample()
        let (next, overflow) = first.moment.milliseconds.addingReportingOverflow(policy.minimumSendIntervalMillis)
        guard !overflow else { throw GatewayDeliveryError.invalidClock }
        self.database = database; self.identity = identity; self.tokens = tokens; self.policy = policy
        self.sample = sample; self.sleep = sleep; self.send = send; lastMoment = first.moment; nextSend = next
    }

    /// The host supplies retained, authenticated enrollment state after protected setup or reconciliation.
    /// Changes cancel affected work. It cannot clear database revocation tombstones.
    public func replaceTrustedEnrollments(_ values: [GatewayPhoneEnrollment], active: Bool) throws {
        try running()
        guard values.count <= 1024, Set(values.map(\.phoneID)).count == values.count else {
            throw GatewayDeliveryError.invalidConfiguration
        }
        let next = Dictionary(uniqueKeysWithValues: values.map { ($0.phoneID, $0) })
        for flight in flights.values {
            let before = enrollments[flight.phone], after = next[flight.phone]
            if self.active != active || before?.epoch != after?.epoch || before?.tag != after?.tag || before?.active != after?.active {
                flight.task.cancel()
            }
        }
        enrollments = next; self.active = active; trustRevision = UUID()
    }

    public func admitCandidate(canonicalPayload: Data, signature: Data, wireVersion: UInt64,
                               registrationToken: String, phoneID: Data) throws -> GatewayCandidateAdmission {
        try running()
        let time = try current()
        return try database.admitCandidate(canonicalPayload: canonicalPayload, signature: signature, wireVersion: wireVersion,
            registrationToken: registrationToken, trust: trust(phoneID), nowUnixMillis: time.wall, now: time.moment)
    }

    public func applyRecipient(canonicalPayload: Data, signature: Data, wireVersion: UInt64,
                               kind: GatewayRecipientKind, phoneID: Data) throws -> GatewayRecipientApplication {
        try running()
        let time = try current()
        let result = try database.applyRecipient(canonicalPayload: canonicalPayload, signature: signature, wireVersion: wireVersion,
            kind: kind, trust: trust(phoneID), nowUnixMillis: time.wall, now: time.moment)
        if result.inserted && kind == .phoneRevocation {
            for flight in flights.values where flight.phone == result.receipt.phoneID && flight.enrollmentEpoch == result.receipt.enrollmentEpoch {
                flight.task.cancel()
            }
        }
        return result
    }

    public func progress(operationID: Data) throws -> GatewayProbeProgress? {
        try running(); return try database.probeProgress(candidateOperationID: operationID)
    }

    /// Runs bounded retries for an admitted candidate. Acceptance still requires a separate phone proof and root control.
    public func deliverProbe(operationID: Data, phoneID: Data) async throws -> GatewayProbeProgress? {
        try running(); try Task.checkCancellation()
        guard operationID.count == 16 else { throw GatewayDatabaseError.wrongScope }
        guard flights[operationID] == nil else { throw GatewayDeliveryError.alreadyRunning }
        guard flights.count < policy.maximumFlights else { throw GatewayDeliveryError.capacityExceeded }
        let enrollment = try trust(phoneID).enrollment
        guard let receipt = try database.receipt(operationID: operationID), receipt.candidate.binding.phoneID == phoneID,
              receipt.candidate.binding.enrollmentEpoch == enrollment.epoch else { throw GatewayDatabaseError.wrongScope }
        let id = UUID()
        let task = Task { try await self.run(operationID: operationID, phoneID: phoneID) }
        flights[operationID] = Flight(id: id, phone: phoneID, enrollmentEpoch: enrollment.epoch, task: task)
        defer { if flights[operationID]?.id == id { flights.removeValue(forKey: operationID) } }
        return try await withTaskCancellationHandler { try await task.value } onCancel: { task.cancel() }
    }

    public func cancel(operationID: Data) { flights[operationID]?.task.cancel() }

    public func shutdown() async throws {
        if let shutdownTask { try await shutdownTask.value; return }
        stopped = true
        let tasks = flights.values.map(\.task)
        for task in tasks { task.cancel() }
        let task = Task {
            for task in tasks { _ = await task.result }
            await tokens.shutdown()
            try database.close()
        }
        shutdownTask = task
        try await task.value
    }

    private func run(operationID: Data, phoneID: Data) async throws -> GatewayProbeProgress? {
        while true {
            try running(); try Task.checkCancellation()
            if let progress = try database.probeProgress(candidateOperationID: operationID) {
                switch progress.status {
                case .accepted, .terminal: return progress
                case .retryable:
                    if let retry = progress.retryAtMilliseconds { try await wait(until: retry) }
                case .reserved, .dispatched: throw GatewayProbeError.attemptInFlight
                }
            }
            let beforeOAuth = try current()
            try database.checkProbeCandidate(candidateOperationID: operationID, trust: trust(phoneID),
                nowUnixMillis: beforeOAuth.wall, now: beforeOAuth.moment)
            let grant = try await tokens.token()
            // Reentrancy during OAuth or pacing must not preserve stale enrollment state or a stale deadline.
            while true {
                try running(); try Task.checkCancellation()
                let time = try current()
                if time.moment.milliseconds < nextSend { try await wait(until: nextSend); continue }
                break
            }
            // Refresh the bearer after pacing, then repeat pacing if another flight took the next slot.
            let freshBearer: FCMAccessToken
            do { freshBearer = try await tokens.accessToken(for: grant) }
            catch FCMError.tokenExpired { continue }
            catch FCMTokenSourceError.invalidated { continue }
            try running(); try Task.checkCancellation()
            let time = try current()
            if time.moment.milliseconds < nextSend { continue }
            let (next, overflow) = time.moment.milliseconds.addingReportingOverflow(policy.minimumSendIntervalMillis)
            guard !overflow else { throw GatewayDeliveryError.invalidClock }
            let snapshot = try trust(phoneID)
            let reservation = try database.reserveProbe(candidateOperationID: operationID, trust: snapshot,
                nowUnixMillis: time.wall, now: time.moment)
            do {
                let probe = try database.takeProbe(reservation, trust: snapshot, nowUnixMillis: time.wall, now: time.moment)
                nextSend = next
                let result = try await send(probe, freshBearer)
                try Task.checkCancellation()
                let outcome: GatewayProbeOutcome
                switch result {
                case .accepted: outcome = .accepted
                case .authenticationRequired:
                    await tokens.invalidate(grant)
                    try Task.checkCancellation()
                    outcome = .retry(minimumDelayMillis: backoff(reservation.number))
                case .retryable(let seconds): outcome = retry(seconds, attempt: reservation.number)
                case .validated, .registrationInvalid, .senderMismatch, .rejected: outcome = .terminal
                }
                try database.finishProbe(reservation, outcome: outcome, now: current().moment)
            } catch {
                // A lost response does not establish receipt. The original candidate remains the only retry scope.
                let retry = !Task.isCancelled && !stopped && (error as? FCMError) == .network
                try database.finishProbe(reservation, outcome: retry ? .retry(minimumDelayMillis: backoff(reservation.number)) : .terminal,
                    now: current().moment)
                if !retry { throw error }
            }
        }
    }

    private func backoff(_ attempt: Int) -> UInt64 {
        let base = min(policy.maximumRetryBackoffMillis, policy.retryBaseDelayMillis * (UInt64(1) << min(max(attempt - 1, 0), 31)))
        return min(policy.maximumRetryBackoffMillis, base + UInt64.random(in: 0...(base / 4)))
    }
    private func retry(_ seconds: TimeInterval, attempt: Int) -> GatewayProbeOutcome {
        let millis = (seconds * 1000).rounded(.up)
        guard seconds.isFinite, seconds >= 0, millis.isFinite, millis < Double(UInt64.max) else { return .terminal }
        return .retry(minimumDelayMillis: max(UInt64(millis), backoff(attempt)))
    }
    private func wait(until deadline: UInt64) async throws {
        let now = try current().moment.milliseconds
        if deadline > now { try await sleep(deadline - now) }
        try Task.checkCancellation()
    }
    var activeProbeCount: Int { flights.count }

    private func running() throws { guard !stopped else { throw GatewayDeliveryError.stopped } }
    private func current() throws -> Sample {
        let result = try sample()
        guard result.moment.epoch == lastMoment.epoch, result.moment.milliseconds >= lastMoment.milliseconds else {
            stopped = true
            for flight in flights.values { flight.task.cancel() }
            throw GatewayDeliveryError.invalidClock
        }
        lastMoment = result.moment
        return result
    }
    private func trust(_ phone: Data) throws -> GatewayCandidateTrust {
        guard let enrollment = enrollments[phone] else { throw GatewayDeliveryError.unknownEnrollment }
        return try GatewayCandidateTrust(ownerID: identity.ownerID, macID: identity.macID, accountID: identity.accountID,
            gatewayID: identity.gatewayID, lifecycleEpoch: identity.lifecycleEpoch, rootPublicKey: identity.rootPublicKey,
            active: active, revision: trustRevision, appliedControlRevision: database.head(), enrollment: enrollment)
    }
}
