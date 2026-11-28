import OSLog

/// Observes proved journal outcomes under the serialized request owner.
struct ReplayCapacityDiagnostics: Sendable {
    enum Counter: String, CaseIterable {
        case consumedRequests = "consumed_requests"
        case commandSubmissions = "command_submissions"

        func isCapacityRefusal(_ error: any Error) -> Bool {
            switch self {
            case .consumedRequests: error as? ConsumptionJournalError == .capacityExceeded
            case .commandSubmissions: error as? CommandSubmissionReplayError == .capacityExceeded
            }
        }
    }

    enum Band: Int64 {
        case warning = 80
        case nearLimit = 95
        case full = 100
    }

    struct Usage {
        let counter: Counter
        let count: Int64
        let limit: Int64

        var full: Bool { count >= limit }

        var band: Band? {
            if full { return .full }
            if count * 100 >= limit * Band.nearLimit.rawValue { return .nearLimit }
            if count * 100 >= limit * Band.warning.rawValue { return .warning }
            return nil
        }
    }

    private static let logger = Logger(subsystem: "dev.sebastiano.remozio.macos.authority", category: "replay-capacity")
    private var reported: [Counter: Band] = [:]
    private let report: @Sendable (Band, String) -> Void

    init(report: @escaping @Sendable (Band, String) -> Void = { band, message in
        if band == .full { ReplayCapacityDiagnostics.logger.error("\(message, privacy: .public)") }
        else { ReplayCapacityDiagnostics.logger.notice("\(message, privacy: .public)") }
    }) {
        self.report = report
    }

    mutating func observe(_ usage: Usage) {
        guard let band = usage.band, band.rawValue > (reported[usage.counter]?.rawValue ?? 0) else { return }
        reported[usage.counter] = band
        report(band, "permanent_replay_capacity counter=\(usage.counter.rawValue) count=\(usage.count) limit=\(usage.limit) band=\(band.rawValue)")
    }
}
