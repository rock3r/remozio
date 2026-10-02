import Foundation

/// A bounded local receipt page. Gaps are possible because the gateway need not receive every root control.
public struct GatewayControlHistoryPage: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let registration: GatewayRegistrationIdentity
    public let afterRevision: UInt64
    public let throughRevision: UInt64
    public let records: [GatewayControlReceipt]
    public let hasMore: Bool
    /// True only if this page covers the entire requested range without a missing revision.
    public var coversRequestedRange: Bool {
        guard !hasMore, records.last?.revision == throughRevision else { return false }
        var previous = afterRevision
        for record in records {
            guard previous < UInt64.max, record.revision == previous + 1 else { return false }
            previous = record.revision
        }
        return true
    }
    public var description: String { "GatewayControlHistoryPage(redacted)" }
    public var debugDescription: String { description }
}

/// Signed transport bytes, not verified history.
public struct GatewayControlHistoryReply: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let canonicalPayload: Data
    public let signature: Data
    public init(canonicalPayload: Data, signature: Data) { self.canonicalPayload = canonicalPayload; self.signature = signature }
    public var description: String { "GatewayControlHistoryReply(redacted)" }
    public var debugDescription: String { description }
}

/// Fresh gateway evidence with independently checked root receipts. It grants no authority or counter change.
public struct VerifiedGatewayControlHistory: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let page: GatewayControlHistoryPage
    public let receivedAt: AuthorityMoment
    let queryOwnerID: UUID
    init(page: GatewayControlHistoryPage, receivedAt: AuthorityMoment, queryOwnerID: UUID) {
        self.page = page; self.receivedAt = receivedAt; self.queryOwnerID = queryOwnerID
    }
    public var description: String { "VerifiedGatewayControlHistory(redacted)" }
    public var debugDescription: String { description }
}
