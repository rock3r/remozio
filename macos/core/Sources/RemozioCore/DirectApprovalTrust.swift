import Foundation

/// A consistent protected-journal result. Empty peers means no eligible phone, so the host must stop listening.
/// Retain the revision with the listener and recheck it under the authority's serialization before using a channel.
public struct DirectApprovalTrust: Sendable {
    public let macID: Data
    public let accountID: Data
    public let revision: UUID
    public let peers: [DirectApprovalPeer]
    init(macID: Data, accountID: Data, revision: UUID, peers: [DirectApprovalPeer]) {
        self.macID = macID; self.accountID = accountID; self.revision = revision; self.peers = peers
    }
}
