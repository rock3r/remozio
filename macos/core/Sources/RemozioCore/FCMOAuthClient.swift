import Foundation

/// A process-local token lease. A continuous clock includes sleep and does not extend validity on wall-clock changes.
public struct FCMTokenLease: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    private let value: FCMAccessToken
    public let expiresAt: ContinuousClock.Instant
    init(value: FCMAccessToken, expiresAt: ContinuousClock.Instant) { self.value = value; self.expiresAt = expiresAt }
    public func accessToken() throws -> FCMAccessToken { try accessToken(at: .now) }
    func accessToken(at now: ContinuousClock.Instant) throws -> FCMAccessToken {
        guard now < expiresAt else { throw FCMError.tokenExpired }
        return value
    }
    public var description: String { "FCMTokenLease(redacted)" }
    public var debugDescription: String { description }
}

/// Makes one token request. Credential provisioning, caching, rotation and retry scheduling belong to its owner.
public struct FCMOAuthClient: Sendable {
    private let account: FCMServiceAccount
    private let transport: FCMHTTPTransport
    private let assertionLifetimeSeconds: UInt32

    public init(account: FCMServiceAccount, timeoutSeconds: TimeInterval = 30, assertionLifetimeSeconds: UInt32 = 300) throws {
        try self.init(account: account, transport: FCMHTTPTransport(timeoutSeconds: timeoutSeconds),
                      assertionLifetimeSeconds: assertionLifetimeSeconds)
    }
    init(account: FCMServiceAccount, transport: FCMHTTPTransport, assertionLifetimeSeconds: UInt32 = 300) throws {
        guard (1...3600).contains(assertionLifetimeSeconds) else { throw FCMError.invalidConfiguration }
        self.account = account; self.transport = transport; self.assertionLifetimeSeconds = assertionLifetimeSeconds
    }

    public func acquireToken() async throws -> FCMTokenLease {
        try Task.checkCancellation()
        let started = ContinuousClock.now
        let reply = try await transport.send(request(at: Date()))
        try Task.checkCancellation()
        return try Self.lease(reply, started: started, now: .now)
    }

    func request(at date: Date) throws -> URLRequest {
        let assertion = try account.assertion(at: date, lifetimeSeconds: assertionLifetimeSeconds)
        var request = URLRequest(url: URL(string: FCMServiceAccount.tokenEndpoint)!)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        // Compact base64url assertions contain no characters that need form escaping.
        request.httpBody = Data(("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=" + assertion).utf8)
        return request
    }

    static func lease(_ reply: FCMHTTPReply, started: ContinuousClock.Instant, now: ContinuousClock.Instant) throws -> FCMTokenLease {
        guard reply.body.count <= FCMHTTPTransport.maximumResponseBytes else { throw FCMError.responseTooLarge }
        guard reply.status == 200 else { throw FCMError.oauthRejected(httpStatus: reply.status) }
        guard let response = try? JSONDecoder().decode(Response.self, from: reply.body), response.token_type == "Bearer",
              (1...3600).contains(response.expires_in),
              response.scope == nil || response.scope == FCMServiceAccount.scope,
              let token = try? FCMAccessToken(response.access_token) else { throw FCMError.invalidResponse }
        // Start before signing and network I/O, so neither latency nor sleep extends the provider's lifetime.
        let lease = FCMTokenLease(value: token, expiresAt: started.advanced(by: .seconds(response.expires_in)))
        _ = try lease.accessToken(at: now)
        return lease
    }
    private struct Response: Decodable {
        let access_token: String
        let token_type: String
        let expires_in: Int
        let scope: String?
    }
}
