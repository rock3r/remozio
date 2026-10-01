import Foundation

public enum FCMError: Error, Equatable { case invalidConfiguration, invalidToken, invalidWake, responseTooLarge, invalidResponse, network }

/// Delivery credentials only. This token confers no Remozio approval authority.
public struct FCMAccessToken: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    fileprivate let value: String
    public init(_ value: String) throws {
        guard !value.isEmpty, value.utf8.count <= 16384, value.utf8.allSatisfy({ (33...126).contains($0) }) else {
            throw FCMError.invalidToken
        }
        self.value = value
    }
    public var description: String { "FCMAccessToken(redacted)" }
    public var debugDescription: String { description }
}

public enum FCMPriority: String, Sendable { case normal = "NORMAL", high = "HIGH" }

/// The caller supplies an opaque random delivery identifier, never a request body or credential.
public struct FCMWake: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    fileprivate let registrationToken: String
    public let identifier: Data
    public let ttlSeconds: UInt32
    public let priority: FCMPriority
    public init(registrationToken: String, identifier: Data, ttlSeconds: UInt32, priority: FCMPriority) throws {
        guard !registrationToken.isEmpty, registrationToken.utf8.count <= 16384,
              registrationToken.utf8.allSatisfy({ (33...126).contains($0) }), identifier.count == 32,
              ttlSeconds <= 2_419_200 else { throw FCMError.invalidWake }
        self.registrationToken = registrationToken; self.identifier = identifier
        self.ttlSeconds = ttlSeconds; self.priority = priority
    }
    public var description: String { "FCMWake(redacted)" }
    public var debugDescription: String { description }
}

public enum FCMDeliveryResult: Equatable, Sendable {
    case accepted, validated
    case registrationInvalid, senderMismatch, authenticationRequired
    /// A lower bound only. The coordinator applies backoff, jitter, current routing and actual request expiry.
    case retryable(minimumDelaySeconds: TimeInterval)
    case rejected(httpStatus: Int)
}

/// A single provider attempt. The owner checks enrollment, routing, token freshness and expiry before each call.
/// It neither retries nor removes enrollment keys. Provider acceptance is not device delivery.
public struct FCMWakeSender: Sendable {
    private let project: String
    private let packageName: String
    private let transport: FCMHTTPTransport

    public init(project: String, packageName: String, timeoutSeconds: TimeInterval = 30) throws {
        try self.init(project: project, packageName: packageName, transport: FCMHTTPTransport(timeoutSeconds: timeoutSeconds))
    }
    init(project: String, packageName: String, transport: FCMHTTPTransport) throws {
        let pathCharacters = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.:".utf8)
        let packageCharacters = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.".utf8)
        guard !project.isEmpty, project != ".", project != "..", project.utf8.count <= 128, project.utf8.allSatisfy(pathCharacters.contains),
              !packageName.isEmpty, packageName.utf8.count <= 255, packageName.utf8.allSatisfy(packageCharacters.contains) else {
            throw FCMError.invalidConfiguration
        }
        self.project = project; self.packageName = packageName; self.transport = transport
    }

    public func send(_ wake: FCMWake, accessToken: FCMAccessToken, validateOnly: Bool = false) async throws -> FCMDeliveryResult {
        try Task.checkCancellation()
        let reply = try await transport.send(request(wake, accessToken: accessToken, validateOnly: validateOnly))
        try Task.checkCancellation()
        return try classify(reply, validateOnly: validateOnly, now: Date())
    }

    func request(_ wake: FCMWake, accessToken: FCMAccessToken, validateOnly: Bool) throws -> URLRequest {
        let url = URL(string: "https://fcm.googleapis.com/v1/projects/\(project)/messages:send")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("Bearer " + accessToken.value, forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: [
            "validate_only": validateOnly,
            "message": ["token": wake.registrationToken,
                "data": ["wake_v1": wake.identifier.base64EncodedString()],
                "android": ["priority": wake.priority.rawValue, "ttl": "\(wake.ttlSeconds)s", "restricted_package_name": packageName]],
        ], options: [.sortedKeys])
        return request
    }

    func classify(_ reply: FCMHTTPReply, validateOnly: Bool, now: Date) throws -> FCMDeliveryResult {
        guard reply.body.count <= FCMHTTPTransport.maximumResponseBytes else { throw FCMError.responseTooLarge }
        if reply.status == 200 {
            guard let response = try? JSONDecoder().decode(Success.self, from: reply.body),
                  response.name.hasPrefix("projects/\(project)/messages/"),
                  response.name.utf8.count > "projects/\(project)/messages/".utf8.count,
                  response.name.utf8.count <= 2048, response.name.utf8.allSatisfy({ (33...126).contains($0) }) else {
                throw FCMError.invalidResponse
            }
            return validateOnly ? .validated : .accepted
        }
        let failure = try? JSONDecoder().decode(Failure.self, from: reply.body)
        let codes = failure?.error.code == reply.status ? failure?.error.details?.compactMap {
            $0.type == "type.googleapis.com/google.firebase.fcm.v1.FcmError" ? $0.errorCode : nil
        } ?? [] : []
        if reply.status == 404, codes == ["UNREGISTERED"] { return .registrationInvalid }
        if reply.status == 403, codes == ["SENDER_ID_MISMATCH"] { return .senderMismatch }
        if reply.status == 401 { return .authenticationRequired }
        if [429, 500, 503].contains(reply.status) {
            return .retryable(minimumDelaySeconds: max(reply.status == 429 ? 60 : 1, retryDelay(reply.retryAfter, now: now) ?? 0))
        }
        return .rejected(httpStatus: reply.status)
    }

    private func retryDelay(_ header: String?, now: Date) -> TimeInterval? {
        guard let header else { return nil }
        let value = header.trimmingCharacters(in: .whitespaces)
        if !value.isEmpty, value.utf8.allSatisfy({ (48...57).contains($0) }) {
            guard let seconds = UInt64(value) else { return .greatestFiniteMagnitude }
            let interval = Double(seconds)
            return seconds > 9_007_199_254_740_992 ? interval.nextUp : interval
        }
        guard value.utf8.count <= 128 else { return nil }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.isLenient = false
        for format in ["EEE, dd MMM yyyy HH:mm:ss 'GMT'", "EEEE, dd-MMM-yy HH:mm:ss 'GMT'", "EEE MMM d HH:mm:ss yyyy"] {
            formatter.dateFormat = format
            if let date = formatter.date(from: value) { return max(0, date.timeIntervalSince(now)) }
        }
        return nil
    }

    private struct Success: Decodable { let name: String }
    private struct Failure: Decodable {
        struct Detail: Decodable {
            let type: String?
            let errorCode: String?
            enum CodingKeys: String, CodingKey { case type = "@type", errorCode }
        }
        struct Body: Decodable { let code: Int; let details: [Detail]? }
        let error: Body
    }
}
