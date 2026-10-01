import Foundation

struct FCMHTTPReply: Sendable {
    let status: Int
    let retryAfter: String?
    let body: Data
}

/// Each attempt owns its session, so cancellation and an oversized response cancel only that attempt.
struct FCMHTTPTransport: Sendable {
    static let maximumResponseBytes = 65536
    let timeoutSeconds: TimeInterval
    let protocolClasses: [AnyClass]?

    init(timeoutSeconds: TimeInterval, protocolClasses: [AnyClass]? = nil) throws {
        guard timeoutSeconds.isFinite, timeoutSeconds > 0, timeoutSeconds <= 120 else { throw FCMError.invalidConfiguration }
        self.timeoutSeconds = timeoutSeconds; self.protocolClasses = protocolClasses
    }

    func send(_ request: URLRequest) async throws -> FCMHTTPReply {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.urlCache = nil; configuration.urlCredentialStorage = nil; configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = timeoutSeconds
        configuration.timeoutIntervalForResource = timeoutSeconds
        configuration.waitsForConnectivity = false
        if let protocolClasses { configuration.protocolClasses = protocolClasses }
        let session = URLSession(configuration: configuration, delegate: NoRedirects(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        do {
            return try await withTaskCancellationHandler {
                try Task.checkCancellation()
                let (bytes, response) = try await session.bytes(for: request)
                guard let response = response as? HTTPURLResponse else { throw FCMError.invalidResponse }
                guard response.expectedContentLength <= Int64(Self.maximumResponseBytes) else { throw FCMError.responseTooLarge }
                var body = Data()
                for try await byte in bytes {
                    try Task.checkCancellation()
                    guard body.count < Self.maximumResponseBytes else { throw FCMError.responseTooLarge }
                    body.append(byte)
                }
                try Task.checkCancellation()
                return FCMHTTPReply(status: response.statusCode, retryAfter: response.value(forHTTPHeaderField: "Retry-After"), body: body)
            } onCancel: { session.invalidateAndCancel() }
        } catch {
            if Task.isCancelled || (error as? URLError)?.code == .cancelled { throw CancellationError() }
            if let known = error as? FCMError { throw known }
            throw FCMError.network // Do not expose provider bodies, tokens or URLSession diagnostics.
        }
    }

    private final class NoRedirects: NSObject, URLSessionTaskDelegate, Sendable {
        func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                        newRequest request: URLRequest, completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
            completionHandler(nil)
        }
    }
}
