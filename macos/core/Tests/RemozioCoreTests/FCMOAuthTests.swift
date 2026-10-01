import Foundation
import Security
import Synchronization
@testable import RemozioCore
import XCTest

final class FCMOAuthTests: XCTestCase, @unchecked Sendable {
    private static let pem = Result { try generate(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]) }
    private static func generate(_ arguments: [String]) throws -> String {
        let process = Process(), pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl"); process.arguments = arguments
        process.standardOutput = pipe; process.standardError = FileHandle.nullDevice
        try process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0, data.count < 16384 else { throw FCMError.invalidCredentials }
        return String(decoding: data, as: UTF8.self)
    }
    private func json(_ overrides: [String: Any] = [:]) throws -> Data {
        var values: [String: Any] = ["type": "service_account", "token_uri": FCMServiceAccount.tokenEndpoint,
            "client_email": "fixture@fixture.iam.gserviceaccount.com", "private_key_id": "fixture-key", "private_key": try Self.pem.get()]
        values.merge(overrides) { _, new in new }
        return try JSONSerialization.data(withJSONObject: values)
    }
    private func account() throws -> FCMServiceAccount { try FCMServiceAccount(json: json()) }
    private func client(_ fixture: AnyClass = OAuthSuccess.self) throws -> FCMOAuthClient {
        try FCMOAuthClient(account: account(), transport: FCMHTTPTransport(timeoutSeconds: 5, protocolClasses: [fixture]))
    }
    private func decode(_ text: Substring) throws -> Data {
        var value = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        value += String(repeating: "=", count: (4 - value.count % 4) % 4)
        return try XCTUnwrap(Data(base64Encoded: value))
    }
    private func reply(_ text: String, status: Int = 200) -> FCMHTTPReply {
        FCMHTTPReply(status: status, retryAfter: nil, body: Data(text.utf8))
    }

    func testRequestContainsOnlyFixedScopeAudienceAndVerifiableRS256Assertion() throws {
        let account = try account(), request = try client().request(at: Date(timeIntervalSince1970: 1000.9))
        XCTAssertEqual(request.url?.absoluteString, "https://oauth2.googleapis.com/token")
        XCTAssertEqual(request.httpMethod, "POST")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/x-www-form-urlencoded")
        XCTAssertNil(request.value(forHTTPHeaderField: "Authorization"))
        let form = String(decoding: try XCTUnwrap(request.httpBody), as: UTF8.self)
        let prefix = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion="
        XCTAssertTrue(form.hasPrefix(prefix))
        let compact = form.dropFirst(prefix.count), parts = compact.split(separator: ".")
        XCTAssertEqual(parts.count, 3); XCTAssertFalse(compact.contains("=")); XCTAssertFalse(compact.contains("&"))
        let header = try JSONSerialization.jsonObject(with: decode(parts[0])) as? [String: String]
        XCTAssertEqual(header, ["alg": "RS256", "typ": "JWT", "kid": "fixture-key"])
        let claims = try XCTUnwrap(JSONSerialization.jsonObject(with: decode(parts[1])) as? [String: Any])
        XCTAssertEqual(Set(claims.keys), ["iss", "scope", "aud", "iat", "exp"])
        XCTAssertEqual(claims["iss"] as? String, "fixture@fixture.iam.gserviceaccount.com")
        XCTAssertEqual(claims["scope"] as? String, FCMServiceAccount.scope)
        XCTAssertEqual(claims["aud"] as? String, FCMServiceAccount.tokenEndpoint)
        XCTAssertEqual(claims["iat"] as? Int, 1000); XCTAssertEqual(claims["exp"] as? Int, 1300)
        var format = SecExternalFormat.formatUnknown, type = SecExternalItemType.itemTypePrivateKey
        var items: CFArray?
        XCTAssertEqual(SecItemImport(Data(try Self.pem.get().utf8) as CFData, nil, &format, &type, [], nil, nil, &items), errSecSuccess)
        let key = (try XCTUnwrap(items) as [AnyObject])[0] as! SecKey
        let publicKey = try XCTUnwrap(SecKeyCopyPublicKey(key)), signature = try decode(parts[2])
        let signed = Data((parts[0] + "." + parts[1]).utf8)
        XCTAssertTrue(SecKeyVerifySignature(publicKey, .rsaSignatureMessagePKCS1v15SHA256, signed as CFData, signature as CFData, nil))
        XCTAssertFalse(SecKeyVerifySignature(publicKey, .rsaSignatureMessagePKCS1v15SHA256, Data("tampered".utf8) as CFData, signature as CFData, nil))
        XCTAssertEqual(String(reflecting: account), "FCMServiceAccount(redacted)")
    }

    func testRejectsCredentialRedirectionWrongTypesAndMalformedKeyContainers() throws {
        let pem = try Self.pem.get()
        for fields: [String: Any] in [
            ["type": "authorized_user"], ["token_uri": "https://other.invalid/token"], ["token_uri": NSNull()],
            ["client_email": ""], ["client_email": "no-at-sign"], ["client_email": "injected\n@test"],
            ["private_key_id": ""], ["private_key_id": String(repeating: "a", count: 257)],
            ["private_key": "not a key"], ["private_key": pem + pem],
            ["private_key": pem.replacingOccurrences(of: "BEGIN PRIVATE", with: "BEGIN ENCRYPTED PRIVATE")],
            ["private_key": "-----BEGIN PRIVATE KEY-----\n!!!\n-----END PRIVATE KEY-----"],
            ["private_key": String(repeating: "x", count: 16385)], ["private_key": true],
        ] {
            XCTAssertThrowsError(try FCMServiceAccount(json: json(fields))) { XCTAssertEqual($0 as? FCMError, .invalidCredentials) }
        }
        for data in [Data(), Data("{}".utf8), Data(repeating: 32, count: 65537)] {
            XCTAssertThrowsError(try FCMServiceAccount(json: data)) { XCTAssertEqual($0 as? FCMError, .invalidCredentials) }
        }
        let ignored = try FCMServiceAccount(json: json(["scope": "arbitrary", "sub": "someone", "universe_domain": "other.invalid"]))
        XCTAssertEqual(try ignored.assertion(at: Date(timeIntervalSince1970: 1000), lifetimeSeconds: 300),
                       try account().assertion(at: Date(timeIntervalSince1970: 1000), lifetimeSeconds: 300))
    }

    func testRejectsWeakRSAAndNonRSAKeys() throws {
        for args in [["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:1024"],
                     ["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"]] {
            let pem = try Self.generate(args)
            let credentials = try json(["private_key": pem])
            XCTAssertThrowsError(try FCMServiceAccount(json: credentials)) {
                XCTAssertEqual($0 as? FCMError, .invalidCredentials)
            }
        }
    }

    func testBoundsAssertionLifetimeAndWallClockBeforeSigning() throws {
        let account = try account()
        for seconds in [-1.0, .infinity, -.infinity, .nan, 253_402_297_200] {
            XCTAssertThrowsError(try account.assertion(at: Date(timeIntervalSince1970: seconds), lifetimeSeconds: 300)) {
                XCTAssertEqual($0 as? FCMError, .invalidTime)
            }
        }
        for lifetime: UInt32 in [0, 3601, .max] {
            XCTAssertThrowsError(try FCMOAuthClient(account: account, assertionLifetimeSeconds: lifetime))
            XCTAssertThrowsError(try account.assertion(at: Date(), lifetimeSeconds: lifetime))
        }
        XCTAssertNoThrow(try account.assertion(at: Date(), lifetimeSeconds: 3600))
    }

    func testConcurrentAssertionsKeepNativeKeyInsideItsLock() async throws {
        let account = try account(), now = Date(timeIntervalSince1970: 1000)
        let expected = try account.assertion(at: now, lifetimeSeconds: 300)
        let values = try await withThrowingTaskGroup(of: String.self) { group in
            for _ in 0..<16 { group.addTask { try account.assertion(at: now, lifetimeSeconds: 300) } }
            var values: [String] = []
            for try await value in group { values.append(value) }
            return values
        }
        XCTAssertEqual(values.count, 16); XCTAssertTrue(values.allSatisfy { $0 == expected })
    }

    func testAcquiresTokenThroughInterceptedNativeHTTP() async throws {
        let started = ContinuousClock.now
        let lease = try await client().acquireToken()
        XCTAssertNoThrow(try lease.accessToken())
        XCTAssertGreaterThan(lease.expiresAt, started)
        XCTAssertLessThanOrEqual(lease.expiresAt, ContinuousClock.now.advanced(by: .seconds(3600)))
        XCTAssertEqual(String(reflecting: lease), "FCMTokenLease(redacted)")
        XCTAssertEqual(String(reflecting: try lease.accessToken()), "FCMAccessToken(redacted)")
    }

    func testRejectsMalformedOrOverbroadTokenResponses() throws {
        let now = ContinuousClock.now
        for text in ["{}", "not JSON", #"{"access_token":"x","token_type":"Basic","expires_in":3600}"#,
                     #"{"access_token":"","token_type":"Bearer","expires_in":3600}"#,
                     #"{"access_token":"x\ny","token_type":"Bearer","expires_in":3600}"#,
                     #"{"access_token":"x","token_type":"Bearer","expires_in":true}"#,
                     #"{"access_token":"x","token_type":"Bearer","expires_in":1.5}"#,
                     #"{"access_token":"x","token_type":"Bearer","expires_in":"3600"}"#,
                     #"{"access_token":"x","token_type":"Bearer","expires_in":0}"#,
                     #"{"access_token":"x","token_type":"Bearer","expires_in":-1}"#,
                     #"{"access_token":"x","token_type":"Bearer","expires_in":3601}"#,
                     #"{"access_token":"x","token_type":"Bearer","expires_in":999999999999999999999999}"#,
                     #"{"access_token":"x","token_type":"Bearer","expires_in":3600,"scope":"other"}"#] {
            XCTAssertThrowsError(try FCMOAuthClient.lease(reply(text), started: now, now: now)) {
                XCTAssertEqual($0 as? FCMError, .invalidResponse)
            }
        }
        XCTAssertThrowsError(try FCMOAuthClient.lease(FCMHTTPReply(status: 200, retryAfter: nil, body: Data(repeating: 32, count: 65537)), started: now, now: now)) {
            XCTAssertEqual($0 as? FCMError, .responseTooLarge)
        }
    }

    func testLeaseAccountsForRequestLatencyAndExpiresAtExactBoundary() throws {
        let start = ContinuousClock.now, response = reply(OAuthSuccess.body)
        let lease = try FCMOAuthClient.lease(response, started: start, now: start.advanced(by: .seconds(3599)))
        XCTAssertNoThrow(try lease.accessToken(at: start.advanced(by: .seconds(3599))))
        XCTAssertThrowsError(try lease.accessToken(at: start.advanced(by: .seconds(3600)))) {
            XCTAssertEqual($0 as? FCMError, .tokenExpired)
        }
        XCTAssertThrowsError(try FCMOAuthClient.lease(response, started: start, now: start.advanced(by: .seconds(3600)))) {
            XCTAssertEqual($0 as? FCMError, .tokenExpired)
        }
    }

    func testProviderErrorsExposeStatusWithoutResponseSecrets() throws {
        let now = ContinuousClock.now
        for status in [301, 307, 400, 401, 403, 429, 500, 503] {
            XCTAssertThrowsError(try FCMOAuthClient.lease(reply("synthetic-secret", status: status), started: now, now: now)) {
                XCTAssertEqual($0 as? FCMError, .oauthRejected(httpStatus: status))
                XCTAssertFalse(String(reflecting: $0).contains("synthetic-secret"))
            }
        }
    }

    func testTransportRefusesRedirectsAndBoundsAndRedactsFailures() async throws {
        let redirectsBefore = OAuthFixtureProtocol.requests.withLock { $0["redirect-target", default: 0] }
        for (fixture, expected): (AnyClass, FCMError) in [(OAuthRedirect.self, .oauthRejected(httpStatus: 307)),
            (OAuthLarge.self, .responseTooLarge), (OAuthNetworkFailure.self, .network)] {
            do { _ = try await client(fixture).acquireToken(); XCTFail("Expected failure") }
            catch { XCTAssertEqual(error as? FCMError, expected) }
        }
        XCTAssertEqual(OAuthFixtureProtocol.requests.withLock { $0["redirect-target", default: 0] }, redirectsBefore)
    }

    func testCancellationStopsActiveTokenRequestWithoutRetry() async throws {
        let client = try client(OAuthHang.self)
        let before = OAuthFixtureProtocol.requests.withLock { $0["hang", default: 0] }
        let task = Task { try await client.acquireToken() }
        defer { task.cancel() }
        for _ in 0..<100 {
            if OAuthFixtureProtocol.requests.withLock({ $0["hang", default: 0] }) > before { break }
            try await Task.sleep(for: .milliseconds(10))
        }
        XCTAssertEqual(OAuthFixtureProtocol.requests.withLock { $0["hang", default: 0] }, before + 1)
        task.cancel()
        do { _ = try await task.value; XCTFail("Expected cancellation") }
        catch { XCTAssertTrue(error is CancellationError) }
    }
}

private class OAuthFixtureProtocol: URLProtocol, @unchecked Sendable {
    static let requests = Mutex<[String: Int]>([:])
    class var scenario: String { "success" }
    class var body: String { #"{"access_token":"synthetic-oauth","token_type":"Bearer","expires_in":3600}"# }
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let scenario = type(of: self).scenario, url = request.url!
        Self.requests.withLock { $0[url.host == "oauth2.googleapis.com" ? scenario : "redirect-target", default: 0] += 1 }
        if scenario == "hang" { return }
        if scenario == "network" {
            client?.urlProtocol(self, didFailWithError: NSError(domain: "synthetic-secret", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "synthetic-secret"])); return
        }
        if scenario == "redirect" {
            let target = URL(string: "https://redirect-target.invalid/")!
            let response = HTTPURLResponse(url: url, statusCode: 307, httpVersion: "HTTP/1.1", headerFields: ["Location": target.absoluteString])!
            client?.urlProtocol(self, wasRedirectedTo: URLRequest(url: target), redirectResponse: response)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocolDidFinishLoading(self); return
        }
        client?.urlProtocol(self, didReceive: HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: scenario == "large" ? Data(repeating: 32, count: 65537) : Data(Self.body.utf8))
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}
private final class OAuthSuccess: OAuthFixtureProtocol, @unchecked Sendable {}
private final class OAuthRedirect: OAuthFixtureProtocol, @unchecked Sendable { override class var scenario: String { "redirect" } }
private final class OAuthLarge: OAuthFixtureProtocol, @unchecked Sendable { override class var scenario: String { "large" } }
private final class OAuthNetworkFailure: OAuthFixtureProtocol, @unchecked Sendable { override class var scenario: String { "network" } }
private final class OAuthHang: OAuthFixtureProtocol, @unchecked Sendable { override class var scenario: String { "hang" } }
