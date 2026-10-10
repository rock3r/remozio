import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class WakeStartupConfigurationTests: XCTestCase {
    private func id(_ n: UInt8, count: Int = 16) -> Data { Data(repeating: n, count: count) }
    private func root() throws -> AuthorityWakeStartupConfiguration {
        let key = P256.Signing.PrivateKey().publicKey.x963Representation
        let service = try AuthorityServiceConfiguration(macID: id(1), accountID: id(2), journalDirectory: "/Library/Remozio/journal",
            serviceName: "dev.remozio.authority", teamID: "TEAMID1234", transportIdentifier: "dev.remozio.transport",
            transportHashes: [id(3, count: 20)], transportUID: 401, maximumPayloadBytes: 4096, continuityDirectory: "/Library/Remozio/continuity")
        let request = try AuthorityRequestStartupConfiguration(service: service, keyRecordPath: "/Library/Remozio/root/key.cbor", authorityPublicKey: key)
        let registration = try GatewayRegistrationIdentity(ownerID: id(3), macID: id(1), accountID: id(2), gatewayID: id(4),
            lifecycleEpoch: id(5), rootPublicKey: key)
        return try .init(request: request, registration: registration, gatewayServiceName: "dev.remozio.gateway.root", gatewayUID: 402,
            teamID: "TEAMID1234", gatewayIdentifier: "dev.remozio.gateway", gatewayHashes: [id(4, count: 20)])
    }
    private func transport(owner: UInt32 = 501, mac: UInt8 = 1) throws -> ApprovalTransportConfiguration {
        try .init(macID: id(mac), accountID: id(2), ownerUID: owner, serviceUID: 401, authorityServiceName: "dev.remozio.authority",
            teamID: "TEAMID1234", authorityIdentifier: "dev.remozio.authority", authorityHashes: [id(3, count: 20)],
            identityReference: Data([1]), identityPublicKeyInfo: P256.Signing.PrivateKey().publicKey.derRepresentation)
    }
    private func wake() throws -> GatewayWakeSignerConfiguration {
        try .init(binding: GatewaySubmissionBinding(ownerID: id(3), macID: id(1), accountID: id(2), gatewayID: id(4), lifecycleEpoch: id(5)),
            credentialID: id(6), transportUID: 401, ownerUID: 501, gatewayUID: 402, serviceName: "dev.remozio.gateway.wake", teamID: "TEAMID1234",
            gatewayIdentifier: "dev.remozio.gateway", gatewayHashes: [id(4, count: 20)], custody: .protectedFile,
            keyRecordPath: "/Library/Remozio/transport/wake.cbor", publicKey: P256.Signing.PrivateKey().publicKey.x963Representation)
    }
    func testRootCanonicalConfigurationPinsHardwareIdentityScopeAndBoundedLease() throws {
        let original = try root(), decoded = try AuthorityWakeStartupConfiguration.decode(original.canonicalBytes)
        XCTAssertEqual(decoded.canonicalBytes, original.canonicalBytes)
        XCTAssertEqual(decoded.registration.rootPublicKey, decoded.request.authorityPublicKey)
        XCTAssertEqual(decoded.gatewayPolicy.expectedUserID, 402)
        XCTAssertEqual(decoded.leaseMilliseconds, 10_000); XCTAssertEqual(decoded.pollMilliseconds, 1000)
        let limits = try CBORLimits(maxBytes: 65_536, maxDepth: 3, maxItems: 128)
        guard case .map(let fields) = try DeterministicCBOR.decode(original.canonicalBytes, limits: limits) else { return XCTFail() }
        for (field, value): (UInt64, CBORValue) in [(0, .unsigned(2)), (4, .unsigned(401)), (8, .unsigned(0)),
            (8, .unsigned(60_001)), (9, .unsigned(5001)), (10, .unsigned(5001)), (11, .null)] {
            var changed = fields; changed[field] = value
            XCTAssertThrowsError(try AuthorityWakeStartupConfiguration.decode(DeterministicCBOR.encode(.map(changed), limits: limits)))
        }
        let other = try GatewayRegistrationIdentity(ownerID: id(3), macID: id(1), accountID: id(2), gatewayID: id(4), lifecycleEpoch: id(5),
            rootPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation)
        var changed = fields; changed[2] = .bytes(try other.encode())
        XCTAssertThrowsError(try AuthorityWakeStartupConfiguration.decode(DeterministicCBOR.encode(.map(changed), limits: limits)))
    }
    func testTransportCanonicalCompositionRejectsWrongMachineOrAccountOwner() throws {
        let transport = try transport(), wake = try wake(), original = try TransportWakeStartupConfiguration(transport: transport, wake: wake, pollMilliseconds: 250)
        XCTAssertEqual(try TransportWakeStartupConfiguration.decode(original.canonicalBytes).canonicalBytes, original.canonicalBytes)
        XCTAssertThrowsError(try TransportWakeStartupConfiguration(transport: self.transport(mac: 9), wake: wake))
        XCTAssertThrowsError(try TransportWakeStartupConfiguration(transport: self.transport(owner: 502), wake: wake))
        for interval: UInt64 in [0, 99, 60_001, UInt64.max] {
            XCTAssertThrowsError(try TransportWakeStartupConfiguration(transport: transport, wake: wake, pollMilliseconds: interval))
        }
        let limits = try CBORLimits(maxBytes: 65_536, maxDepth: 3, maxItems: 128)
        guard case .map(var fields) = try DeterministicCBOR.decode(original.canonicalBytes, limits: limits) else { return XCTFail() }
        fields[4] = .unsigned(1)
        XCTAssertThrowsError(try TransportWakeStartupConfiguration.decode(DeterministicCBOR.encode(.map(fields), limits: limits)))
    }
    func testNormalAccountCannotOpenRootServiceOrReadPrivateStartupInputs() throws {
        guard getuid() != 0, geteuid() != 0 else { throw XCTSkip("Requires an unprivileged fixture") }
        XCTAssertThrowsError(try AuthorityWakeStartupConfiguration.load(path: "/Library/Remozio/root/startup.cbor"))
        XCTAssertThrowsError(try AuthorityWakeService.open(configuration: root(), routing: {
            XCTFail("Wrong account reached presence")
            throw AuthorityWakePublisherError.closed
        }, reconcileExpired: { _ in XCTFail("Wrong account reached request cleanup") })) {
            XCTAssertEqual($0 as? GatewayServiceError, .wrongAccount)
        }
    }
}
