import Darwin
import Foundation
import RemozioMach
import XCTest
@testable import RemozioCore

final class CommandFrontendEndpointTests: XCTestCase {
    func testUnknownPrivateServiceReportsUnavailableWithoutRegistration() throws {
        let endpoint = try CommandFrontendEndpoint(serviceName: "dev.remozio.absent." + UUID().uuidString)
        defer { endpoint.close() }
        XCTAssertThrowsError(try endpoint.lookup()) { error in
            guard case CommandAuthorityEndpointError.unavailable = error else { return XCTFail("Unexpected error: \(error)") }
        }
    }
    func testLookupRejectsUnterminatedServiceNamesWithoutTruncationOrRights() {
        let size = remozio_frontend_service_name_capacity()
        let name = String(repeating: "x", count: size)
        XCTAssertThrowsError(try CommandFrontendEndpoint(serviceName: name))
        XCTAssertThrowsError(try CommandFrontendEndpoint(serviceName: "dev.remozio.bad\0service"))
        var port: mach_port_t = UInt32.max, unavailable = true
        let status = name.withCString { remozio_frontend_lookup_service($0, &port, &unavailable) }
        XCTAssertEqual(status, KERN_INVALID_ARGUMENT); XCTAssertEqual(port, 0); XCTAssertFalse(unavailable)
    }
}
