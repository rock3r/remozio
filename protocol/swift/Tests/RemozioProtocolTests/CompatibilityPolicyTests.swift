import Foundation
import XCTest
@testable import RemozioProtocol

final class CompatibilityPolicyTests: XCTestCase {
    private let a = UUID(uuidString: "00000000-0000-0000-0000-000000000001")!
    private let b = UUID(uuidString: "00000000-0000-0000-0000-000000000002")!
    private let c = UUID(uuidString: "00000000-0000-0000-0000-000000000003")!

    func testEnvelopeIntersectionAndTrustedFloor() throws {
        XCTAssertEqual(try CompatibilityPolicy.envelopeVersion(local: [1, 3, 5], peer: [1, 2, 3], trustedMinimum: 1), 3)
        XCTAssertEqual(try CompatibilityPolicy.envelopeVersion(local: [1, 3], peer: [1], trustedMinimum: 1), 1)
        XCTAssertThrowsError(try CompatibilityPolicy.envelopeVersion(local: [1, 3], peer: [1], trustedMinimum: 2)) { error in
            XCTAssertEqual(error as? CompatibilityError, .noSafeEnvelopeVersion)
        }
        XCTAssertThrowsError(try CompatibilityPolicy.envelopeVersion(local: [1], peer: [2], trustedMinimum: 1))
        XCTAssertThrowsError(try CompatibilityPolicy.envelopeVersion(local: [1], peer: [1], trustedMinimum: 0))
    }

    func testMostReachableContractThenNewestTie() throws {
        let old = try contract(1)
        let new = try contract(2)
        let all = capabilities([old, new])
        let phones = [a: all, b: capabilities([old]), c: capabilities([old])]
        let result = try select(authority: all, phones: phones, allowed: [old, new])
        XCTAssertEqual(result.contract, old)
        XCTAssertEqual(result.eligibleEnrollments, [a, b, c])
        let tie = try select(authority: all, phones: [a: all, b: all], allowed: [old, new])
        XCTAssertEqual(tie.contract, new)
        XCTAssertEqual(tie.eligibleEnrollments, [a, b])
    }

    func testSecurityPolicyAndFeaturesExcludeMorePopularOldContract() throws {
        let old = try contract(1)
        let new = try contract(2)
        let all = capabilities([old, new])
        let phones = [a: all, b: capabilities([old]), c: capabilities([old])]
        let result = try select(authority: all, phones: phones, allowed: [new])
        XCTAssertEqual(result.contract, new)
        XCTAssertEqual(result.eligibleEnrollments, [a])
        let missingFeature = ContractCapabilities(contracts: [new: []])
        XCTAssertThrowsError(try select(authority: all, phones: [a: missingFeature], allowed: [new]))
        XCTAssertThrowsError(try select(authority: missingFeature, phones: [a: all], allowed: [new]))
    }

    func testRequestKindsAndSchemaVersionsStaySeparate() throws {
        let schema1 = try contract(1)
        let schema2 = try contract(1, schema: 2)
        let firewall = try RequestContract(requestKind: .littleSnitch, wireVersion: 9, schemaVersion: 9)
        let all = capabilities([schema1, schema2, firewall])
        let result = try select(authority: all, phones: [a: all], allowed: [schema1, schema2, firewall])
        XCTAssertEqual(result.contract, schema2)
        XCTAssertThrowsError(try select(authority: all, phones: [a: capabilities([firewall])], allowed: [firewall]))
        XCTAssertThrowsError(try select(authority: all, phones: [:], allowed: [schema1]))
        XCTAssertThrowsError(try RequestContract(requestKind: .command, wireVersion: 0, schemaVersion: 1))
        XCTAssertThrowsError(try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 0))
    }

    private func contract(_ wire: UInt64, schema: UInt64 = 1) throws -> RequestContract {
        try RequestContract(requestKind: .command, wireVersion: wire, schemaVersion: schema)
    }
    private func capabilities(_ contracts: [RequestContract]) -> ContractCapabilities {
        ContractCapabilities(contracts: Dictionary(uniqueKeysWithValues: contracts.map { ($0, Set<UInt64>([7])) }))
    }
    private func select(authority: ContractCapabilities, phones: [UUID: ContractCapabilities], allowed: Set<RequestContract>) throws -> ContractSelection {
        try CompatibilityPolicy.requestContract(requestKind: .command, authority: authority, authorizedEnrollments: phones,
                                                trustedAllowedContracts: allowed, requiredFeatures: [7])
    }
}
