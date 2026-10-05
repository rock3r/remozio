import Foundation
import XCTest
import RemozioProtocol
@testable import RemozioCore

final class AuthorityCodePolicyTests: XCTestCase {
    private let limits = try! CBORLimits(maxBytes: 8192, maxDepth: 4, maxItems: 256)

    func testCompleteRoleCatalogRoundTripsInStableOrder() throws {
        let entries = try AuthorityCodeRole.allCases.reversed().map { try entry(role: $0, installed: .max, minimum: .max) }
        let policy = try AuthorityCodePolicy(entries: entries)
        XCTAssertEqual(policy.entries.map(\.role), AuthorityCodeRole.allCases)
        XCTAssertEqual(try AuthorityCodePolicy.decode(policy.bytes), policy)
        XCTAssertEqual(try policy.bytes, try AuthorityCodePolicy(entries: entries.reversed()).bytes)
        XCTAssertTrue(policy.entries.contains { $0.role == .commandFrontend })
        XCTAssertLessThan(try policy.bytes.count, AuthorityCodePolicy.maximumBytes)
    }

    func testMalformedOrNoncanonicalPolicyCannotBecomeRetainedState() throws {
        let policy = try AuthorityCodePolicy(entries: [entry(role: .authority), entry(role: .transport)])
        guard case .map(let fields) = try DeterministicCBOR.decode(policy.bytes, limits: limits),
              case .array(let entries) = fields[1], case .map(let entry) = entries[0] else { return XCTFail("bad fixture") }
        var invalid = [CBORValue.map([0: .unsigned(2), 1: .array(entries)]),
            .map([0: .unsigned(1), 1: .array(entries.reversed())]),
            .map([0: .unsigned(1), 1: .array([entries[0], entries[0]])]),
            .map([0: .unsigned(1), 1: .array([])]),
            .map([0: .unsigned(1), 1: .array(entries), 2: .null])]
        for (key, value) in [(UInt64(0), CBORValue.unsigned(99)), (6, .unsigned(2)), (3, .unsigned(0)),
                             (4, .unsigned(0)), (5, .bytes(Data(repeating: 1, count: 21)))] {
            var changed = entry; changed[key] = value
            invalid.append(.map([0: .unsigned(1), 1: .array([.map(changed)])]))
        }
        for value in invalid {
            XCTAssertThrowsError(try AuthorityCodePolicy.decode(DeterministicCBOR.encode(value, limits: limits))) {
                XCTAssertEqual($0 as? AuthorityCodePolicyError, .corruptData)
            }
        }
        XCTAssertThrowsError(try AuthorityCodePolicy.decode(Data(repeating: 0, count: 8193)))
    }

    func testIdentityAndGenerationBounds() throws {
        for team in ["", "ABCDEFGHI", "ABCDEFGHIJK", "abcdef1234", "ABCDEF123é"] {
            XCTAssertThrowsError(try entry(team: team))
        }
        for identifier in ["", String(repeating: "a", count: 256), "dev.remozio;other", "démo"] {
            XCTAssertThrowsError(try entry(identifier: identifier))
        }
        XCTAssertThrowsError(try entry(installed: 0))
        XCTAssertThrowsError(try entry(minimum: 0))
        XCTAssertThrowsError(try entry(installed: 1, minimum: 2))
        XCTAssertThrowsError(try AuthorityCodePolicy(entries: []))
        XCTAssertThrowsError(try AuthorityCodePolicy(entries: [entry(), entry()]))
    }

    func testInactiveRolesRetainIdentityAndMonotoneFloors() throws {
        let previous = try AuthorityCodePolicy(entries: [entry(installed: 4, minimum: 2)])
        let inactive = try AuthorityCodePolicy(entries: [entry(installed: 4, minimum: 3, active: false)])
        XCTAssertNoThrow(try inactive.requireSuccessor(of: previous))
        XCTAssertNoThrow(try AuthorityCodePolicy(entries: [entry(installed: 5, minimum: 3)]).requireSuccessor(of: inactive))
        let changes: [(AuthorityCodeEntry, AuthorityCodePolicyError)] = [
            (try entry(installed: 3, minimum: 2), .rollback),
            (try entry(installed: 5, minimum: 1), .rollback),
            (try entry(team: "ABCDEFGHIJ", installed: 5, minimum: 2), .identityChanged),
            (try entry(identifier: "dev.remozio.other", installed: 5, minimum: 2), .identityChanged),
            (try entry(role: .transport, installed: 5, minimum: 2), .removedRole),
        ]
        for (entry, error) in changes {
            XCTAssertThrowsError(try AuthorityCodePolicy(entries: [entry]).requireSuccessor(of: previous)) {
                XCTAssertEqual($0 as? AuthorityCodePolicyError, error)
            }
        }
    }

    func testStoredPolicyVersionsPreserveRoleTokensAndRejectIncompleteTokens() throws {
        let policy = try AuthorityCodePolicy(entries: AuthorityCodeRole.allCases.map { try entry(role: $0) })
        let revision = UUID()
        let legacy = try AuthorityCodePolicySnapshot.decodeStored(policy.bytes, revision: revision)
        XCTAssertEqual(Set(legacy.roleRevisions.keys), Set(AuthorityCodeRole.allCases))
        XCTAssertTrue(legacy.roleRevisions.values.allSatisfy { $0 == revision })
        XCTAssertEqual(try AuthorityCodePolicySnapshot.decodeStored(legacy.storedBytes, revision: revision), legacy)
        guard case .map(let fields) = try DeterministicCBOR.decode(legacy.storedBytes, limits: limits),
              case .map(let roles) = fields[2] else { return XCTFail("bad fixture") }
        var missing = roles; missing.removeValue(forKey: AuthorityCodeRole.transport.rawValue)
        var extra = roles; extra[99] = .bytes(Data(repeating: 1, count: 16))
        var malformed = roles; malformed[AuthorityCodeRole.transport.rawValue] = .bytes(Data(repeating: 1, count: 15))
        for roles in [missing, extra, malformed] {
            var changed = fields; changed[2] = .map(roles)
            XCTAssertThrowsError(try AuthorityCodePolicySnapshot.decodeStored(DeterministicCBOR.encode(.map(changed), limits: limits), revision: revision)) {
                XCTAssertEqual($0 as? AuthorityCodePolicyError, .corruptData)
            }
        }
        var unknown = fields; unknown[0] = .unsigned(3)
        XCTAssertThrowsError(try AuthorityCodePolicySnapshot.decodeStored(DeterministicCBOR.encode(.map(unknown), limits: limits), revision: revision))
    }

    private func entry(role: AuthorityCodeRole = .authority, team: String = "ABCDEF1234", identifier: String = "dev.remozio.authority",
                       installed: UInt64 = 1, minimum: UInt64 = 1, active: Bool = true) throws -> AuthorityCodeEntry {
        try AuthorityCodeEntry(role: role, teamID: team, identifier: identifier, installedGeneration: installed,
            minimumGeneration: minimum, codeDirectoryHash: Data(repeating: 7, count: 20), active: active)
    }
}
