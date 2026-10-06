import Darwin
import Foundation
import RemozioMach
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class CommandAncestryObservationTests: XCTestCase {
    private func process(_ pid: UInt32, parent: Int32, version: UInt32 = 7, uid: UInt32 = 501,
                         path: Data? = Data("/synthetic/program".utf8)) -> CommandAncestryObservation.Process {
        var token = audit_token_t()
        token.val = (0, uid, 0, uid, 0, pid, 0, version)
        return .init(token: token, parentPID: parent, path: path)
    }
    private var source: CommandAncestryObservation.Process { process(10, parent: 20) }
    private func chain(_ pid: pid_t) -> CommandAncestryObservation.Process {
        switch pid {
        case 10: source
        case 20: process(20, parent: 30, version: UInt32.max, uid: 0)
        case 30: process(30, parent: 0, path: nil)
        default: fatalError("Unexpected synthetic process")
        }
    }
    func testReapedProcessIsReportedAsExited() throws {
        let child = Foundation.Process()
        child.executableURL = URL(fileURLWithPath: "/usr/bin/true")
        child.environment = ["PATH": "/usr/bin:/bin"]
        try child.run()
        let pid = child.processIdentifier
        child.waitUntilExit()
        XCTAssertEqual(child.terminationStatus, 0)
        var token = audit_token_t(), missing = false
        XCTAssertNotEqual(remozio_pid_audit_token(pid, &token, &missing), KERN_SUCCESS)
        XCTAssertTrue(missing)
        XCTAssertThrowsError(try CommandAncestryObservation.sample(pid)) {
            XCTAssertEqual(($0 as? CommandAncestryObservation.Unavailable)?.reason, .exited)
        }
    }

    func testAuditLookupDoesNotReportLiveOrInvalidProcessAsMissing() throws {
        var token = audit_token_t(), missing = true
        XCTAssertEqual(remozio_pid_audit_token(getpid(), &token, &missing), KERN_SUCCESS)
        XCTAssertFalse(missing)
        XCTAssertEqual(audit_token_to_pid(token), getpid())
        let original = token
        missing = true
        XCTAssertEqual(remozio_pid_audit_token(0, &token, &missing), KERN_INVALID_ARGUMENT)
        XCTAssertFalse(missing)
        XCTAssertTrue(CommandAncestryObservation.sameToken(original, token))
    }

    func testCompleteChainPreservesKernelCounterBitsAndUnavailablePaths() throws {
        let value = try CommandAncestryObservation.capture(source: source.token, maximumEntries: 2, read: chain)
        XCTAssertEqual(value.completeness, .complete)
        XCTAssertEqual(value.reason, .none)
        XCTAssertEqual(value.entries.map(\.pid), [20, 30])
        XCTAssertEqual(value.entries.first?.pidVersion, UInt32.max)
        XCTAssertEqual(value.entries.first?.uid, 0)
        XCTAssertNil(value.entries.last?.executablePath)
    }
    func testDepthLimitKeepsOnlyTheVerifiedPrefix() throws {
        let value = try CommandAncestryObservation.capture(source: source.token, maximumEntries: 1, read: chain)
        XCTAssertEqual(value.entries.map(\.pid), [20])
        XCTAssertEqual(value.completeness, .partial)
        XCTAssertEqual(value.reason, .truncated)
        let empty = try CommandAncestryObservation.capture(source: source.token, maximumEntries: 0, read: chain)
        XCTAssertEqual(empty.completeness, .unavailable)
        XCTAssertEqual(empty.reason, .truncated)
        XCTAssertTrue(empty.entries.isEmpty)
    }
    func testLostParentOrPermissionFailureCannotInventAnEntry() throws {
        for reason: AncestryReason in [.exited, .permission, .unsupported] {
            let value = try CommandAncestryObservation.capture(source: source.token, maximumEntries: 8, read: { pid in
                if pid == 30 { throw CommandAncestryObservation.Unavailable(reason: reason) }
                return self.chain(pid)
            })
            XCTAssertEqual(value.entries.map(\.pid), [20])
            XCTAssertEqual(value.completeness, .partial)
            XCTAssertEqual(value.reason, reason)
            let unavailable = try CommandAncestryObservation.capture(source: source.token, maximumEntries: 8, read: { _ in
                throw CommandAncestryObservation.Unavailable(reason: reason)
            })
            XCTAssertEqual(unavailable.completeness, .unavailable)
            XCTAssertTrue(unavailable.entries.isEmpty)
        }
    }
    func testChangedParentLinkStopsBeforeAppendingTheNewParent() throws {
        var reads = 0
        let value = try CommandAncestryObservation.capture(source: source.token, maximumEntries: 8, read: { pid in
            if pid == 10 {
                reads += 1
                if reads == 2 { return self.process(10, parent: 40) }
            }
            return self.chain(pid)
        })
        XCTAssertTrue(value.entries.isEmpty)
        XCTAssertEqual(value.completeness, .unavailable)
        XCTAssertEqual(value.reason, .unsupported)
    }
    func testAncestorExecStopsWithThePreviouslyVerifiedPrefix() throws {
        var reads = 0
        let value = try CommandAncestryObservation.capture(source: source.token, maximumEntries: 8, read: { pid in
            if pid == 20 {
                reads += 1
                if reads == 2 { return self.process(20, parent: 30, version: 8) }
            }
            return self.chain(pid)
        })
        XCTAssertEqual(value.entries.map(\.pid), [20])
        XCTAssertEqual(value.completeness, .partial)
        XCTAssertEqual(value.reason, .exited)
    }
    func testCallerReplacementIsRejectedRatherThanDowngradedToPartial() throws {
        for replacementRead in [1, 2] {
            var reads = 0
            XCTAssertThrowsError(try CommandAncestryObservation.capture(source: source.token, maximumEntries: 8, read: { pid in
                if pid == 10 {
                    reads += 1
                    if reads == replacementRead { return self.process(10, parent: 20, version: 8) }
                }
                return self.chain(pid)
            })) { XCTAssertEqual($0 as? MachCommandCallerError, .wrongPeer) }
        }
    }
    func testCyclesAndCancellationCannotCreateCompleteAncestry() throws {
        let cycle = try CommandAncestryObservation.capture(source: source.token, maximumEntries: 8, read: { pid in
            pid == 20 ? self.process(20, parent: 10) : self.source
        })
        XCTAssertEqual(cycle.entries.map(\.pid), [20])
        XCTAssertEqual(cycle.reason, .unsupported)
        enum Cancelled: Error { case test }
        var checks = 0
        XCTAssertThrowsError(try CommandAncestryObservation.capture(source: source.token, maximumEntries: 8,
            checkCancellation: { checks += 1; if checks == 3 { throw Cancelled.test } }, read: chain)) {
            XCTAssertTrue($0 is Cancelled)
        }
    }
}
