import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class RuntimeJobRegistrationTests: XCTestCase {
    private struct LostReply: Error {}
    private func job() throws -> InstalledAccountJobManifest {
        try .init(accountID: Data(repeating: 1, count: 16), role: .authority, executionUID: 0,
            userName: "root", bundlePath: MachineBootstrap.bundlePath)
    }
    private func output(_ job: InstalledAccountJobManifest) -> String {
        "system/\(job.declaration.label) = {\n\tpath = \(job.path)\n\ttype = LaunchDaemon\n\tstate = waiting\n\tprogram = \(job.executablePath)\n\targuments = {\n"
            + job.arguments.map { "\t\t" + $0 + "\n" }.joined() + "\t}\n\tenvironment = {\n\t\tEXAMPLE => synthetic\n\t}\n}\n"
    }
    func testOperationalObservationMatchesOnlyTheExactLoadedProgramArgumentsAndSourcePath() throws {
        let job = try job(), original = output(job), target = "system/" + job.declaration.label
        XCTAssertTrue(try LaunchdJobObservation.decode(Data(original.utf8), target: target).matches(job))
        for changed in [original.replacingOccurrences(of: "\tpath = " + job.path, with: "\tpath = /private/other.plist"),
                        original.replacingOccurrences(of: "\tprogram = " + job.executablePath, with: "\tprogram = /usr/bin/true"),
                        original.replacingOccurrences(of: "\t\t--command-configuration", with: "\t\t--configuration"),
                        original.replacingOccurrences(of: "\ttype = LaunchDaemon", with: "\ttype = LaunchAgent")] {
            XCTAssertFalse(try LaunchdJobObservation.decode(Data(changed.utf8), target: target).matches(job))
        }
    }
    func testUnknownTruncatedDuplicateAndMisScopedOutputNeverLooksAbsentOrMatching() throws {
        let job = try job(), original = output(job), target = "system/" + job.declaration.label
        for changed in [original.replacingOccurrences(of: target, with: "system/dev.remozio.other"), String(original.dropLast(2)),
                        original.replacingOccurrences(of: "\tpath = ", with: "\tother-path = "),
                        original.replacingOccurrences(of: "\tstate = waiting", with: "\tprogram = /usr/bin/true"),
                        original.replacingOccurrences(of: "\targuments = {", with: "\tunknown-arguments = {")] {
            XCTAssertThrowsError(try LaunchdJobObservation.decode(Data(changed.utf8), target: target))
        }
        XCTAssertThrowsError(try LaunchdJobObservation.decode(Data(repeating: 65, count: 65537), target: target))
        XCTAssertThrowsError(try LaunchdJobObservation.decode(Data([0xff]), target: target))
    }
    func testMatchingRegistrationDoesNotBootstrapOrMutateTheExistingJob() throws {
        var checks = 0
        try RuntimeJobRegistration.reconcile(verifyCurrent: { checks += 1 }, inspect: { .matching },
            bootstrap: { XCTFail("A matching job must be retained") })
        XCTAssertEqual(checks, 2)
    }
    func testConflictingOrUnknownRegistrationCannotBeReplaced() throws {
        XCTAssertThrowsError(try RuntimeJobRegistration.reconcile(verifyCurrent: {}, inspect: { .conflicting },
            bootstrap: { XCTFail("Never replace an unclaimed job") })) { XCTAssertEqual($0 as? RuntimeActivationError, .conflictingPlan) }
        XCTAssertThrowsError(try RuntimeJobRegistration.reconcile(verifyCurrent: {}, inspect: { throw LostReply() },
            bootstrap: { XCTFail("Unknown is not absent") }))
    }
    func testLostBootstrapAcknowledgmentReconcilesTheExactJobWithoutASecondMutation() throws {
        var reads = 0, starts = 0
        try RuntimeJobRegistration.reconcile(verifyCurrent: {}, inspect: { reads += 1; return reads == 1 ? .absent : .matching }, bootstrap: {
            starts += 1; throw LostReply()
        })
        XCTAssertEqual(reads, 2); XCTAssertEqual(starts, 1)
    }
    func testFailedAndConflictingBootstrapOutcomesRemainRecoverableWithoutDeletion() throws {
        for conflict in [false, true] {
            var reads = 0, starts = 0
            XCTAssertThrowsError(try RuntimeJobRegistration.reconcile(verifyCurrent: {}, inspect: {
                reads += 1; return reads == 1 || !conflict ? .absent : .conflicting
            }, bootstrap: { starts += 1 })) {
                XCTAssertEqual($0 as? RuntimeActivationError, conflict ? .conflictingPlan : .unavailable)
            }
            XCTAssertEqual(starts, 1)
        }
    }
    func testAChangedScopeStopsBeforeAnyNativeMutation() throws {
        var checks = 0
        XCTAssertThrowsError(try RuntimeJobRegistration.reconcile(verifyCurrent: { checks += 1; if checks == 2 { throw LostReply() } },
            inspect: { .absent }, bootstrap: { XCTFail("Scope changed before bootstrap") }))
    }
    func testNativeSystemRegistrationRefusesOrdinaryUsersBeforeValidationOrLaunchctl() throws {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary-owner Root guard") }
        XCTAssertThrowsError(try RuntimeJobRegistration.ensure(job(), verifyCurrent: { XCTFail("Root guard must run first") })) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
    }
}
