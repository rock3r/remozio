import Darwin
import SQLite3
import XCTest
@testable import RemozioCore

final class AuthorityStartupFailureTests: XCTestCase {
    func testRecoveryOutcomesRemainDistinct() {
        XCTAssertEqual(AuthorityStartupFailure(error: AuthorityStorageStartupError.historyRecoveryRequired), .historyRecoveryRequired)
        XCTAssertEqual(AuthorityStartupFailure(error: AuthorityStorageStartupError.repairRequired), .repairRequired)
    }

    func testTemporaryAcquisitionAndStorageFailuresCanRetry() {
        XCTAssertEqual(AuthorityStartupFailure(error: JournalLeaseError.busy), .temporaryStorageFailure)
        for code in [EINTR, EAGAIN, EBUSY, ENOMEM, EMFILE, ENFILE, EIO, ENOSPC, ETIMEDOUT] {
            XCTAssertEqual(AuthorityStartupFailure(error: JournalLeaseError.system(code)), .temporaryStorageFailure)
        }
        for primary in [SQLITE_BUSY, SQLITE_LOCKED, SQLITE_IOERR, SQLITE_FULL, SQLITE_NOMEM, SQLITE_INTERRUPT] {
            for code in [primary, primary | (1 << 8)] {
                XCTAssertEqual(AuthorityStartupFailure(error: JournalDatabaseError.storage(code)), .temporaryStorageFailure)
                XCTAssertEqual(AuthorityStartupFailure(error: ContinuityStoreError.storage(code)), .temporaryStorageFailure)
                XCTAssertEqual(AuthorityStartupFailure(error: AuditJournalError.storage(code)), .temporaryStorageFailure)
            }
        }
    }

    func testInvalidProvisioningAndUnknownFailuresDoNotRetry() {
        struct UnknownFailure: Error {}
        let failures: [any Error] = [
            JournalDatabaseError.wrongScope, JournalDatabaseError.incompatibleStore,
            JournalDatabaseError.invalidConfiguration, JournalDatabaseError.unavailable,
            ContinuityStoreError.wrongScope, ContinuityStoreError.incompatibleStore,
            ContinuityStoreError.invalidCheckpoint, ContinuityStoreError.unavailable,
            JournalLeaseError.unsafeMetadata, JournalLeaseError.identityChanged,
            JournalLeaseError.rootRequired, JournalLeaseError.invalidPath, UnknownFailure()
        ]
        for error in failures { XCTAssertEqual(AuthorityStartupFailure(error: error), .configurationFailure) }
        for code in [ENOENT, EACCES, EPERM, ELOOP, ENOTDIR, EINVAL] {
            XCTAssertEqual(AuthorityStartupFailure(error: JournalLeaseError.system(code)), .configurationFailure)
        }
        for code in [SQLITE_CORRUPT, SQLITE_NOTADB, SQLITE_CANTOPEN, SQLITE_READONLY, SQLITE_MISUSE, SQLITE_SCHEMA] {
            XCTAssertEqual(AuthorityStartupFailure(error: JournalDatabaseError.storage(code)), .configurationFailure)
            XCTAssertEqual(AuthorityStartupFailure(error: ContinuityStoreError.storage(code)), .configurationFailure)
            XCTAssertEqual(AuthorityStartupFailure(error: AuditJournalError.storage(code)), .configurationFailure)
        }
    }
}
