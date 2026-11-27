import Darwin
import Foundation
import OSLog
import RemozioProtocol

/// Stores one authenticated notice per enrollment under the existing journal writer lease.
struct PhoneRepairNoticeStorage {
    let anchor: String
    let relativeDirectory: String
    let owner: uid_t

    private let reportInvalidNotice: () -> Void

    init(anchor: String, relativeDirectory: String, owner: uid_t, reportInvalidNotice: @escaping () -> Void = {
        Logger(subsystem: "dev.sebastiano.remozio.macos.authority", category: "phone-repair").error("Stored phone repair notice could not be verified")
    }) {
        self.anchor = anchor
        self.relativeDirectory = relativeDirectory
        self.owner = owner
        self.reportInvalidNotice = reportInvalidNotice
    }

    func read(scope: ChannelScope, decisionKey: Data) throws -> PhoneRepairNoticeFrame.Reason? {
        try validatedNotice(scope: scope, decisionKey: decisionKey)?.notice.reason
    }

    func retain(_ notice: PhoneRepairNoticeFrame, decisionKey: Data, verify: () throws -> Void) throws {
        let scope = notice.scope
        try verify()
        let directory = try ProtectedSetupDirectory(anchor: anchor, relativePath: relativeDirectory, owner: owner, createIfMissing: false)
        defer { directory.close() }
        let file = AdministrativeSetupPublication.File.phoneRepairNotice(phone: scope.phoneID, epoch: scope.enrollmentEpoch)
        let bytes = try validatedNotice(scope: scope, decisionKey: decisionKey)?.bytes ?? notice.encode()
        _ = try AdministrativeSetupPublication.publish(bytes, file: file, directory: directory, owner: owner, verify: verify)
    }

    private func validatedNotice(scope: ChannelScope, decisionKey: Data)
        throws -> (notice: PhoneRepairNoticeFrame, bytes: Data)? {
        do {
            guard let bytes = try retainedBytes(scope: scope) else { return nil }
            let notice = try PhoneRepairNoticeFrame.decode(bytes)
            guard notice.scope == scope, try notice.verify(decisionPublicKey: decisionKey) else {
                throw EnrollmentJournalError.corruptData
            }
            return (notice, bytes)
        } catch {
            reportInvalidNotice()
            throw error
        }
    }

    private func retainedBytes(scope: ChannelScope) throws -> Data? {
        let file = AdministrativeSetupPublication.File.phoneRepairNotice(phone: scope.phoneID, epoch: scope.enrollmentEpoch)
        return try ProtectedServiceConfiguration.readOptionalPrivate(anchor: anchor,
            relativePath: relativeDirectory + "/" + file.name, owner: owner)
    }
}

extension StoredApprovalEnrollment {
    var repairNoticeDecisionKey: Data? {
        approval.keys.first { $0.keyClass == .decision }?.publicKey
    }
}
