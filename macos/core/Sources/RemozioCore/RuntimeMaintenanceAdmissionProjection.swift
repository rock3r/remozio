import Foundation

/// Negative admission metadata only. It cannot release a live hold, acquire a drain or admit a request.
/// Consume at protected startup or the explicit native command, never through per-request polling.
struct RuntimeMaintenanceAdmissionProjection: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    let requiresLocalHold: Bool
    let attemptID: Data?, revision: Data?
    var description: String { "RuntimeMaintenanceAdmissionProjection(redacted)" }
    var debugDescription: String { description }
    init(record: RuntimeMaintenanceWindowRecord?, macID: Data, installationID: Data,
         account: RuntimeMaintenanceWindowRecord.Account, registration: UpdateAdmissionRegistrationRecord) throws {
        guard macID.count == 16, installationID.count == 16,
              registration.macID == macID, registration.installationID == installationID else {
            throw RuntimePreparationError.changedScope
        }
        guard let record else { requiresLocalHold = false; attemptID = nil; revision = nil; return }
        guard record.scope.macID == macID, record.scope.installationID == installationID else {
            throw RuntimePreparationError.changedScope
        }
        guard record.scope.authority.accountID == account.accountID else {
            requiresLocalHold = false; attemptID = nil; revision = nil; return
        }
        guard record.scope.authority == account,
              let gate = registration.accounts.first(where: { $0.accountID == account.accountID }),
              record.gate == nil || record.gate?.identity == gate.identity else { throw RuntimePreparationError.changedScope }
        requiresLocalHold = record.phase != .restored
        attemptID = record.id; revision = record.revision
    }
}
