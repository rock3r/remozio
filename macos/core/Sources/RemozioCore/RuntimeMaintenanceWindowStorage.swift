import Foundation

/// Declares protected window storage. It creates no table, admits no schema and grants no writer authority.
enum RuntimeMaintenanceWindowStorage {
    static let schemaVersion: Int64 = 29
    static let tableName = "runtime_maintenance_windows_v1"
    static let createSQL = "CREATE TABLE runtime_maintenance_windows_v1(account BLOB PRIMARY KEY CHECK(length(account)=16),attempt BLOB NOT NULL UNIQUE CHECK(length(attempt)=16),revision BLOB NOT NULL UNIQUE CHECK(length(revision)=16),phase INTEGER NOT NULL CHECK(phase BETWEEN 1 AND 10),record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 4096)) STRICT"
    static var readerRequirements: [RetainedReleaseFormat] { get throws {
        try [AuthorityCodeRole.authority, .setupController].flatMap { role in
            try [RetainedReleaseFormat(role: role, name: "authority.installation-preparation", readVersions: [UInt64(schemaVersion)]),
                 RetainedReleaseFormat(role: role, name: RuntimeMaintenanceWindowRecord.formatName, readVersions: [1])]
        }
    } }
    static func requireReaderFormats(_ candidate: SignedReleaseEvidence) throws {
        try MachineUpdateRetainedSetupPromotionReadyStorage.requireReaderFormats(candidate)
        for required in try readerRequirements {
            guard let format = candidate.manifest.components.first(where: { $0.role == required.role })?
                .formats.first(where: { $0.name == required.name }), required.readVersions.isSubset(of: format.readers) else {
                throw PreparationStoreError.incompatibleStore
            }
        }
    }
    /// The caller supplies indexed columns and bytes from one protected transaction. No machine query occurs here.
    static func decode(accountID: Data, attemptID: Data, revision: Data, phase: UInt64,
                       bytes: Data) throws -> RuntimeMaintenanceWindowRecord {
        let value: RuntimeMaintenanceWindowRecord
        do { value = try RuntimeMaintenanceWindowRecord.decode(bytes) } catch { throw PreparationStoreError.corruptRecord }
        guard value.scope.authority.accountID == accountID, value.id == attemptID, value.revision == revision,
              value.phase.rawValue == phase else { throw PreparationStoreError.corruptRecord }
        return value
    }
}
