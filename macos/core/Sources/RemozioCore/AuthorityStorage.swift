import Foundation
import RemozioProtocol

/// Confined ownership of both stores before recovery. Opening never initializes or repairs persisted state.
final class AuthorityStorage {
    let journal: JournalDatabase
    let continuity: ContinuityStore

    static func open(configuration: AuthorityServiceConfiguration) throws -> AuthorityStorage {
        guard let directory = configuration.continuityDirectory else {
            throw AuthorityServiceConfigurationError.invalidConfiguration
        }
        let limits = try CBORLimits(maxBytes: 16_777_216, maxDepth: 32, maxItems: 262_144)
        return try AuthorityStorage(openJournal: {
            try JournalDatabase.open(directoryPath: configuration.journalDirectory,
                macID: configuration.macID, accountID: configuration.accountID,
                recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
                maximumConsumptions: 1_000_000, busyMilliseconds: 5000)
        }, openContinuity: {
            try ContinuityStore.open(directoryPath: directory,
                macID: configuration.macID, accountID: configuration.accountID)
        })
    }

    /// Internal factory seam for protected fixture stores. Both factories transfer exclusive ownership.
    init(openJournal: () throws -> JournalDatabase, openContinuity: () throws -> ContinuityStore) throws {
        let journal = try openJournal()
        do {
            continuity = try openContinuity()
            self.journal = journal
        } catch {
            try? journal.close()
            throw error
        }
    }

    func close() throws {
        defer { continuity.close() }
        try journal.close()
    }

    deinit { try? close() }
}
