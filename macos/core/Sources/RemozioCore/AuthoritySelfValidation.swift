import Foundation

public enum AuthoritySelfValidationError: Error, Equatable { case unconfigured, invalidPolicy }

/// Defense in depth for authority startup. Protected installation must independently prevent launching obsolete code.
enum AuthoritySelfValidation {
    static func validate(journal: AuthorityJournal) throws {
        try journal.read { transaction in
            guard let entry = try transaction.codePolicy()?.policy.entries.first(where: { $0.role == .authority }) else {
                throw AuthoritySelfValidationError.unconfigured
            }
            try DynamicCodeValidation.validateSelf(requirement: requirement(for: entry))
        }
    }

    static func requirement(for entry: AuthorityCodeEntry) throws -> String {
        guard entry.role == .authority, entry.active else { throw AuthoritySelfValidationError.invalidPolicy }
        let policy = try XPCPeerPolicy(teamID: entry.teamID, componentIdentifier: entry.identifier,
            approvedCodeDirectoryHashes: [entry.codeDirectoryHash], expectedUserID: 0)
        // Exact signed metadata binds the installed generation; construction already enforces the retained floor.
        return policy.requirement + " and info[\"RemozioSecurityGeneration\"] = \"\(entry.installedGeneration)\""
    }
}
