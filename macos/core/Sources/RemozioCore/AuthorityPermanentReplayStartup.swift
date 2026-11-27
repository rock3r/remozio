/// The signed marker distinguishes the final format 20 catalog from dormant format 20 builds.
enum AuthorityPermanentReplayStartup {
    static let formatName = "authority.journal-replay-counters"
    static let version: UInt64 = 1

    static func hasReaderFloor(release: SignedReleaseEvidence, policy: AuthorityCodePolicy) -> Bool {
        for role in [AuthorityCodeRole.authority, .setupController] {
            guard let entry = policy.entries.first(where: { $0.role == role && $0.active }),
                  let component = release.manifest.components.first(where: { $0.role == role }),
                  component.generation == entry.installedGeneration,
                  entry.minimumGeneration == component.generation,
                  release.codeDirectoryHashes[role] == entry.codeDirectoryHash,
                  let journal = component.formats.first(where: { $0.name == "authority.journal" }),
                  journal.readers.contains(20), journal.writers.contains(20),
                  let catalog = component.formats.first(where: { $0.name == formatName }),
                  catalog.readers.contains(version), catalog.writers.contains(version) else { return false }
        }
        return true
    }
}
