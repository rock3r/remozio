/// Both participants must declare the distinct health codec before a native health connection can open.
enum MachineUpdateConsumerHealthReleaseValidation {
    static let formatName = "runtime.machine-update-consumer-health"
    static let version: UInt64 = 1
    static var formatRequirements: [RetainedReleaseFormat] { get throws {
        try [AuthorityCodeRole.authority, .transport, .notificationGateway].map {
            try .init(role: $0, name: formatName, readVersions: [version], writeVersions: [version])
        }
    } }
    static func validate(_ release: SignedReleaseEvidence, host: GatewaySettingsConsumerHostConfiguration) throws {
        try host.requireUpdateHealthStartupSupported()
        try host.validateRelease(release)
        let authority = release.manifest.components.first { $0.role == .authority }
        let hostFormat = authority?.formats.first { $0.name == GatewaySettingsConsumerHostConfiguration.formatName }
        guard hostFormat?.readers.contains(host.formatVersion) == true else {
            throw GatewayPreparationError.changedScope
        }
        try validateDeclarations(release, policy: host.codePolicy, consumer: host.role.codeRole)
    }
    static func validateDeclarations(_ release: SignedReleaseEvidence, policy: AuthorityCodePolicy,
                                     consumer: AuthorityCodeRole) throws {
        guard [.transport, .notificationGateway].contains(consumer) else { throw GatewayPreparationError.changedScope }
        for role in [AuthorityCodeRole.authority, consumer] {
            guard let code = policy.entries.first(where: { $0.role == role && $0.active }),
                  let component = release.manifest.components.first(where: { $0.role == role }),
                  component.identifier == code.identifier, component.teamID == code.teamID,
                  component.generation == code.installedGeneration, component.codeDirectoryHash == code.codeDirectoryHash,
                  release.codeDirectoryHashes[role] == code.codeDirectoryHash,
                  let format = component.formats.first(where: { $0.name == formatName }),
                  format.readers.contains(version), format.writers.contains(version) else {
                throw GatewayPreparationError.changedScope
            }
        }
    }
}
