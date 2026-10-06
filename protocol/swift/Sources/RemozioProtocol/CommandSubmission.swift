import Foundation

public struct CommandEnvironmentAddition: Equatable, Sendable {
    public let name: Data
    public let value: Data
    public init(name: Data, value: Data) { self.name = name; self.value = value }
}

/// Local frontend claims. Parsing does not authenticate a channel, authorize a target, or establish OS provenance.
public struct CommandSubmission: Equatable, Sendable {
    public static let supportedSchemaVersions: Set<UInt64> = [1]
    public let schemaVersion: UInt64
    public let canonicalBytes: Data
    public let executablePath: Data
    public let arguments: [Data]
    public let directoryPath: Data
    public let requestedTargetUID: UInt32
    public let environmentAdditions: [CommandEnvironmentAddition]
    public let ioMode: CommandIOMode
    public let disconnectBehavior: StartedCommandDisconnect
    public let unverifiedRationale: String?
    public let binding: CapturedSubmission

    public init(schemaVersion: UInt64, executablePath: Data, arguments: [Data], directoryPath: Data,
                requestedTargetUID: UInt32, environmentAdditions: [CommandEnvironmentAddition], ioMode: CommandIOMode,
                disconnectBehavior: StartedCommandDisconnect, unverifiedRationale: String?, binding: CapturedSubmission,
                limits: CBORLimits) throws {
        guard Self.supportedSchemaVersions.contains(schemaVersion) else { throw CommandCaptureError.version }
        let additions: CBORValue = .array(environmentAdditions.map { .map([0: .bytes($0.name), 1: .bytes($0.value)]) })
        let bindings: CBORValue = .map([0: .bytes(binding.id), 1: .bytes(binding.nonce), 2: .bytes(binding.callerBinding)])
        let fields: CBORValue = .map([0: .unsigned(schemaVersion), 1: .bytes(executablePath),
            2: .array(arguments.map { .bytes($0) }), 3: .bytes(directoryPath), 4: .unsigned(UInt64(requestedTargetUID)),
            5: additions, 6: .unsigned(ioMode.rawValue), 7: .unsigned(disconnectBehavior.rawValue),
            8: unverifiedRationale.map { .text($0) } ?? .null, 9: bindings])
        try self.init(canonicalBytes: DeterministicCBOR.encode(fields, limits: limits), limits: limits, expectedSchemaVersion: schemaVersion)
    }

    public init(canonicalBytes: Data, limits: CBORLimits, expectedSchemaVersion: UInt64) throws {
        let fields = try CaptureFields(DeterministicCBOR.decode(canonicalBytes, limits: limits), count: 10)
        schemaVersion = try fields.uint(0)
        guard Self.supportedSchemaVersions.contains(expectedSchemaVersion), schemaVersion == expectedSchemaVersion else {
            throw CommandCaptureError.version
        }
        executablePath = try fields.path(1)
        arguments = try fields.array(2).map { try CaptureFields.cString($0) }
        guard !arguments.isEmpty else { throw CommandCaptureError.bytes }
        directoryPath = try fields.path(3)
        requestedTargetUID = try fields.uint32(4)
        var additions: [CommandEnvironmentAddition] = [], previous: Data?
        for raw in try fields.array(5) {
            let entry = try CaptureFields(raw, count: 2)
            let name = try CaptureFields.cString(entry[0])
            guard !name.isEmpty, !name.contains(0x3d), previous == nil || previous!.lexicographicallyPrecedes(name) else {
                throw CommandCaptureError.environment
            }
            additions.append(try CommandEnvironmentAddition(name: name, value: CaptureFields.cString(entry[1])))
            previous = name
        }
        environmentAdditions = additions
        ioMode = try fields.tag(6)
        disconnectBehavior = try fields.tag(7)
        unverifiedRationale = try fields.optionalText(8)
        let bindings = try CaptureFields(fields[9], count: 3)
        binding = try CapturedSubmission(id: bindings.bytes(0, count: 16), nonce: bindings.bytes(1, count: 32), callerBinding: bindings.bytes(2, count: 16))
        self.canonicalBytes = canonicalBytes
    }
}
