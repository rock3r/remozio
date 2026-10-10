import Foundation

public enum CommandCaptureError: Error, Equatable {
    case fields, type, version, bytes, path, environment, enumeration, ancestry
}
public struct CapturedFileIdentity: Equatable, Sendable {
    public let device: UInt64
    public let inode: UInt64
    public init(device: UInt64, inode: UInt64) { self.device = device; self.inode = inode }
}
public struct CapturedExecutable: Equatable, Sendable {
    public let path: Data
    public let identity: CapturedFileIdentity
    public let sha256: Data
    public init(path: Data, identity: CapturedFileIdentity, sha256: Data) {
        self.path = path; self.identity = identity; self.sha256 = sha256
    }
}
public struct CapturedDirectory: Equatable, Sendable {
    public let path: Data
    public let identity: CapturedFileIdentity
    public init(path: Data, identity: CapturedFileIdentity) { self.path = path; self.identity = identity }
}
public struct CommandTarget: Equatable, Sendable {
    public let uid: UInt32
    public let gid: UInt32
    public let supplementaryGroups: [UInt32]
    public let observedName: String?
    public init(uid: UInt32, gid: UInt32, supplementaryGroups: [UInt32], observedName: String?) {
        self.uid = uid; self.gid = gid; self.supplementaryGroups = supplementaryGroups; self.observedName = observedName
    }
}
public enum EnvironmentSource: UInt64, Sendable { case minimal, requested }
public struct CapturedEnvironmentEntry: Equatable, Sendable {
    public let name: Data
    public let value: Data
    public let source: EnvironmentSource
    public init(name: Data, value: Data, source: EnvironmentSource) {
        self.name = name; self.value = value; self.source = source
    }
}
public enum CommandInputKind: UInt64, Sendable {
    case null, pipe, file, tty, pty, socket, directory, device, other
    public var minimumSchemaVersion: UInt64 { rawValue <= 4 ? 1 : 2 }
}
public struct CapturedCommandInput: Equatable, Sendable {
    public let kind: CommandInputKind
    public let streamBinding: Data?
    public let observedPath: Data?
    public let identity: CapturedFileIdentity?
    public init(kind: CommandInputKind, streamBinding: Data?, observedPath: Data?, identity: CapturedFileIdentity?) {
        self.kind = kind; self.streamBinding = streamBinding; self.observedPath = observedPath; self.identity = identity
    }
}
public enum CommandStreamAccess: UInt64, Sendable { case readOnly, writeOnly, readWrite }
public struct CommandStreamFlags: OptionSet, Equatable, Sendable {
    public let rawValue: UInt64
    public init(rawValue: UInt64) { self.rawValue = rawValue }
    public static let append = Self(rawValue: 1)
    public static let nonblocking = Self(rawValue: 2)
    public static let asynchronous = Self(rawValue: 4)
    public static let synchronous = Self(rawValue: 8)
}
public struct CapturedCommandStream: Equatable, Sendable {
    public let source: CapturedCommandInput
    public let access: CommandStreamAccess
    public let flags: CommandStreamFlags
    public init(source: CapturedCommandInput, access: CommandStreamAccess, flags: CommandStreamFlags) {
        self.source = source; self.access = access; self.flags = flags
    }
}
public struct CapturedCommandTerminal: Equatable, Sendable {
    public let stream: CapturedCommandStream
    public let sessionID: UInt32
    public let terminalDevice: UInt32
    public init(stream: CapturedCommandStream, sessionID: UInt32, terminalDevice: UInt32) {
        self.stream = stream; self.sessionID = sessionID; self.terminalDevice = terminalDevice
    }
}
public struct CapturedCommandStdioLayout: Equatable, Sendable {
    public let input: CapturedCommandStream
    public let output: CapturedCommandStream
    public let error: CapturedCommandStream
    public let terminal: CapturedCommandTerminal?
    public let ptyMask: UInt32
    public init(input: CapturedCommandStream, output: CapturedCommandStream, error: CapturedCommandStream,
                terminal: CapturedCommandTerminal?, ptyMask: UInt32) {
        self.input = input; self.output = output; self.error = error; self.terminal = terminal; self.ptyMask = ptyMask
    }
}
public enum CommandIOMode: UInt64, Sendable { case pipes, pty }
public enum StartedCommandDisconnect: UInt64, Sendable { case terminate, continueRunning }
public enum CapturedSigningStatus: UInt64, Sendable { case unsigned, adHoc, validated, invalid, unavailable }
public struct CapturedSigningIdentity: Equatable, Sendable {
    public let status: CapturedSigningStatus
    public let identifier: String?
    public let team: String?
    public let cdHash: Data?
    public init(status: CapturedSigningStatus, identifier: String?, team: String?, cdHash: Data?) {
        self.status = status; self.identifier = identifier; self.team = team; self.cdHash = cdHash
    }
}
public struct CapturedRequester: Equatable, Sendable {
    public let executablePath: Data
    public let realUID: UInt32
    public let effectiveUID: UInt32
    public let pid: UInt32
    public let pidVersion: UInt32
    public let signing: CapturedSigningIdentity
    public let sessionID: UInt32?
    public let ttyPath: Data?
    public init(executablePath: Data, realUID: UInt32, effectiveUID: UInt32, pid: UInt32, pidVersion: UInt32,
                signing: CapturedSigningIdentity, sessionID: UInt32?, ttyPath: Data?) {
        self.executablePath = executablePath; self.realUID = realUID; self.effectiveUID = effectiveUID
        self.pid = pid; self.pidVersion = pidVersion; self.signing = signing; self.sessionID = sessionID; self.ttyPath = ttyPath
    }
}
public enum AncestryCompleteness: UInt64, Sendable { case complete, partial, unavailable }
public enum AncestryReason: UInt64, Sendable { case none, exited, permission, truncated, unsupported }
public struct CapturedAncestor: Equatable, Sendable {
    public let pid: UInt32
    public let pidVersion: UInt32
    public let executablePath: Data?
    public let uid: UInt32
    public init(pid: UInt32, pidVersion: UInt32, executablePath: Data?, uid: UInt32) {
        self.pid = pid; self.pidVersion = pidVersion; self.executablePath = executablePath; self.uid = uid
    }
}
public struct CapturedAncestry: Equatable, Sendable {
    public let completeness: AncestryCompleteness
    public let entries: [CapturedAncestor]
    public let reason: AncestryReason
    public init(completeness: AncestryCompleteness, entries: [CapturedAncestor], reason: AncestryReason) {
        self.completeness = completeness; self.entries = entries; self.reason = reason
    }
}
public struct CapturedSubmission: Equatable, Sendable {
    public let id: Data
    public let nonce: Data
    public let callerBinding: Data
    public init(id: Data, nonce: Data, callerBinding: Data) {
        self.id = id; self.nonce = nonce; self.callerBinding = callerBinding
    }
}

/// Encodes and parses command claims. OS provenance, authenticated issuance, and execution remain separate responsibilities.
public struct CommandCapture: Equatable, Sendable {
    public static let supportedSchemaVersions: Set<UInt64> = [1, 2, 3]
    public let schemaVersion: UInt64
    public let canonicalBytes: Data
    public let executable: CapturedExecutable
    public let arguments: [Data]
    public let directory: CapturedDirectory
    public let target: CommandTarget
    public let environment: [CapturedEnvironmentEntry]
    public let input: CapturedCommandInput
    public let ioMode: CommandIOMode
    public let stdioLayout: CapturedCommandStdioLayout?
    public let disconnectBehavior: StartedCommandDisconnect
    public let requester: CapturedRequester
    public let ancestry: CapturedAncestry
    public let unverifiedRationale: String?
    public let submission: CapturedSubmission

    public init(schemaVersion: UInt64, executable: CapturedExecutable, arguments: [Data], directory: CapturedDirectory,
                target: CommandTarget, environment: [CapturedEnvironmentEntry], input: CapturedCommandInput,
                ioMode: CommandIOMode, disconnectBehavior: StartedCommandDisconnect, requester: CapturedRequester,
                ancestry: CapturedAncestry, unverifiedRationale: String?, submission: CapturedSubmission,
                stdioLayout: CapturedCommandStdioLayout? = nil, limits: CBORLimits) throws {
        guard Self.supportedSchemaVersions.contains(schemaVersion) else { throw CommandCaptureError.version }
        func identity(_ value: CapturedFileIdentity) -> CBORValue {
            .map([0: .unsigned(value.device), 1: .unsigned(value.inode)])
        }
        let executableValue: CBORValue = .map([0: .bytes(executable.path), 1: identity(executable.identity), 2: .bytes(executable.sha256)])
        let directoryValue: CBORValue = .map([0: .bytes(directory.path), 1: identity(directory.identity)])
        let targetValue: CBORValue = .map([0: .unsigned(UInt64(target.uid)), 1: .unsigned(UInt64(target.gid)),
            2: .array(target.supplementaryGroups.map { .unsigned(UInt64($0)) }), 3: target.observedName.map { .text($0) } ?? .null])
        let environmentValue: CBORValue = .array(environment.map {
            .map([0: .bytes($0.name), 1: .bytes($0.value), 2: .unsigned($0.source.rawValue)])
        })
        let inputValue: CBORValue = .map([0: .unsigned(input.kind.rawValue), 1: input.streamBinding.map { .bytes($0) } ?? .null,
            2: input.observedPath.map { .bytes($0) } ?? .null, 3: input.identity.map(identity) ?? .null])
        let signingValue: CBORValue = .map([0: .unsigned(requester.signing.status.rawValue),
            1: requester.signing.identifier.map { .text($0) } ?? .null, 2: requester.signing.team.map { .text($0) } ?? .null,
            3: requester.signing.cdHash.map { .bytes($0) } ?? .null])
        let requesterValue: CBORValue = .map([0: .bytes(requester.executablePath), 1: .unsigned(UInt64(requester.realUID)),
            2: .unsigned(UInt64(requester.effectiveUID)), 3: .unsigned(UInt64(requester.pid)),
            4: .unsigned(UInt64(requester.pidVersion)), 5: signingValue,
            6: requester.sessionID.map { .unsigned(UInt64($0)) } ?? .null, 7: requester.ttyPath.map { .bytes($0) } ?? .null])
        let ancestryValue: CBORValue = .map([0: .unsigned(ancestry.completeness.rawValue), 1: .array(ancestry.entries.map {
            .map([0: .unsigned(UInt64($0.pid)), 1: .unsigned(UInt64($0.pidVersion)),
                2: $0.executablePath.map { .bytes($0) } ?? .null, 3: .unsigned(UInt64($0.uid))])
        }), 2: .unsigned(ancestry.reason.rawValue)])
        let submissionValue: CBORValue = .map([0: .bytes(submission.id), 1: .bytes(submission.nonce), 2: .bytes(submission.callerBinding)])
        guard (schemaVersion == 3) == (stdioLayout != nil) else { throw CommandCaptureError.fields }
        var fields: [UInt64: CBORValue] = [0: .unsigned(schemaVersion), 1: executableValue, 2: .array(arguments.map { .bytes($0) }),
            3: directoryValue, 4: targetValue, 5: environmentValue, 6: inputValue, 7: .unsigned(ioMode.rawValue),
            8: .unsigned(disconnectBehavior.rawValue), 9: requesterValue, 10: ancestryValue,
            11: unverifiedRationale.map { .text($0) } ?? .null, 12: submissionValue]
        func source(_ value: CapturedCommandInput) -> CBORValue {
            .map([0: .unsigned(value.kind.rawValue), 1: value.streamBinding.map { .bytes($0) } ?? .null,
                2: value.observedPath.map { .bytes($0) } ?? .null, 3: value.identity.map(identity) ?? .null])
        }
        func stream(_ value: CapturedCommandStream) -> CBORValue {
            .map([0: source(value.source), 1: .unsigned(value.access.rawValue), 2: .unsigned(value.flags.rawValue)])
        }
        if let layout = stdioLayout {
            fields[13] = .map([0: stream(layout.input), 1: stream(layout.output), 2: stream(layout.error),
                3: layout.terminal.map { .map([0: stream($0.stream), 1: .unsigned(UInt64($0.sessionID)),
                    2: .unsigned(UInt64($0.terminalDevice))]) } ?? .null, 4: .unsigned(UInt64(layout.ptyMask))])
        }
        try self.init(canonicalBytes: DeterministicCBOR.encode(.map(fields), limits: limits), limits: limits, expectedSchemaVersion: schemaVersion)
    }

    public init(canonicalBytes: Data, limits: CBORLimits, expectedSchemaVersion: UInt64 = 1) throws {
        guard Self.supportedSchemaVersions.contains(expectedSchemaVersion) else { throw CommandCaptureError.version }
        let root = try CaptureFields(DeterministicCBOR.decode(canonicalBytes, limits: limits), count: expectedSchemaVersion == 3 ? 14 : 13)
        schemaVersion = try root.uint(0)
        guard Self.supportedSchemaVersions.contains(expectedSchemaVersion), schemaVersion == expectedSchemaVersion else {
            throw CommandCaptureError.version
        }
        let executable = try CaptureFields(root[1], count: 3)
        self.executable = try CapturedExecutable(path: executable.path(0), identity: executable.identity(1), sha256: executable.bytes(2, count: 32))
        self.arguments = try root.array(2).map { try CaptureFields.cString($0) }
        guard !arguments.isEmpty else { throw CommandCaptureError.bytes }
        let directory = try CaptureFields(root[3], count: 2)
        self.directory = try CapturedDirectory(path: directory.path(0), identity: directory.identity(1))
        let target = try CaptureFields(root[4], count: 4)
        self.target = try CommandTarget(uid: target.uint32(0), gid: target.uint32(1),
            supplementaryGroups: target.array(2).map { try CaptureFields.uint32($0) }, observedName: target.optionalText(3))
        var environment: [CapturedEnvironmentEntry] = []
        var previous: Data?
        for value in try root.array(5) {
            let entry = try CaptureFields(value, count: 3)
            let name = try CaptureFields.cString(entry[0])
            guard !name.isEmpty, !name.contains(0x3d), previous == nil || previous!.lexicographicallyPrecedes(name) else {
                throw CommandCaptureError.environment
            }
            environment.append(try CapturedEnvironmentEntry(name: name, value: CaptureFields.cString(entry[1]), source: entry.tag(2)))
            previous = name
        }
        self.environment = environment
        func source(_ value: CBORValue) throws -> CapturedCommandInput {
            let fields = try CaptureFields(value, count: 4)
            let kind: CommandInputKind = try fields.tag(0)
            guard expectedSchemaVersion >= kind.minimumSchemaVersion else { throw CommandCaptureError.enumeration }
            let binding = try fields.optionalBytes(1, count: 16), path = try fields.optionalPath(2), identity = try fields.optionalIdentity(3)
            if kind == .null {
                guard binding == nil, path == nil, identity == nil else { throw CommandCaptureError.fields }
            } else { guard binding != nil else { throw CommandCaptureError.bytes } }
            return CapturedCommandInput(kind: kind, streamBinding: binding, observedPath: path, identity: identity)
        }
        self.input = try source(root[6])
        self.ioMode = try root.tag(7)
        self.disconnectBehavior = try root.tag(8)
        let requester = try CaptureFields(root[9], count: 8)
        let signing = try CaptureFields(requester[5], count: 4)
        self.requester = try CapturedRequester(executablePath: requester.path(0), realUID: requester.uint32(1),
            effectiveUID: requester.uint32(2), pid: requester.pid(3), pidVersion: requester.uint32(4),
            signing: CapturedSigningIdentity(status: signing.tag(0), identifier: signing.optionalText(1),
                team: signing.optionalText(2), cdHash: signing.optionalBytes(3, count: 20)),
            sessionID: requester.optionalUInt32(6), ttyPath: requester.optionalPath(7))
        let ancestry = try CaptureFields(root[10], count: 3)
        let completeness: AncestryCompleteness = try ancestry.tag(0)
        let reason: AncestryReason = try ancestry.tag(2)
        let entries = try ancestry.array(1).map { value in
            let entry = try CaptureFields(value, count: 4)
            return try CapturedAncestor(pid: entry.pid(0), pidVersion: entry.uint32(1), executablePath: entry.optionalPath(2), uid: entry.uint32(3))
        }
        guard (completeness == .complete) == (reason == .none), completeness != .unavailable || entries.isEmpty else {
            throw CommandCaptureError.ancestry
        }
        self.ancestry = CapturedAncestry(completeness: completeness, entries: entries, reason: reason)
        self.unverifiedRationale = try root.optionalText(11)
        let submission = try CaptureFields(root[12], count: 3)
        self.submission = try CapturedSubmission(id: submission.bytes(0, count: 16), nonce: submission.bytes(1, count: 32),
            callerBinding: submission.bytes(2, count: 16))
        if schemaVersion == 3 {
            func stream(_ value: CBORValue) throws -> CapturedCommandStream {
                let fields = try CaptureFields(value, count: 3)
                let flags = try fields.uint(2)
                guard flags <= 15 else { throw CommandCaptureError.enumeration }
                return try CapturedCommandStream(source: source(fields[0]), access: fields.tag(1), flags: .init(rawValue: flags))
            }
            let fields = try CaptureFields(root[13], count: 5)
            let input = try stream(fields[0]), output = try stream(fields[1]), error = try stream(fields[2])
            let terminal: CapturedCommandTerminal?
            if fields[3] == .null { terminal = nil }
            else {
                let value = try CaptureFields(fields[3], count: 3)
                let control = try stream(value[0]), session = try value.pid(1), device = try value.uint32(2)
                guard control.access == .readWrite, [.tty, .pty].contains(control.source.kind),
                      control.source.identity != nil, device != UInt32.max, self.requester.sessionID == session else {
                    throw CommandCaptureError.fields
                }
                terminal = CapturedCommandTerminal(stream: control, sessionID: session, terminalDevice: device)
            }
            let mask = try fields.uint32(4)
            guard mask <= 7, input.source == self.input, input.access != .writeOnly,
                  output.access != .readOnly, error.access != .readOnly,
                  ioMode == .pty || (mask == 0 && terminal == nil), terminal != nil || mask == 0 else {
                throw CommandCaptureError.fields
            }
            for (index, value) in [input, output, error].enumerated() where mask & (1 << index) != 0 {
                guard [.tty, .pty].contains(value.source.kind), let identity = value.source.identity,
                      identity == terminal?.stream.source.identity else { throw CommandCaptureError.fields }
            }
            stdioLayout = CapturedCommandStdioLayout(input: input, output: output, error: error, terminal: terminal, ptyMask: mask)
        } else { stdioLayout = nil }
        self.canonicalBytes = canonicalBytes
    }
}

struct CaptureFields {
    let values: [UInt64: CBORValue]
    init(_ value: CBORValue, count: UInt64) throws {
        guard case let .map(values) = value, Set(values.keys) == Set(0..<count) else { throw CommandCaptureError.fields }
        self.values = values
    }
    subscript(_ field: UInt64) -> CBORValue { values[field]! }
    func uint(_ field: UInt64) throws -> UInt64 {
        guard case let .unsigned(value) = self[field] else { throw CommandCaptureError.type }
        return value
    }
    static func uint32(_ value: CBORValue) throws -> UInt32 {
        guard case let .unsigned(number) = value, let result = UInt32(exactly: number) else { throw CommandCaptureError.type }
        return result
    }
    func uint32(_ field: UInt64) throws -> UInt32 { try Self.uint32(self[field]) }
    func pid(_ field: UInt64) throws -> UInt32 {
        let value = try uint32(field)
        guard value > 0, value <= Int32.max else { throw CommandCaptureError.type }
        return value
    }
    func optionalUInt32(_ field: UInt64) throws -> UInt32? { self[field] == .null ? nil : try uint32(field) }
    func tag<T: RawRepresentable>(_ field: UInt64) throws -> T where T.RawValue == UInt64 {
        guard let value = T(rawValue: try uint(field)) else { throw CommandCaptureError.enumeration }
        return value
    }
    func array(_ field: UInt64) throws -> [CBORValue] {
        guard case let .array(value) = self[field] else { throw CommandCaptureError.type }
        return value
    }
    func bytes(_ field: UInt64, count: Int) throws -> Data {
        guard case let .bytes(value) = self[field], value.count == count else { throw CommandCaptureError.bytes }
        return value
    }
    func optionalBytes(_ field: UInt64, count: Int) throws -> Data? { self[field] == .null ? nil : try bytes(field, count: count) }
    static func cString(_ value: CBORValue) throws -> Data {
        guard case let .bytes(data) = value, !data.contains(0) else { throw CommandCaptureError.bytes }
        return data
    }
    func path(_ field: UInt64) throws -> Data {
        let data = try Self.cString(self[field])
        guard data.first == 0x2f else { throw CommandCaptureError.path }
        return data
    }
    func optionalPath(_ field: UInt64) throws -> Data? { self[field] == .null ? nil : try path(field) }
    func optionalText(_ field: UInt64) throws -> String? {
        if self[field] == .null { return nil }
        guard case let .text(value) = self[field] else { throw CommandCaptureError.type }
        return value
    }
    func identity(_ field: UInt64) throws -> CapturedFileIdentity {
        let value = try CaptureFields(self[field], count: 2)
        return try CapturedFileIdentity(device: value.uint(0), inode: value.uint(1))
    }
    func optionalIdentity(_ field: UInt64) throws -> CapturedFileIdentity? { self[field] == .null ? nil : try identity(field) }
}
