import Darwin
import Foundation
import RemozioProtocol

public enum CommandFrontendInvocationError: Error, Equatable {
    case invalidArguments, oversized, unknownCommand, missingSeparator, missingExecutable
    case unknownOption, missingOptionValue, invalidUserID, invalidEnvironment, invalidRationale, invalidDisconnectBehavior
    case invalidPath, executableNotFound
    case system(Int32)
}

/// Untrusted frontend claims. Root must capture filesystem facts, credentials and effective environment before approval.
public struct CommandFrontendInvocation: Equatable, Sendable {
    public let arguments: [Data]
    public let requestedTargetUID: UInt32
    public let environmentAdditions: [CommandEnvironmentAddition]
    public let ioMode: CommandIOMode
    public let disconnectBehavior: StartedCommandDisconnect
    public let unverifiedRationale: String?

    /// Copies the actual C argv without Unicode conversion. The vector must be a valid argc/argv pair owned by the caller.
    /// It borrows no stream, changes no terminal state, and retains no pointers after this call.
    public static func copyArguments(count: Int32, vector: UnsafePointer<UnsafeMutablePointer<CChar>?>,
                                     limits: CBORLimits) throws -> [Data] {
        guard count > 0, Int(count) <= limits.maxItems else { throw CommandFrontendInvocationError.oversized }
        var copied: [Data] = [], remaining = limits.maxBytes
        for index in 0..<Int(count) {
            guard let pointer = vector[index] else { throw CommandFrontendInvocationError.invalidArguments }
            // Count terminators too, so an array of empty arguments also consumes the configured budget.
            let length = strnlen(pointer, remaining)
            guard length < remaining else { throw CommandFrontendInvocationError.oversized }
            copied.append(Data(bytes: pointer, count: length)); remaining -= length + 1
        }
        return copied
    }

    /// argv includes the frontend name. Options end at the required --; later bytes belong only to the target.
    /// Defaults come from caller configuration rather than ambient environment or terminal guesses.
    public init(arguments argv: [Data], defaultIOMode: CommandIOMode, defaultDisconnectBehavior: StartedCommandDisconnect,
                limits: CBORLimits) throws {
        guard !argv.isEmpty, argv.count <= limits.maxItems else { throw CommandFrontendInvocationError.oversized }
        var remaining = limits.maxBytes
        for value in argv {
            guard !value.contains(0) else { throw CommandFrontendInvocationError.invalidArguments }
            guard value.count < remaining else { throw CommandFrontendInvocationError.oversized }
            remaining -= value.count + 1
        }
        guard argv.count >= 2 else { throw CommandFrontendInvocationError.unknownCommand }
        func bytes(_ text: String) -> Data { Data(text.utf8) }
        guard argv[1] == bytes("run") || argv[1] == bytes("sudo") else { throw CommandFrontendInvocationError.unknownCommand }
        var index = 2, uid: UInt32 = 0, environment: [Data: Data] = [:]
        var mode = defaultIOMode, disconnect = defaultDisconnectBehavior, rationale: String?
        func nextValue() throws -> Data {
            index += 1
            guard index < argv.count, argv[index] != bytes("--") else { throw CommandFrontendInvocationError.missingOptionValue }
            return argv[index]
        }
        while index < argv.count, argv[index] != bytes("--") {
            switch argv[index] {
            case bytes("--pty"): mode = .pty
            case bytes("--pipes"): mode = .pipes
            case bytes("--uid"):
                let value = try nextValue()
                guard !value.isEmpty else { throw CommandFrontendInvocationError.invalidUserID }
                var parsed: UInt32 = 0
                for digit in value {
                    guard (0x30...0x39).contains(digit) else { throw CommandFrontendInvocationError.invalidUserID }
                    let (scaled, overflow) = parsed.multipliedReportingOverflow(by: 10)
                    let (sum, sumOverflow) = scaled.addingReportingOverflow(UInt32(digit - 0x30))
                    guard !overflow, !sumOverflow else { throw CommandFrontendInvocationError.invalidUserID }
                    parsed = sum
                }
                uid = parsed
            case bytes("--env"):
                let value = try nextValue()
                guard let separator = value.firstIndex(of: 0x3d), separator > value.startIndex else {
                    throw CommandFrontendInvocationError.invalidEnvironment
                }
                environment[Data(value[..<separator])] = Data(value[value.index(after: separator)...])
            case bytes("--on-disconnect"):
                switch try nextValue() {
                case bytes("terminate"): disconnect = .terminate
                case bytes("continue"): disconnect = .continueRunning
                default: throw CommandFrontendInvocationError.invalidDisconnectBehavior
                }
            case bytes("--reason"):
                guard let value = String(data: try nextValue(), encoding: .utf8) else {
                    throw CommandFrontendInvocationError.invalidRationale
                }
                rationale = value
            default: throw CommandFrontendInvocationError.unknownOption
            }
            index += 1
        }
        guard index < argv.count else { throw CommandFrontendInvocationError.missingSeparator }
        index += 1
        guard index < argv.count, !argv[index].isEmpty else { throw CommandFrontendInvocationError.missingExecutable }
        arguments = Array(argv[index...]); requestedTargetUID = uid
        environmentAdditions = environment.keys.sorted { $0.lexicographicallyPrecedes($1) }.map {
            CommandEnvironmentAddition(name: $0, value: environment[$0]!)
        }
        ioMode = mode; disconnectBehavior = disconnect; unverifiedRationale = rationale
    }

    /// Copies the current directory bytes. Root must retain and recheck the named directory independently.
    public static func currentDirectory() throws -> Data {
        guard let pointer = getcwd(nil, 0) else { throw CommandFrontendInvocationError.system(errno) }
        defer { free(pointer) }
        return Data(bytes: pointer, count: strlen(pointer))
    }

    /// Resolves only the frontend's path claim. It never rewrites argv[0], follows shell syntax or grants execution authority.
    /// PATH is supplied explicitly. Relative and empty entries use the captured directory, not a later process cwd.
    public func executablePath(directory: Data, searchPath: Data) throws -> Data {
        try Self.validatePath(directory)
        guard !searchPath.contains(0) else { throw CommandFrontendInvocationError.invalidPath }
        let executable = arguments[0]
        if executable.first == 0x2f { try Self.validatePath(executable); return executable }
        if executable.contains(0x2f) { return try Self.join(directory, executable) }
        for entry in searchPath.split(separator: 0x3a, omittingEmptySubsequences: false) {
            let base: Data
            if entry.isEmpty { base = directory }
            else if entry.first == 0x2f { base = Data(entry) }
            else {
                guard let relative = try? Self.join(directory, Data(entry)) else { continue }
                base = relative
            }
            // An unusable PATH entry does not hide a later usable executable.
            guard let path = try? Self.join(base, executable) else { continue }
            var info = stat(), terminated = path; terminated.append(0)
            let found = terminated.withUnsafeBytes { fstatat(AT_FDCWD, $0.baseAddress!.assumingMemoryBound(to: CChar.self), &info, 0) }
            if found == 0, info.st_mode & S_IFMT == S_IFREG, info.st_mode & 0o111 != 0 { return path }
        }
        throw CommandFrontendInvocationError.executableNotFound
    }

    /// The authenticated handshake supplies this binding. Readiness retries replace it with fresh identifiers.
    public func submission(directory: Data, executablePath: Data, binding: CapturedSubmission,
                           schemaVersion: UInt64, limits: CBORLimits) throws -> CommandSubmission {
        try CommandSubmission(schemaVersion: schemaVersion, executablePath: executablePath, arguments: arguments,
            directoryPath: directory, requestedTargetUID: requestedTargetUID, environmentAdditions: environmentAdditions,
            ioMode: ioMode, disconnectBehavior: disconnectBehavior, unverifiedRationale: unverifiedRationale,
            binding: binding, limits: limits)
    }

    private static func validatePath(_ value: Data) throws {
        guard value.first == 0x2f, !value.contains(0), value.count < Int(PATH_MAX) else { throw CommandFrontendInvocationError.invalidPath }
    }
    private static func join(_ base: Data, _ tail: Data) throws -> Data {
        var value = base
        if value.last != 0x2f { value.append(0x2f) }
        value.append(tail); try validatePath(value); return value
    }
}
