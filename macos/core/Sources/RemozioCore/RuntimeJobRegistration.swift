import Darwin
import Foundation

/// Operational launchd fields only. They do not prove process health, credentials or immutable job settings.
struct LaunchdJobObservation {
    let path: String
    let program: String
    let arguments: [String]
    let kind: String
    static func decode(_ bytes: Data, target: String) throws -> Self {
        guard bytes.count <= 65_536, let text = String(data: bytes, encoding: .utf8), !text.utf8.contains(0) else { throw RuntimeActivationError.unavailable }
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        guard lines.first == target + " = {", lines.dropLast().last == "}" else { throw RuntimeActivationError.unavailable }
        var fields: [String: String] = [:], arguments: [String] = [], inArguments = false, sawArguments = false
        for line in lines.dropFirst().dropLast(2) {
            if inArguments {
                if line == "\t}" { inArguments = false; continue }
                guard line.hasPrefix("\t\t"), arguments.count < 32 else { throw RuntimeActivationError.unavailable }
                let value = String(line.dropFirst(2))
                guard value.utf8.count < 4096, !value.contains("\r"), !value.contains("\t") else { throw RuntimeActivationError.unavailable }
                arguments.append(value); continue
            }
            if line == "\targuments = {" {
                guard !sawArguments else { throw RuntimeActivationError.unavailable }
                inArguments = true; sawArguments = true; continue
            }
            for key in ["path", "program", "type"] where line.hasPrefix("\t" + key + " = ") {
                guard fields[key] == nil else { throw RuntimeActivationError.unavailable }
                let value = String(line.dropFirst(key.count + 4))
                guard !value.isEmpty, value.utf8.count < 4096, !value.contains("\r"), !value.contains("\t") else { throw RuntimeActivationError.unavailable }
                fields[key] = value
            }
        }
        guard !inArguments, sawArguments, let path = fields["path"], let program = fields["program"], let kind = fields["type"] else {
            throw RuntimeActivationError.unavailable
        }
        return .init(path: path, program: program, arguments: arguments, kind: kind)
    }
    func matches(_ job: InstalledAccountJobManifest) -> Bool {
        kind == "LaunchDaemon" && path == job.path && program == job.executablePath && arguments == job.arguments
    }
}

/// No stop, remove, replacement or blanket launchctl command is exposed here.
enum RuntimeJobRegistration {
    enum Observation { case absent, matching, conflicting }
    static func ensure(_ job: InstalledAccountJobManifest, verifyCurrent: () throws -> Void) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let target = "system/" + job.declaration.label
        try reconcile(verifyCurrent: verifyCurrent, inspect: {
            let result = try BoundedNativeCommand.run(executable: "/bin/launchctl", arguments: ["print", target])
            if result.exitCode == 113, let error = String(data: result.errorOutput, encoding: .utf8),
               error.contains("Could not find service \"" + job.declaration.label + "\"") { return .absent }
            guard result.exitCode == 0 else { throw RuntimeActivationError.unavailable }
            return try LaunchdJobObservation.decode(result.output, target: target).matches(job) ? .matching : .conflicting
        }, bootstrap: {
            _ = try BoundedNativeCommand.run(executable: "/bin/launchctl", arguments: ["bootstrap", "system", job.path])
        })
    }
    // Sequencing fixtures do not prove system-domain admission or the loaded process's identity.
    static func reconcile(verifyCurrent: () throws -> Void, inspect: () throws -> Observation,
                          bootstrap: () throws -> Void) throws {
        try verifyCurrent()
        switch try inspect() {
        case .matching: try verifyCurrent(); return
        case .conflicting: throw RuntimeActivationError.conflictingPlan
        case .absent: break
        }
        try verifyCurrent()
        // A failed or timed-out call can still have registered the exact job. Reconcile without replacing it.
        do { try bootstrap() } catch { }
        try verifyCurrent()
        switch try inspect() {
        case .matching: try verifyCurrent()
        case .conflicting: throw RuntimeActivationError.conflictingPlan
        case .absent: throw RuntimeActivationError.unavailable
        }
    }
}
