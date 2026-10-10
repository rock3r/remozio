import Darwin
import Foundation
import RemozioMach

/// Read-only observations from one original audit incarnation. They grant no command or process authority.
struct CommandCallerTerminalContext {
    private let original: remozio_command_terminal_context_t
    private let auditBinding: Data
    var sessionID: Int32 { original.session }
    var terminalDevice: UInt32? { original.has_terminal ? original.terminal_device : nil }

    init(originalAuditToken token: audit_token_t) throws {
        var expected = token, observed = remozio_command_terminal_context_t()
        let error = remozio_command_terminal_context_capture(&expected, &observed)
        guard error == 0 else { throw CommandCallerTerminalContextError.native(error) }
        original = observed
        auditBinding = withUnsafeBytes(of: &expected) { Data($0) }
    }

    func recheck(originalAuditToken token: audit_token_t) throws {
        var expected = token, saved = original
        guard withUnsafeBytes(of: &expected, { Data($0) }) == auditBinding else { throw CommandCallerTerminalContextError.binding }
        let error = remozio_command_terminal_context_recheck(&expected, &saved)
        guard error == 0 else { throw CommandCallerTerminalContextError.native(error) }
    }
}

enum CommandCallerTerminalContextError: Error, Equatable {
    case binding
    case native(Int32)
}
