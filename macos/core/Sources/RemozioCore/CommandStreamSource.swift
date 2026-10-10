import Darwin
import RemozioMach

/// Binds dynamic terminal aliases in the submitting process before creating fileports.
enum CommandStreamSource {
    static func withRetainedDescriptor<T>(_ source: Int32, _ body: (Int32) throws -> T) throws -> T {
        var descriptor: Int32 = -1
        let error = remozio_command_stream_source_retain(source, &descriptor)
        guard error == 0 else { throw RetainedCommandInputError.system(error) }
        defer { _ = Darwin.close(descriptor) }
        return try body(descriptor)
    }

    /// A receiver cannot resolve a dynamic alias on behalf of the authenticated caller.
    static func rejectTerminalAlias(_ descriptor: Int32) throws {
        var alias = false
        let error = remozio_command_stream_source_is_terminal_alias(descriptor, &alias)
        guard error == 0 else { throw RetainedCommandInputError.system(error) }
        guard !alias else { throw MachCommandCallerError.malformed }
    }
}
