import Darwin
import Foundation
import RemozioProtocol
import Security

/// Metadata for the original retained streams. The request owner supplies and rechecks the authenticated caller context.
struct RetainedCommandStdioObservation {
    let layout: CapturedCommandStdioLayout
    let context: CommandCallerTerminalContext
    private let input: CommandStreamObservation
    private let output: CommandStreamObservation
    private let error: CommandStreamObservation
    private let terminal: CommandStreamObservation?

    init(received: ReceivedMachCommandInputSubmission, context: CommandCallerTerminalContext,
         mode: CommandIOMode, inputBinding: Data) throws {
        guard received.carrierVersion == MachCommandCallerReceiver.mappedIOInputCarrierVersion,
              let outputs = received.outputs else { throw RetainedCommandCaptureError.invalidContext }
        self.context = context
        input = try received.input.withBorrowedDescriptor { try CommandStreamObservation(descriptor: $0, streamBinding: inputBinding) }
        let outputBinding = try Self.binding(), errorBinding = try Self.binding()
        output = try outputs.output.withBorrowedDescriptor { try CommandStreamObservation(descriptor: $0, streamBinding: outputBinding) }
        error = try outputs.error.withBorrowedDescriptor { try CommandStreamObservation(descriptor: $0, streamBinding: errorBinding) }
        guard input.captured.access != .writeOnly, output.captured.access != .readOnly, error.captured.access != .readOnly else {
            throw RetainedCommandCaptureError.invalidContext
        }
        var mask: UInt32 = 0
        let capturedTerminal: CapturedCommandTerminal?
        if mode == .pty, let device = context.terminalDevice {
            guard let descriptor = received.controlTerminal else { throw RetainedCommandCaptureError.invalidContext }
            let binding = try Self.binding()
            let observed = try descriptor.withBorrowedDescriptor { try CommandStreamObservation(descriptor: $0, streamBinding: binding) }
            guard observed.captured.access == .readWrite, observed.captured.source.kind == .tty,
                  observed.terminalDevice == device, observed.terminalSessionID == context.sessionID else {
                throw RetainedCommandCaptureError.invalidContext
            }
            terminal = observed
            capturedTerminal = CapturedCommandTerminal(stream: observed.captured, sessionID: UInt32(context.sessionID), terminalDevice: device)
            for (index, stream) in [input, output, error].enumerated() {
                if stream.captured.source.kind == .tty, stream.captured.source.identity == observed.captured.source.identity,
                   stream.terminalDevice == device, stream.terminalSessionID == context.sessionID {
                    mask |= 1 << index
                }
            }
        } else {
            guard received.controlTerminal == nil else { throw RetainedCommandCaptureError.invalidContext }
            terminal = nil; capturedTerminal = nil
        }
        layout = CapturedCommandStdioLayout(input: input.captured, output: output.captured, error: error.captured,
            terminal: capturedTerminal, ptyMask: mask)
        try recheck(input: received.input, outputs: outputs, controlTerminal: received.controlTerminal)
    }

    func recheck(input: RetainedCommandInputDescriptor, outputs: RetainedCommandOutputChannels,
                 controlTerminal: RetainedCommandInputDescriptor?) throws {
        try input.withBorrowedDescriptor { try self.input.recheck(descriptor: $0) }
        try outputs.output.withBorrowedDescriptor { try output.recheck(descriptor: $0) }
        try outputs.error.withBorrowedDescriptor { try error.recheck(descriptor: $0) }
        if let terminal {
            guard let controlTerminal else { throw RetainedCommandCaptureError.invalidContext }
            try controlTerminal.withBorrowedDescriptor { try terminal.recheck(descriptor: $0) }
        } else { guard controlTerminal == nil else { throw RetainedCommandCaptureError.invalidContext } }
    }

    private static func binding() throws -> Data {
        var bytes = [UInt8](repeating: 0, count: 16)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else { throw MachCommandCallerError.security(status) }
        return Data(bytes)
    }
}
