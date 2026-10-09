import Darwin
import Foundation

/// Owns bounded private IO inside the serialized execution controller. This owner cannot release or repeat a command.
final class CommandPTYStreamPump {
    private let pty: RetainedCommandPTY
    private let channel: MachCommandStreamAuthority
    private var input = Data()
    private var inputAllowance = CommandStreamFrame.inputWindow
    private var pendingCredit = 0
    private var inputEnded = false
    private var inputUnavailable = false
    private var eofBytes: Data?
    private var eofWritten = false
    private var output: Data?
    private var outputEOF = false
    private var outputEndSent = false
    private(set) var opened = false
    private(set) var connected = true

    init(pty: RetainedCommandPTY, channel: MachCommandStreamAuthority) {
        self.pty = pty; self.channel = channel
    }
    var readyForTerminal: Bool { !opened || !connected || outputEndSent && channel.outputDrained }
    func open() throws -> Bool {
        guard connected else { throw CommandStreamError.closed }
        if opened { return true }
        opened = try channel.send(.opened)
        return opened
    }
    // The callbacks run only within this bounded turn. The pump never retains its native process owner.
    func poll(expression: String, userID: uid_t, auditSessionID: au_asid_t?, checkCaller: () throws -> Void,
              checkControlPolicy: () throws -> Void, applyControl: (CommandStreamFrame.Body) throws -> Void) throws {
        guard opened else { return }
        if connected {
            do {
                try checkCaller()
                for _ in 0..<4 {
                    guard let body = try channel.receiveControl(expression: expression, userID: userID, auditSessionID: auditSessionID) else { break }
                    try checkControlPolicy()
                    switch body {
                    case .input(let bytes):
                        guard !inputEnded, bytes.count <= inputAllowance,
                              input.count <= CommandStreamFrame.inputWindow - bytes.count else { throw CommandStreamError.capacity }
                        inputAllowance -= bytes.count; input.append(bytes)
                    case .inputEnd: inputEnded = true
                    case .signal, .resize, .cancel: try applyControl(body)
                    case .outputDrained: break
                    default: throw CommandStreamError.malformed
                    }
                }
            } catch { detach(); throw error }
        }
        for _ in 0..<4 {
            try pumpInput()
            if connected, !outputEndSent, pendingCredit > 0 {
                let credit = pendingCredit
                if try channel.send(.inputCredit(UInt32(credit))) {
                    pendingCredit -= credit; inputAllowance += credit
                }
            }
            if let bytes = output {
                if connected {
                    guard try channel.send(.output(bytes)) else { break }
                }
                output = nil
            }
            if !outputEOF {
                switch try pty.read(maximumBytes: CommandStreamFrame.maximumChunk) {
                case .waiting: break
                case .bytes(let bytes): output = bytes
                case .end: outputEOF = true
                }
            }
            if outputEOF, output == nil, pendingCredit == 0, connected, !outputEndSent {
                outputEndSent = try channel.send(.outputEnd)
            }
        }
    }
    private func pumpInput() throws {
        if outputEOF || inputUnavailable { input = Data(); return }
        do { try writeInput() }
        catch RetainedCommandPTYError.native(let error) where error == EPIPE || error == EIO {
            input = Data(); inputUnavailable = true; eofWritten = true
        }
    }
    private func writeInput() throws {
        if !input.isEmpty {
            let bytes = Data(input.prefix(CommandStreamFrame.maximumChunk))
            let written = try pty.write(bytes)
            if written > 0 {
                let remaining = input.count - written
                var retained = Data(count: remaining)
                if remaining > 0 {
                    retained.withUnsafeMutableBytes { destination in
                        input.copyBytes(to: destination.bindMemory(to: UInt8.self), from: written..<input.count)
                    }
                }
                input = retained
                if connected { pendingCredit += written }
            }
        }
        if inputEnded, input.isEmpty, !eofWritten {
            // No bytes are invented for raw input. Recheck the application's current canonical mode on later turns.
            if eofBytes == nil { eofBytes = try pty.currentCanonicalEOFSequence() }
            if let bytes = eofBytes {
                let written = try pty.write(bytes)
                if written > 0 {
                    eofBytes = Data(bytes.dropFirst(written))
                    if eofBytes?.isEmpty == true { eofWritten = true }
                }
            }
        }
    }
    func detach() {
        guard connected else { return }
        connected = false; inputEnded = true; pendingCredit = 0; output = nil; channel.close()
        // Accepted input stays bounded and is flushed for a selected continuing command. Native cancellation belongs to the controller.
    }
    func signalForeground(_ number: Int32) throws { try pty.signalForeground(number) }
    func resize(_ size: winsize) throws { try pty.resize(size) }
    func finishDelivery() { channel.close(); connected = false }
    func close() { channel.close(); pty.close() }
}
