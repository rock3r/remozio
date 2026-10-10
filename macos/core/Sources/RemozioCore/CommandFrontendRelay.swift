import Darwin
import Foundation
import RemozioProtocol

public enum CommandFrontendRelayError: Error, Equatable {
    case incompatibleProfile, invalidConfiguration, invalidProgress, closed
}

public enum CommandFrontendRelayObservation {
    case waiting, progress, foregroundRequired, interrupted, suspended
    case jobState(VerifiedCommandExecutionJobObservation)
    case terminal(VerifiedCommandTerminalResult)
}

protocol CommandFrontendExecutionChannel: AnyObject {
    var executionIOMode: CommandIOMode? { get }
    func pollStreamEvent(timeoutMilliseconds: UInt32) throws -> CommandExecutionStreamEvent?
    func forwardInput(_ bytes: Data) throws -> Int
    func finishInput() throws -> Bool
    func acknowledgeOutput() throws -> Bool
    func resizeTerminal(rows: UInt16, columns: UInt16, pixelWidth: UInt16, pixelHeight: UInt16) throws -> Bool
    func forwardSignal(_ signal: UInt32) throws -> Bool
    func cancelCommand() throws -> Bool
    func close()
}

extension RetainedCommandExecutionSession: CommandFrontendExecutionChannel {}

/// Relays the original admitted channel. It cannot approve, execute, resubmit or take terminal foreground.
/// The CLI serializes every call and owns the signal loop. Poll waits never limit the command lifetime.
public final class CommandFrontendRelay {
    private let channel: any CommandFrontendExecutionChannel
    private let terminal: (any CommandFrontendTerminalIO)?
    private let mode: CommandIOMode
    private var opened = false, active = false, suspended = false, closed = false
    private var input = Data(), output = Data()
    private var inputCapacity = 0
    private var inputEnded = false, inputEndSent = false
    private var outputEnded = false, outputAcknowledged = false
    private var pendingSize: CommandFrontendTerminalSize?
    private var sentSize: CommandFrontendTerminalSize?
    public private(set) var terminalResult: VerifiedCommandTerminalResult?

    /// PTY mode uses the separate calling terminal. Open its lease before command submission.
    public convenience init(session: RetainedCommandExecutionSession, terminal: CommandFrontendTerminal) throws {
        guard session.executionIOMode == .pty else { throw CommandFrontendRelayError.incompatibleProfile }
        try self.init(channel: session, terminal: terminal)
    }
    /// Pipes preserve original stdio under Root routing. This owner reads and writes no local stream.
    public convenience init(pipeSession: RetainedCommandExecutionSession) throws {
        guard pipeSession.executionIOMode == .pipes else { throw CommandFrontendRelayError.incompatibleProfile }
        try self.init(channel: pipeSession, terminal: nil)
    }
    init(channel: any CommandFrontendExecutionChannel, terminal: (any CommandFrontendTerminalIO)?) throws {
        guard let mode = channel.executionIOMode, (mode == .pty) == (terminal != nil) else {
            throw CommandFrontendRelayError.incompatibleProfile
        }
        self.channel = channel; self.terminal = terminal; self.mode = mode
    }
    deinit { channel.close(); terminal?.closeReportingFailure() }
    public var needsTerminalRestoration: Bool { terminal?.needsRestore ?? false }

    /// Perform one bounded turn. The caller waits between idle turns and yields to its local signal loop on interruption.
    public func advance(timeoutMilliseconds: UInt32 = 250) throws -> CommandFrontendRelayObservation {
        guard (1...60_000).contains(timeoutMilliseconds) else { throw CommandFrontendRelayError.invalidConfiguration }
        if terminalResult != nil { return try finishTerminal() }
        guard !closed else { throw CommandFrontendRelayError.closed }
        if suspended { return .suspended }
        do { return try turn(timeoutMilliseconds: timeoutMilliseconds) }
        catch CommandExecutionStreamPollError.interrupted {
            active = false
            if terminal?.needsRestore == true { try? terminal?.restore() }
            return .interrupted
        } catch CommandFrontendTerminalError.native(let number) where number == EINTR {
            active = false
            // An interrupted terminal operation may retain raw settings. Do not reactivate over them.
            if terminal?.needsRestore == true { try? terminal?.restore() }
            return .interrupted
        } catch CommandFrontendTerminalError.native(let number) where number == EAGAIN {
            active = false
            if terminal?.needsRestore == true { try? terminal?.restore() }
            return .foregroundRequired
        } catch {
            retireAfterFailure()
            throw error
        }
    }
    private func turn(timeoutMilliseconds: UInt32) throws -> CommandFrontendRelayObservation {
        var progressed = false
        if opened, let terminal {
            if !(try terminal.isForeground()) {
                active = false
                if terminal.needsRestore { try terminal.restore() }
                return .foregroundRequired
            }
            if !active {
                if terminal.needsRestore { try terminal.restore() }
                try terminal.activate(); active = true; progressed = true
            }
            let size = try terminal.dimensions()
            if size != sentSize { pendingSize = size }
            if let size = pendingSize, try channel.resizeTerminal(rows: size.rows, columns: size.columns,
                    pixelWidth: size.pixelWidth, pixelHeight: size.pixelHeight) {
                sentSize = size; pendingSize = nil; progressed = true
            }
            if !output.isEmpty {
                let count = try terminal.write(output)
                guard (0...output.count).contains(count) else { throw CommandFrontendRelayError.invalidProgress }
                if count > 0 { output = Data(output.dropFirst(count)); progressed = true }
                // Input must still progress while the local output suffix remains blocked.
            }
            if !outputEnded {
                if input.isEmpty, !inputEnded, inputCapacity > 0 {
                    switch try terminal.read(maximumBytes: min(inputCapacity, CommandStreamFrame.maximumChunk)) {
                    case .waiting: break
                    case .end: inputEnded = true; progressed = true
                    case .bytes(let bytes):
                        guard !bytes.isEmpty, bytes.count <= min(inputCapacity, CommandStreamFrame.maximumChunk) else {
                            throw CommandFrontendRelayError.invalidProgress
                        }
                        input = bytes; progressed = true
                    }
                }
                if !input.isEmpty {
                    let count = try channel.forwardInput(input)
                    guard count == 0 || count == input.count else { throw CommandFrontendRelayError.invalidProgress }
                    if count > 0 { inputCapacity -= count; input = Data(); progressed = true }
                }
                if inputEnded, input.isEmpty, !inputEndSent {
                    inputEndSent = try channel.finishInput(); progressed = progressed || inputEndSent
                }
            }
        }
        if mode == .pty, outputEnded, output.isEmpty, !outputAcknowledged {
            outputAcknowledged = try channel.acknowledgeOutput()
            progressed = progressed || outputAcknowledged
        }
        // Retain one output chunk while allowing independent input and controls to progress.
        if !output.isEmpty { return progressed ? .progress : .waiting }
        if progressed { return .progress }
        guard let event = try channel.pollStreamEvent(timeoutMilliseconds: timeoutMilliseconds) else { return .waiting }
        switch event {
        case .opened:
            guard !opened else { throw CommandFrontendRelayError.invalidProgress }
            opened = true; inputCapacity = mode == .pty ? CommandStreamFrame.inputWindow : 0
        case .output(let bytes):
            guard opened, mode == .pty, !outputEnded, output.isEmpty,
                  (1...CommandStreamFrame.maximumChunk).contains(bytes.count) else { throw CommandFrontendRelayError.invalidProgress }
            output = bytes
        case .outputEnded:
            guard opened, mode == .pty, !outputEnded else { throw CommandFrontendRelayError.invalidProgress }
            outputEnded = true
        case .inputCapacity(let count):
            guard opened, mode == .pty, count >= inputCapacity, count <= CommandStreamFrame.inputWindow else {
                throw CommandFrontendRelayError.invalidProgress
            }
            inputCapacity = count
        case .jobState(let observation):
            // The CLI must reconcile the current local signal and foreground state before any suspension.
            return .jobState(observation)
        case .terminal(let result):
            terminalResult = result; channel.close(); closed = true
            return try finishTerminal()
        }
        return .progress
    }
    private func finishTerminal() throws -> CommandFrontendRelayObservation {
        guard let terminalResult else { throw CommandFrontendRelayError.closed }
        do { try terminal?.close(); active = false }
        catch CommandFrontendTerminalError.native(let number) where number == EAGAIN { return .foregroundRequired }
        catch CommandFrontendTerminalError.native(let number) where number == EINTR { return .interrupted }
        return .terminal(terminalResult)
    }

    /// Restore before the CLI performs a cooperative stop. A failure leaves suspension incomplete and preserves cleanup.
    public func prepareForSuspension() throws {
        active = false; try terminal?.restore(); suspended = true
    }
    public func resume() { suspended = false }
    /// Known-zero sends can be retried by the CLI. These controls never submit or repeat a command.
    public func forwardSignal(_ number: UInt32) throws -> Bool {
        guard opened, !closed else { throw CommandFrontendRelayError.closed }
        do { return try channel.forwardSignal(number) }
        catch { retireAfterFailure(); throw error }
    }
    public func cancelCommand() throws -> Bool {
        guard opened, !closed else { throw CommandFrontendRelayError.closed }
        do { return try channel.cancelCommand() }
        catch { retireAfterFailure(); throw error }
    }
    private func retireAfterFailure() {
        channel.close(); closed = true; active = false
        try? terminal?.restore()
    }
    /// Disconnect the original channel, then restore. Failed restoration retains its owner for another close attempt.
    public func close() throws {
        channel.close(); closed = true; active = false
        try terminal?.close()
    }
}
