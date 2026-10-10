import Darwin
import Foundation
import RemozioProtocol

/// Read-only state at a fresh query. This grants no execution or signal permission.
public enum CommandCurrentJobState: Equatable, Sendable {
    case unknown, running
    case stopped(signal: UInt32, revision: UInt64)
}

struct CommandCurrentJobPayload: Equatable {
    let nonce: Data
    let state: CommandCurrentJobState
    var fields: CBORValue { get throws {
        guard nonce.count == 32 else { throw CommandStreamError.binding }
        switch state {
        case .unknown: return .map([0: .bytes(nonce), 1: .unsigned(0)])
        case .running: return .map([0: .bytes(nonce), 1: .unsigned(1)])
        case .stopped(let signal, let revision):
            guard signal > 0, signal < UInt32(NSIG), revision > 0 else { throw CommandStreamError.malformed }
            return .map([0: .bytes(nonce), 1: .unsigned(2), 2: .unsigned(UInt64(signal)), 3: .unsigned(revision)])
        }
    } }
    static func decode(_ raw: CBORValue) throws -> Self {
        guard case .map(let fields) = raw, case .bytes(let nonce) = fields[0], case .unsigned(let tag) = fields[1] else {
            throw CommandStreamError.malformed
        }
        let state: CommandCurrentJobState
        switch tag {
        case 0, 1:
            guard Set(fields.keys) == [0, 1] else { throw CommandStreamError.malformed }
            state = tag == 0 ? .unknown : .running
        case 2:
            guard Set(fields.keys) == [0, 1, 2, 3], case .unsigned(let signal) = fields[2], let number = UInt32(exactly: signal),
                  case .unsigned(let revision) = fields[3] else { throw CommandStreamError.malformed }
            state = .stopped(signal: number, revision: revision)
        default: throw CommandStreamError.malformed
        }
        let result = Self(nonce: nonce, state: state)
        guard try result.fields == raw else { throw CommandStreamError.malformed }
        return result
    }
}
