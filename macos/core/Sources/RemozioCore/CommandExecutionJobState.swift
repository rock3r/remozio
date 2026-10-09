import Darwin
import Foundation
import RemozioMach
import RemozioProtocol

/// Tracing metadata from the stop snapshot. It does not establish the historical stop cause.
public enum CommandStopTracing: UInt64, Equatable, Sendable { case unknown = 0, untraced = 1, traced = 2 }

/// Observed state of the original native target. A nested foreground job has its own owner.
public enum CommandExecutionJobState: Equatable, Sendable {
    case stopped(signal: UInt32, rawStopCode: UInt32, tracing: CommandStopTracing)
    case continued
}

/// Bounded observation data. It grants no release, retry, signal or process-identity authority.
struct CommandJobStatePayload: Equatable {
    let revision: UInt64
    let state: CommandExecutionJobState
    init(revision: UInt64, state: CommandExecutionJobState) { self.revision = revision; self.state = state }
    init(nativeRecord: remozio_monitor_record_t) throws {
        var record = nativeRecord, bytes = [UInt8](repeating: 0, count: Int(REMOZIO_MONITOR_RECORD_BYTES))
        guard record.tag == UInt32(REMOZIO_MONITOR_JOB_STATE.rawValue),
              record.flags & UInt32(REMOZIO_MONITOR_TARGET_RELEASE_ATTEMPTED.rawValue) != 0,
              remozio_monitor_record_encode(&record, &bytes) == 0 else { throw CommandStreamError.malformed }
        revision = record.job_revision
        if record.flags & UInt32(REMOZIO_MONITOR_STOPPED.rawValue) != 0 {
            let tracing: CommandStopTracing = record.flags & UInt32(REMOZIO_MONITOR_TRACING_KNOWN.rawValue) == 0 ? .unknown :
                (record.flags & UInt32(REMOZIO_MONITOR_TRACED.rawValue) == 0 ? .untraced : .traced)
            state = .stopped(signal: record.detail, rawStopCode: record.stop_code, tracing: tracing)
        } else { state = .continued }
    }
    var fields: CBORValue { get throws {
        guard revision > 0 else { throw CommandStreamError.sequence }
        switch state {
        case .continued: return .map([0: .unsigned(revision), 1: .unsigned(2)])
        case .stopped(let signal, let code, let tracing):
            guard signal > 0, signal < UInt32(NSIG), [UInt32(CLD_STOPPED), UInt32(CLD_TRAPPED)].contains(code) else {
                throw CommandStreamError.malformed
            }
            return .map([0: .unsigned(revision), 1: .unsigned(1), 2: .unsigned(UInt64(signal)),
                         3: .unsigned(UInt64(code)), 4: .unsigned(tracing.rawValue)])
        }
    } }
    static func decode(_ raw: CBORValue) throws -> Self {
        guard case .map(let fields) = raw, case .unsigned(let revision) = fields[0],
              case .unsigned(let tag) = fields[1] else { throw CommandStreamError.malformed }
        let state: CommandExecutionJobState
        switch tag {
        case 1:
            guard Set(fields.keys) == [0, 1, 2, 3, 4], case .unsigned(let signal) = fields[2], let number = UInt32(exactly: signal),
                  case .unsigned(let code) = fields[3], let rawCode = UInt32(exactly: code),
                  case .unsigned(let tracing) = fields[4], let snapshot = CommandStopTracing(rawValue: tracing) else {
                throw CommandStreamError.malformed
            }
            state = .stopped(signal: number, rawStopCode: rawCode, tracing: snapshot)
        case 2:
            guard Set(fields.keys) == [0, 1] else { throw CommandStreamError.malformed }
            state = .continued
        default: throw CommandStreamError.malformed
        }
        let value = Self(revision: revision, state: state)
        guard try value.fields == raw else { throw CommandStreamError.malformed }
        return value
    }
}
