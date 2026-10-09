import Darwin
import Foundation
import RemozioMach
import XCTest

final class CommandMonitorProtocolTests: XCTestCase {
    private let preparedTag = UInt32(REMOZIO_MONITOR_PREPARED.rawValue)
    private let jobTag = UInt32(REMOZIO_MONITOR_JOB_STATE.rawValue)
    private let reapedTag = UInt32(REMOZIO_MONITOR_TARGET_REAPED.rawValue)
    private let failureTag = UInt32(REMOZIO_MONITOR_FAILURE.rawValue)
    private let stoppedFlag = UInt32(REMOZIO_MONITOR_STOPPED.rawValue)
    private let knownFlag = UInt32(REMOZIO_MONITOR_TRACING_KNOWN.rawValue)
    private let tracedFlag = UInt32(REMOZIO_MONITOR_TRACED.rawValue)
    private let birthFlag = UInt32(REMOZIO_MONITOR_BIRTH_KNOWN.rawValue)
    private let releasedFlag = UInt32(REMOZIO_MONITOR_TARGET_RELEASE_ATTEMPTED.rawValue)

    private func prepared(birth: Bool = true) -> remozio_monitor_record_t {
        var record = remozio_monitor_record_t()
        record.tag = preparedTag; record.target_pid = 42; record.sequence = 1
        if birth { record.flags = birthFlag; record.birth_seconds = 1_700_000_000; record.birth_microseconds = 999_999 }
        return record
    }
    private func event(_ tag: UInt32, sequence: UInt64, revision: UInt64 = 0, released: Bool = true, birth: Bool = true) -> remozio_monitor_record_t {
        var record = prepared(birth: birth)
        record.tag = tag; record.sequence = sequence; record.job_revision = revision
        if released { record.flags |= releasedFlag }
        return record
    }
    private func stop(sequence: UInt64 = 2, revision: UInt64 = 1, traced: Bool? = false, birth: Bool = true) -> remozio_monitor_record_t {
        var record = event(jobTag, sequence: sequence, revision: revision, birth: birth)
        record.flags |= stoppedFlag; record.detail = UInt32(SIGSTOP); record.stop_code = UInt32(CLD_STOPPED)
        if let traced { record.flags |= knownFlag; if traced { record.flags |= tracedFlag } }
        return record
    }
    private func encode(_ value: remozio_monitor_record_t) throws -> [UInt8] {
        var record = value, bytes = [UInt8](repeating: 0xa5, count: Int(REMOZIO_MONITOR_RECORD_BYTES))
        XCTAssertEqual(remozio_monitor_record_encode(&record, &bytes), 0)
        return bytes
    }
    private func accept(_ state: inout remozio_monitor_stream_t, _ value: remozio_monitor_record_t, file: StaticString = #filePath, line: UInt = #line) {
        var record = value
        XCTAssertEqual(remozio_monitor_stream_accept(&state, &record), 0, file: file, line: line)
    }
    private func reject(_ state: inout remozio_monitor_stream_t, _ value: remozio_monitor_record_t, file: StaticString = #filePath, line: UInt = #line) {
        let before = withUnsafeBytes(of: state) { Array($0) }
        var record = value
        XCTAssertEqual(remozio_monitor_stream_accept(&state, &record), EPROTO, file: file, line: line)
        XCTAssertEqual(withUnsafeBytes(of: state) { Array($0) }, before, file: file, line: line)
    }
    private func released(birth: Bool = true) -> remozio_monitor_stream_t {
        var state = remozio_monitor_stream_t(); remozio_monitor_stream_init(&state)
        accept(&state, prepared(birth: birth)); XCTAssertEqual(remozio_monitor_stream_note_release(&state), 0)
        return state
    }

    func testCanonicalPreparedRecordUsesExplicitVersionAndNetworkByteOrder() throws {
        let expected = "524d4d310000000100000001000000080000002a00000000000000000000000000000000000000010000000000000000000000006553f10000000000000f423f"
        XCTAssertEqual(try encode(prepared()).map { String(format: "%02x", $0) }.joined(), expected)
        XCTAssertEqual(REMOZIO_MONITOR_RECORD_BYTES, 64)
    }
    func testRoundTripsSupportedRecordShapesWithoutInferringStopCause() throws {
        var trap = stop(traced: true); trap.detail = UInt32(SIGTRAP); trap.stop_code = UInt32(CLD_TRAPPED)
        var normalExit = event(reapedTag, sequence: 4, revision: 2); normalExit.detail = 7 << 8
        var signalExit = normalExit; signalExit.detail = UInt32(SIGKILL)
        var coreExit = normalExit; coreExit.detail = UInt32(SIGSEGV) | 0x80
        var failure = remozio_monitor_record_t(); failure.tag = failureTag; failure.sequence = 1; failure.detail = UInt32(ENOENT)
        let values = [prepared(), prepared(birth: false), stop(traced: nil), stop(), trap,
            event(jobTag, sequence: 3, revision: 2), normalExit, signalExit, coreExit, failure]
        for value in values {
            let bytes = try encode(value)
            var decoded = remozio_monitor_record_t()
            XCTAssertEqual(bytes.withUnsafeBytes { remozio_monitor_record_decode($0.baseAddress, $0.count, &decoded) }, 0)
            XCTAssertEqual(try encode(decoded), bytes)
        }
    }
    func testTruncationOverlongRecordsAndMalformedHeadersClearTheDecodedOutput() throws {
        let bytes = try encode(prepared())
        for count in 0..<64 {
            var decoded = prepared()
            XCTAssertEqual(bytes.withUnsafeBytes { remozio_monitor_record_decode($0.baseAddress, count, &decoded) }, EPROTO)
            XCTAssertEqual(decoded.target_pid, 0); XCTAssertEqual(decoded.sequence, 0); XCTAssertEqual(decoded.flags, 0)
        }
        var extended = bytes + [0], decoded = prepared()
        XCTAssertEqual(remozio_monitor_record_decode(&extended, extended.count, &decoded), EPROTO)
        for offset in [0, 7, 11, 12, 28] {
            var changed = bytes; changed[offset] ^= 0x80; decoded = prepared()
            XCTAssertEqual(changed.withUnsafeBytes { remozio_monitor_record_decode($0.baseAddress, $0.count, &decoded) }, EPROTO)
            XCTAssertEqual(decoded.target_pid, 0); XCTAssertEqual(decoded.sequence, 0)
        }
    }
    func testRejectsInvalidFieldsAndNonterminalOrNoncanonicalWaitStatuses() throws {
        var noSequence = prepared(); noSequence.sequence = 0
        var noPID = prepared(birth: false); noPID.target_pid = 0
        var badBirth = prepared(); badBirth.birth_microseconds = 1_000_000
        var noBirthFlag = prepared(); noBirthFlag.flags = 0
        var tracedUnknown = stop(traced: nil); tracedUnknown.flags |= tracedFlag
        var continuedKnown = event(jobTag, sequence: 2, revision: 1); continuedKnown.flags |= knownFlag
        var invalidStop = stop(); invalidStop.detail = UInt32(NSIG)
        var preparedReleased = prepared(); preparedReleased.flags |= releasedFlag
        var noFailure = event(failureTag, sequence: 2); noFailure.detail = 0
        var invalidRecords = [noSequence, noPID, badBirth, noBirthFlag, tracedUnknown, continuedKnown, invalidStop, preparedReleased, noFailure]
        for status in [UInt32(0x7f | (SIGSTOP << 8)), 0xffff, UInt32(NSIG), UInt32(SIGKILL) | (1 << 8), 0x1_0000] {
            var record = event(reapedTag, sequence: 2); record.detail = status; invalidRecords.append(record)
        }
        for var record in invalidRecords {
            var bytes = [UInt8](repeating: 0, count: 64)
            XCTAssertEqual(remozio_monitor_record_encode(&record, &bytes), EPROTO)
        }
    }
    func testReleasedLifecycleAllowsCoalescedJobRevisionsAndRetainsActualWaitStatus() {
        var state = released()
        accept(&state, stop(revision: 4, traced: nil))
        accept(&state, event(jobTag, sequence: 3, revision: 8))
        var terminal = event(reapedTag, sequence: 4, revision: 9); terminal.detail = 7 << 8
        accept(&state, terminal)
        XCTAssertTrue(state.prepared); XCTAssertTrue(state.release_attempted); XCTAssertTrue(state.reaped); XCTAssertFalse(state.failed)
        XCTAssertEqual(state.latest.detail, 7 << 8); XCTAssertEqual(state.last_job_revision, 9)
        reject(&state, event(jobTag, sequence: 5, revision: 10))
        terminal.sequence = 5; reject(&state, terminal)
    }
    func testReleaseMarkerConsumesOneAttemptAndCannotBeGrantedByAReport() {
        var state = remozio_monitor_stream_t(); remozio_monitor_stream_init(&state)
        XCTAssertEqual(remozio_monitor_stream_note_release(&state), EBUSY)
        reject(&state, stop(sequence: 1))
        accept(&state, prepared())
        var repeated = prepared(); repeated.sequence = 2; reject(&state, repeated)
        reject(&state, stop())
        XCTAssertEqual(remozio_monitor_stream_note_release(&state), 0)
        XCTAssertEqual(remozio_monitor_stream_note_release(&state), EALREADY)
        var terminal = event(reapedTag, sequence: 2, released: false); terminal.detail = UInt32(SIGKILL)
        accept(&state, stop())
        terminal.sequence = 3; reject(&state, terminal)
        terminal.flags |= releasedFlag; terminal.job_revision = 1; accept(&state, terminal)
        XCTAssertEqual(remozio_monitor_stream_note_release(&state), EALREADY)
    }
    func testTargetCanRetireBeforeReceivingAnAlreadyAttemptedRootRelease() {
        var state = released()
        var terminal = event(reapedTag, sequence: 2, released: false); terminal.detail = UInt32(SIGKILL)
        accept(&state, terminal)
        XCTAssertTrue(state.release_attempted); XCTAssertFalse(state.target_release_attempted); XCTAssertTrue(state.reaped)
        XCTAssertEqual(remozio_monitor_stream_note_release(&state), EALREADY)
    }
    func testFailureQueuedBeforeRootReleaseDoesNotFalselyClaimTargetRelease() {
        var state = released()
        var failure = event(failureTag, sequence: 2, released: false); failure.detail = UInt32(EPIPE)
        accept(&state, failure)
        var terminal = event(reapedTag, sequence: 3, released: false); terminal.detail = 70 << 8; accept(&state, terminal)
        XCTAssertTrue(state.release_attempted); XCTAssertFalse(state.target_release_attempted); XCTAssertTrue(state.failed)
        XCTAssertEqual(state.failure_error, UInt32(EPIPE)); XCTAssertTrue(state.reaped)
    }
    func testPreparedCancellationCanBeReapedWithoutRelease() {
        var state = remozio_monitor_stream_t(); remozio_monitor_stream_init(&state)
        accept(&state, prepared())
        var terminal = event(reapedTag, sequence: 2, released: false); terminal.detail = UInt32(SIGKILL)
        accept(&state, terminal)
        XCTAssertFalse(state.release_attempted); XCTAssertTrue(state.reaped)
        XCTAssertEqual(remozio_monitor_stream_note_release(&state), EBUSY)
    }
    func testFailureBeforeSpawnCannotIntroduceAReplacementTarget() {
        var state = remozio_monitor_stream_t(); remozio_monitor_stream_init(&state)
        var failure = remozio_monitor_record_t(); failure.tag = failureTag; failure.sequence = 1; failure.detail = UInt32(ENOENT)
        accept(&state, failure)
        var next = prepared(); next.sequence = 2; reject(&state, next)
        next = event(reapedTag, sequence: 2, released: false); next.detail = UInt32(SIGKILL); reject(&state, next)
        failure.sequence = 2; reject(&state, failure)
        XCTAssertEqual(remozio_monitor_stream_note_release(&state), EBUSY)
        XCTAssertTrue(state.failed); XCTAssertFalse(state.reaped); XCTAssertEqual(state.failure_error, UInt32(ENOENT))
    }
    func testSetupFailureWithSpawnedTargetRetainsItsReapingResponsibility() {
        var state = remozio_monitor_stream_t(); remozio_monitor_stream_init(&state)
        var failure = event(failureTag, sequence: 1, released: false); failure.detail = UInt32(EIO)
        accept(&state, failure)
        var terminal = event(reapedTag, sequence: 2, released: false); terminal.detail = UInt32(SIGKILL)
        accept(&state, terminal)
        XCTAssertFalse(state.prepared); XCTAssertFalse(state.release_attempted); XCTAssertTrue(state.failed); XCTAssertTrue(state.reaped)
        XCTAssertEqual(state.failure_error, UInt32(EIO)); XCTAssertEqual(state.latest.detail, UInt32(SIGKILL))
    }
    func testFailureAfterReleasePreservesBothTheFailureAndFinalReapedResult() {
        var state = released(); accept(&state, stop(revision: 4))
        var failure = event(failureTag, sequence: 3); failure.detail = UInt32(ECHILD)
        accept(&state, failure)
        reject(&state, event(jobTag, sequence: 4, revision: 5))
        var terminal = event(reapedTag, sequence: 4, revision: 3); terminal.detail = 7 << 8; reject(&state, terminal)
        terminal.job_revision = 4; accept(&state, terminal)
        XCTAssertTrue(state.failed); XCTAssertTrue(state.reaped); XCTAssertEqual(state.failure_error, UInt32(ECHILD))
        XCTAssertEqual(state.latest.detail, 7 << 8)
    }
    func testRejectsDuplicateSkippedRegressedAndWrappedSequencesWithoutMutatingState() {
        var state = released()
        reject(&state, stop(sequence: 1)); reject(&state, stop(sequence: 3)); reject(&state, prepared())
        accept(&state, stop())
        reject(&state, stop(sequence: 2, revision: 2)); reject(&state, stop(sequence: 1, revision: 2))
        var duplicatePrepared = prepared(); duplicatePrepared.sequence = 3; reject(&state, duplicatePrepared)
        state.latest.sequence = UInt64.max
        reject(&state, event(jobTag, sequence: 0, revision: 2)); reject(&state, event(jobTag, sequence: 1, revision: 2))
    }
    func testTargetPIDAndBirthBindingCannotChangeOrBecomeKnownLater() {
        for birth in [true, false] {
            var state = released(birth: birth)
            var changed = stop(birth: birth); changed.target_pid = 43; reject(&state, changed)
            changed = stop(birth: !birth); reject(&state, changed)
            if birth {
                changed = stop(); changed.birth_seconds += 1; reject(&state, changed)
                changed = stop(); changed.birth_microseconds -= 1; reject(&state, changed)
            }
            accept(&state, stop(birth: birth))
        }
    }
    func testRepeatedOrRegressedJobRevisionsAreRejectedButUnknownTracingIsRetained() {
        var state = released(); accept(&state, stop(revision: 9, traced: nil))
        XCTAssertEqual(state.latest.flags & (knownFlag | tracedFlag), 0)
        reject(&state, event(jobTag, sequence: 3, revision: 9)); reject(&state, event(jobTag, sequence: 3, revision: 8))
        accept(&state, event(jobTag, sequence: 3, revision: 12))
        XCTAssertEqual(state.latest.flags & (stoppedFlag | knownFlag | tracedFlag), 0)
    }
    func testFirstReapedReportAndRepeatedFailureNeverEstablishAValidStream() {
        var state = remozio_monitor_stream_t(); remozio_monitor_stream_init(&state)
        var terminal = event(reapedTag, sequence: 1, released: false); terminal.detail = 7 << 8; reject(&state, terminal)
        accept(&state, prepared())
        var failure = event(failureTag, sequence: 2, released: false); failure.detail = UInt32(ETIMEDOUT); accept(&state, failure)
        failure.sequence = 3; reject(&state, failure)
        XCTAssertEqual(remozio_monitor_stream_note_release(&state), EBUSY)
    }
    func testNullArgumentsFailWithoutChangingExistingStream() {
        var state = released(), record = stop(), decoded = prepared(), bytes = [UInt8](repeating: 0, count: 64)
        XCTAssertEqual(remozio_monitor_stream_accept(nil, &record), EINVAL)
        XCTAssertEqual(remozio_monitor_stream_accept(&state, nil), EINVAL)
        XCTAssertEqual(remozio_monitor_stream_note_release(nil), EINVAL)
        XCTAssertEqual(remozio_monitor_record_encode(&record, nil), EINVAL)
        XCTAssertEqual(remozio_monitor_record_encode(nil, &bytes), EPROTO)
        XCTAssertEqual(remozio_monitor_record_decode(nil, 64, &decoded), EPROTO)
        XCTAssertEqual(remozio_monitor_record_decode(&bytes, 64, nil), EINVAL)
        XCTAssertEqual(state.latest.sequence, 1); XCTAssertEqual(decoded.sequence, 0)
    }

    func testCanonicalVersionedControlRecordsCarryNoTargetPID() {
        var control = remozio_monitor_control_t()
        control.tag = UInt32(REMOZIO_MONITOR_CANCEL.rawValue); control.sequence = 1
        var bytes = [UInt8](repeating: 0, count: Int(REMOZIO_MONITOR_CONTROL_BYTES))
        XCTAssertEqual(remozio_monitor_control_encode(&control, &bytes), 0)
        XCTAssertEqual(bytes.map { String(format: "%02x", $0) }.joined(), "524d4b3100000001000000020000000000000000000000010000000000000000")
        var decoded = remozio_monitor_control_t()
        XCTAssertEqual(bytes.withUnsafeBytes { remozio_monitor_control_decode($0.baseAddress, $0.count, &decoded) }, 0)
        XCTAssertEqual(decoded.tag, control.tag); XCTAssertEqual(decoded.sequence, 1); XCTAssertEqual(decoded.signal, 0)
        control.tag = UInt32(REMOZIO_MONITOR_SIGNAL.rawValue); control.signal = UInt32(SIGCONT); control.sequence = 2
        XCTAssertEqual(remozio_monitor_control_encode(&control, &bytes), 0)
        XCTAssertEqual(bytes.withUnsafeBytes { remozio_monitor_control_decode($0.baseAddress, $0.count, &decoded) }, 0)
        XCTAssertEqual(decoded.signal, UInt32(SIGCONT)); XCTAssertEqual(decoded.sequence, 2)
    }
    func testTruncatedUnsupportedAndReservedControlBytesAreRejected() {
        var control = remozio_monitor_control_t()
        control.tag = UInt32(REMOZIO_MONITOR_SIGNAL.rawValue); control.signal = UInt32(SIGTERM); control.sequence = 1
        var bytes = [UInt8](repeating: 0, count: 32), decoded = control
        XCTAssertEqual(remozio_monitor_control_encode(&control, &bytes), 0)
        for count in 0..<32 {
            decoded = control
            XCTAssertEqual(bytes.withUnsafeBytes { remozio_monitor_control_decode($0.baseAddress, count, &decoded) }, EPROTO)
            XCTAssertEqual(decoded.sequence, 0); XCTAssertEqual(decoded.tag, 0)
        }
        for offset in [0, 7, 11, 12, 24] {
            var changed = bytes; changed[offset] ^= 0x80; decoded = control
            XCTAssertEqual(changed.withUnsafeBytes { remozio_monitor_control_decode($0.baseAddress, $0.count, &decoded) }, EPROTO)
            XCTAssertEqual(decoded.sequence, 0)
        }
        var extended = bytes + [0]
        XCTAssertEqual(remozio_monitor_control_decode(&extended, extended.count, &decoded), EPROTO)
    }
    func testInvalidControlTagsSequencesAndSignalsAreRejected() {
        var control = remozio_monitor_control_t(), bytes = [UInt8](repeating: 0, count: 32)
        control.tag = UInt32(REMOZIO_MONITOR_SIGNAL.rawValue); control.signal = UInt32(SIGTERM)
        XCTAssertEqual(remozio_monitor_control_encode(&control, &bytes), EPROTO)
        control.sequence = 1; control.signal = 0
        XCTAssertEqual(remozio_monitor_control_encode(&control, &bytes), EPROTO)
        control.signal = UInt32(NSIG)
        XCTAssertEqual(remozio_monitor_control_encode(&control, &bytes), EPROTO)
        control.tag = UInt32(REMOZIO_MONITOR_CANCEL.rawValue); control.signal = UInt32(SIGTERM)
        XCTAssertEqual(remozio_monitor_control_encode(&control, &bytes), EPROTO)
        control.tag = 99; control.signal = 0
        XCTAssertEqual(remozio_monitor_control_encode(&control, &bytes), EPROTO)
        XCTAssertEqual(remozio_monitor_control_encode(nil, &bytes), EPROTO)
        XCTAssertEqual(remozio_monitor_control_encode(&control, nil), EINVAL)
        XCTAssertEqual(remozio_monitor_control_decode(nil, 32, &control), EPROTO)
        XCTAssertEqual(remozio_monitor_control_decode(&bytes, 32, nil), EINVAL)
    }
}
