import Foundation
import XCTest
@testable import RemozioCore

final class NetworkByteChannelTests: XCTestCase, @unchecked Sendable {
    private final class Driver: ByteConnectionDriver, @unchecked Sendable {
        let started = XCTestExpectation(description: "started")
        let receiving = XCTestExpectation(description: "receiving")
        let sending = XCTestExpectation(description: "sending")
        private let lock = NSLock()
        private var event: (@Sendable (ByteConnectionEvent) -> Void)?
        private var read: (@Sendable (Data?, Bool, Bool) -> Void)?
        private var write: (@Sendable (Bool) -> Void)?
        private var cancellations = 0
        private var sent = Data()
        var cancelCount: Int { lock.withLock { cancellations } }
        var sentBytes: Data { lock.withLock { sent } }
        func start(_ event: @escaping @Sendable (ByteConnectionEvent) -> Void) {
            lock.withLock { self.event = event }; started.fulfill()
        }
        func receive(_ result: @escaping @Sendable (Data?, Bool, Bool) -> Void) {
            lock.withLock { read = result }; receiving.fulfill()
        }
        func send(_ data: Data, result: @escaping @Sendable (Bool) -> Void) {
            lock.withLock { sent = data; write = result }; sending.fulfill()
        }
        func cancel() { lock.withLock { cancellations += 1 } }
        func emit(_ value: ByteConnectionEvent) { lock.withLock { event }?(value) }
        func completeRead(_ data: Data?, ended: Bool = false, failed: Bool = false) {
            lock.withLock { read }?(data, ended, failed)
        }
        func completeWrite(failed: Bool = false) { lock.withLock { write }?(failed) }
    }

    private func opened(cancellation: ChannelCancellation = ChannelCancellation()) async throws -> (NetworkByteChannel, Driver) {
        let driver = Driver()
        let channel = NetworkByteChannel(driver: driver, cancellation: cancellation)
        let start = Task { try await channel.start() }
        await fulfillment(of: [driver.started], timeout: 2)
        driver.emit(.ready)
        try await start.value
        return (channel, driver)
    }

    private func expectFailure<T>(_ task: Task<T, Error>) async {
        do { _ = try await task.value; XCTFail("Expected channel failure") } catch { }
    }

    func testNoBytesBeforeAdmissionAndNoRepeatedStart() async throws {
        let driver = Driver()
        let channel = NetworkByteChannel(driver: driver)
        await expectFailure(Task { try await channel.receive() })
        let start = Task { try await channel.start() }
        await fulfillment(of: [driver.started], timeout: 2)
        await expectFailure(Task { try await channel.send(Data([1])) })
        await expectFailure(Task { try await channel.start() })
        driver.emit(.ready)
        try await start.value
        await expectFailure(Task { try await channel.start() })
        await channel.close()
    }

    func testOneReadAndWriteCanRunTogetherWithoutQueueingExtras() async throws {
        let (channel, driver) = try await opened()
        let read = Task { try await channel.receive() }
        let write = Task { try await channel.send(Data([3, 4])) }
        await fulfillment(of: [driver.receiving, driver.sending], timeout: 2)
        await expectFailure(Task { try await channel.receive() })
        await expectFailure(Task { try await channel.send(Data([5])) })
        XCTAssertEqual(driver.sentBytes, Data([3, 4]))
        driver.completeRead(Data([1, 2])); driver.completeWrite()
        let bytes = try await read.value
        XCTAssertEqual(bytes, Data([1, 2]))
        try await write.value
        await channel.close()
    }

    func testCloseSettlesBothWaitersAndLateCallbacksCannotReopen() async throws {
        let (channel, driver) = try await opened()
        let read = Task { try await channel.receive() }
        let write = Task { try await channel.send(Data([1])) }
        await fulfillment(of: [driver.receiving, driver.sending], timeout: 2)
        await channel.close(); await channel.close()
        await expectFailure(read); await expectFailure(write)
        driver.completeRead(Data([9])); driver.completeWrite(); driver.emit(.ready)
        await expectFailure(Task { try await channel.receive() })
        await expectFailure(Task { try await channel.send(Data([9])) })
        XCTAssertEqual(driver.cancelCount, 1)
    }

    func testOpeningDeadlineAndCancellationSettleTheStart() async throws {
        let driver = Driver()
        let channel = NetworkByteChannel(driver: driver)
        let start = Task { try await channel.start(timeoutMilliseconds: 10) }
        await expectFailure(start)
        XCTAssertEqual(driver.cancelCount, 1)
        driver.emit(.ready)
        await expectFailure(Task { try await channel.receive() })

        let other = Driver()
        let cancelled = NetworkByteChannel(driver: other)
        let pending = Task { try await cancelled.start() }
        await fulfillment(of: [other.started], timeout: 2)
        pending.cancel()
        await expectFailure(pending)
        XCTAssertEqual(other.cancelCount, 1)
    }

    func testReadCancellationClosesTheWriteToo() async throws {
        let (channel, driver) = try await opened()
        let read = Task { try await channel.receive() }
        let write = Task { try await channel.send(Data([1])) }
        await fulfillment(of: [driver.receiving, driver.sending], timeout: 2)
        read.cancel()
        await expectFailure(read); await expectFailure(write)
        XCTAssertEqual(driver.cancelCount, 1)
    }

    func testCancellationWinsBeforeAWriteCallbackEvenWithoutQueuedClose() async throws {
        let cancellation = ChannelCancellation()
        let (channel, driver) = try await opened(cancellation: cancellation)
        let read = Task { try await channel.receive() }
        let write = Task { try await channel.send(Data([1])) }
        await fulfillment(of: [driver.receiving, driver.sending], timeout: 2)
        cancellation.cancel()
        driver.completeWrite()
        await expectFailure(write); await expectFailure(read)
        XCTAssertEqual(driver.cancelCount, 1)
    }

    func testCancellationWinsBeforeAReadCallbackEvenWithoutQueuedClose() async throws {
        let cancellation = ChannelCancellation()
        let (channel, driver) = try await opened(cancellation: cancellation)
        let read = Task { try await channel.receive() }
        let write = Task { try await channel.send(Data([1])) }
        await fulfillment(of: [driver.receiving, driver.sending], timeout: 2)
        cancellation.cancel()
        driver.completeRead(Data([9]))
        await expectFailure(read); await expectFailure(write)
        XCTAssertEqual(driver.cancelCount, 1)
    }

    func testCancelledEOFFastPathCannotReturnSuccess() async throws {
        let cancellation = ChannelCancellation()
        let (channel, driver) = try await opened(cancellation: cancellation)
        let read = Task { try await channel.receive() }
        await fulfillment(of: [driver.receiving], timeout: 2)
        driver.completeRead(nil, ended: true)
        _ = try await read.value
        cancellation.cancel()
        await expectFailure(Task { try await channel.receive() })
        XCTAssertEqual(driver.cancelCount, 1)
    }

    func testFailureNeverReturnsPartialData() async throws {
        let (channel, driver) = try await opened()
        let read = Task { try await channel.receive() }
        await fulfillment(of: [driver.receiving], timeout: 2)
        driver.completeRead(Data([1]), failed: true)
        await expectFailure(read)
        XCTAssertEqual(driver.cancelCount, 1)
    }

    func testEOFDeliversFinalBytesAndAllowsAResponse() async throws {
        let (channel, driver) = try await opened()
        let read = Task { try await channel.receive() }
        await fulfillment(of: [driver.receiving], timeout: 2)
        driver.completeRead(Data([1]), ended: true)
        let bytes = try await read.value
        XCTAssertEqual(bytes, Data([1]))
        let eof = try await channel.receive()
        XCTAssertNil(eof)
        let write = Task { try await channel.send(Data([2])) }
        await fulfillment(of: [driver.sending], timeout: 2)
        driver.completeWrite()
        try await write.value
        await channel.close()
    }

    func testInvalidReadProgressAndOversizedChunksFailClosed() async throws {
        for bytes in [Data(), Data(repeating: 1, count: NetworkByteChannel.maximumChunkBytes + 1)] {
            let (channel, driver) = try await opened()
            let read = Task { try await channel.receive() }
            await fulfillment(of: [driver.receiving], timeout: 2)
            driver.completeRead(bytes)
            await expectFailure(read)
            XCTAssertEqual(driver.cancelCount, 1)
        }
    }

    func testInvalidWriteSizeDoesNotCloseAnUnusedChannel() async throws {
        let (channel, driver) = try await opened()
        for bytes in [Data(), Data(repeating: 1, count: NetworkByteChannel.maximumChunkBytes + 1)] {
            await expectFailure(Task { try await channel.send(bytes) })
        }
        XCTAssertEqual(driver.cancelCount, 0)
        await channel.close()
    }

    func testNativeFailureSettlesOpeningAndWriteFailureClosesChannel() async throws {
        let driver = Driver()
        let channel = NetworkByteChannel(driver: driver)
        let start = Task { try await channel.start() }
        await fulfillment(of: [driver.started], timeout: 2)
        driver.emit(.failed)
        await expectFailure(start)
        let (other, writer) = try await opened()
        let write = Task { try await other.send(Data([1])) }
        await fulfillment(of: [writer.sending], timeout: 2)
        writer.completeWrite(failed: true)
        await expectFailure(write)
        XCTAssertEqual(writer.cancelCount, 1)
    }
}
