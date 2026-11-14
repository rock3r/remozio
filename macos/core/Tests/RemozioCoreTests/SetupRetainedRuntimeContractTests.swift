import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class SetupRetainedRuntimeContractTests: XCTestCase {
    private typealias Contract = SetupRetainedRuntimeContract
    private typealias Progress = Contract.Progress
    private typealias Request = Contract.Request
    private typealias Reply = Contract.Result
    private let wide = try! CBORLimits(maxBytes: 4096, maxDepth: 8, maxItems: 256)
    private func data(_ byte: UInt8, _ count: Int = 16) -> Data { Data(repeating: byte, count: count) }
    private func progress(_ stage: Progress.Stage = .materialPending) throws -> Progress {
        try .init(macID: data(1), installationID: data(2), targetID: data(3), targetRevision: data(4), stateDigest: data(5, 32), stage: stage)
    }
    private func fields(_ bytes: Data) throws -> [UInt64: CBORValue] {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: wide) else { throw AdministrativeSetupChannelError.invalidMessage }; return f
    }
    private func encoded(_ fields: [UInt64: CBORValue]) throws -> Data { try DeterministicCBOR.encode(.map(fields), limits: wide) }
    func testAllValuesRoundTripExactlyAndKeepCommittedOutcomesSeparate() throws {
        for stage in Progress.Stage.allCases {
            let value = try progress(stage); XCTAssertEqual(try Progress.decode(value.bytes), value)
            XCTAssertEqual(value.debugDescription, value.description)
            if stage == .retainedComplete { XCTAssertThrowsError(try Request(requestID: data(6), expected: value)); continue }
            let request = try Request(requestID: data(6), expected: value)
            XCTAssertEqual(try Request.decode(request.bytes), request); try request.requireCurrent(value)
        }
        let request = try Request(requestID: data(6), expected: progress())
        for operation in Reply.Operation.allCases {
            for restoration in Reply.Restoration.allCases {
                for flags in [(false, false), (false, true), (true, false), (true, true)] {
                    let value = try Reply(requestID: request.requestID, progress: progress(.retainedComplete), operation: operation,
                        restoration: restoration, failure: .restorationFailed, cancelled: flags.0, expired: flags.1)
                    let decoded = try Reply.decode(value.bytes); XCTAssertEqual(decoded, value)
                    XCTAssertEqual(decoded.operation, operation); try decoded.requireReply(to: request)
                    XCTAssertLessThan(try value.bytes.count, Contract.maximumBytes)
                    XCTAssertEqual(decoded.debugDescription, decoded.description)
                }
            }
        }
        let late = try Reply(requestID: request.requestID, progress: nil, operation: .committed, restoration: .restored,
            cancelled: true, expired: true)
        XCTAssertEqual(try Reply.decode(late.bytes), late); try late.requireReply(to: request)
        XCTAssertThrowsError(try Reply(requestID: data(6), progress: nil, operation: .failed, restoration: .notNeeded))
        XCTAssertThrowsError(try Reply(requestID: data(6), progress: nil, operation: .unknown, restoration: .pending))
        XCTAssertThrowsError(try Reply(requestID: data(6), progress: nil, operation: .committed, restoration: .needsOwnerRecovery))
    }
    func testEveryStaleObservationAndForeignReplyScopeRefuses() throws {
        let current = try progress(), request = try Request(requestID: data(6), expected: current)
        let original = try fields(current.bytes)
        for key in UInt64(2)...7 {
            var changed = original; changed[key] = key == 7 ? .unsigned(2) : .bytes(data(99, key == 6 ? 32 : 16))
            let actual = try Progress.decode(encoded(changed))
            XCTAssertThrowsError(try request.requireCurrent(actual)) { XCTAssertEqual($0 as? AdministrativeSetupError, .staleProgress) }
            if [UInt64(2), 3, 4].contains(key) {
                let reply = try Reply(requestID: request.requestID, progress: actual, operation: .committed, restoration: .restored)
                XCTAssertThrowsError(try reply.requireReply(to: request))
            }
        }
        let foreign = try Reply(requestID: data(99), progress: current, operation: .notStarted, restoration: .notNeeded)
        XCTAssertThrowsError(try foreign.requireReply(to: request))
        try request.requireCurrent(current)
    }
    func testStrictVersionsTagsKeysTypesAndClosedEnumsRefuse() throws {
        let request = try Request(requestID: data(6), expected: progress())
        let reply = try Reply(requestID: data(6), progress: progress(), operation: .committed, restoration: .restored)
        let examples: [(Data, (Data) throws -> Void)] = [
            (try progress().bytes, { _ = try Progress.decode($0) }), (try request.bytes, { _ = try Request.decode($0) }),
            (try reply.bytes, { _ = try Reply.decode($0) })]
        for (bytes, decode) in examples {
            let original = try fields(bytes)
            for key in original.keys { var f = original; f.removeValue(forKey: key); XCTAssertThrowsError(try decode(encoded(f))) }
            var f = original; f[99] = .null; XCTAssertThrowsError(try decode(encoded(f)))
            for version in [UInt64(0), 2, .max] { f = original; f[0] = .unsigned(version); XCTAssertThrowsError(try decode(encoded(f))) }
            f = original; f[1] = .text("setup.other"); XCTAssertThrowsError(try decode(encoded(f)))
            for key in original.keys { f = original; f[key] = .array([]); XCTAssertThrowsError(try decode(encoded(f))) }
        }
        var f = try fields(progress().bytes); f[7] = .unsigned(0); XCTAssertThrowsError(try Progress.decode(encoded(f)))
        f[7] = .unsigned(6); XCTAssertThrowsError(try Progress.decode(encoded(f)))
        for key in [UInt64(4), 5, 6] {
            for unknown in [UInt64(0), 99, .max] {
                f = try fields(reply.bytes); f[key] = .unsigned(unknown); XCTAssertThrowsError(try Reply.decode(encoded(f)))
            }
        }
        for key in [UInt64(7), 8] { f = try fields(reply.bytes); f[key] = .unsigned(1); XCTAssertThrowsError(try Reply.decode(encoded(f))) }
        XCTAssertThrowsError(try Request.decode(reply.bytes)); XCTAssertThrowsError(try Reply.decode(request.bytes))
        XCTAssertThrowsError(try Progress.decode(request.bytes))
    }
    func testExactByteLengthsAndNestedObservationsAreBounded() throws {
        let original = try fields(progress().bytes)
        for key in UInt64(2)...6 {
            for count in [0, key == 6 ? 31 : 15, key == 6 ? 33 : 17] {
                var f = original; f[key] = .bytes(data(9, count)); XCTAssertThrowsError(try Progress.decode(encoded(f)))
            }
        }
        let request = try Request(requestID: data(6), expected: progress())
        let reply = try Reply(requestID: data(6), progress: progress(), operation: .committed, restoration: .restored)
        for count in [0, 15, 17] {
            var f = try fields(request.bytes); f[2] = .bytes(data(9, count)); XCTAssertThrowsError(try Request.decode(encoded(f)))
            f = try fields(reply.bytes); f[2] = .bytes(data(9, count)); XCTAssertThrowsError(try Reply.decode(encoded(f)))
        }
        var f = try fields(request.bytes); f[3] = .bytes(data(9, 1025)); XCTAssertThrowsError(try Request.decode(encoded(f)))
        f[3] = .null; XCTAssertThrowsError(try Request.decode(encoded(f)))
        f = try fields(reply.bytes); f[3] = .bytes(try request.bytes); XCTAssertThrowsError(try Reply.decode(encoded(f)))
        f = try fields(request.bytes); f[3] = .bytes(try progress(.retainedComplete).bytes)
        XCTAssertThrowsError(try Request.decode(encoded(f)))
    }
    func testTruncatedNoncanonicalDuplicateAndTrailingBytesRefuse() throws {
        let request = try Request(requestID: data(6), expected: progress())
        let reply = try Reply(requestID: data(6), progress: nil, operation: .notStarted, restoration: .notNeeded)
        let examples: [(Data, String, (Data) throws -> Void)] = [
            (try progress().bytes, Progress.formatName, { _ = try Progress.decode($0) }),
            (try request.bytes, Request.formatName, { _ = try Request.decode($0) }),
            (try reply.bytes, Reply.formatName, { _ = try Reply.decode($0) })]
        for (bytes, name, decode) in examples {
            for end in 0..<bytes.count { XCTAssertThrowsError(try decode(bytes.prefix(end))) }
            XCTAssertThrowsError(try decode(bytes + Data([0])))
            XCTAssertThrowsError(try decode(bytes + data(0, 1025)))
            let root = try XCTUnwrap(bytes.first)
            XCTAssertThrowsError(try decode(Data([root, 0, 0x18, 1]) + bytes.dropFirst(3)))
            XCTAssertThrowsError(try decode(Data([root + 1, 0, 1]) + bytes.dropFirst()))
            let a = Data([0, 1]), b = Data([1]) + (try DeterministicCBOR.encode(.text(name), limits: wide))
            XCTAssertTrue(bytes.dropFirst().starts(with: a + b))
            XCTAssertThrowsError(try decode(Data([root]) + b + a + bytes.dropFirst(1 + a.count + b.count)))
        }
    }
    func testBothPeersRequireExactCodecVersionsWithoutAdvertisingDispatch() throws {
        let hash = data(1, 20), roles: [AuthorityCodeRole] = [.app, .setupController]
        let names = [AdministrativeSetupInterface.formatName, Request.formatName, Progress.formatName, Reply.formatName]
        func release(omit: (AuthorityCodeRole, String)? = nil, badReader: Bool = false, badWriter: Bool = false) throws -> SignedReleaseEvidence {
            let components = try roles.map { role in
                let formats = try names.compactMap { name -> ReleaseFormat? in
                    if let omit, omit.0 == role && omit.1 == name && !badReader && !badWriter { return nil }
                    let version: UInt64 = name == AdministrativeSetupInterface.formatName ? Contract.version : 1
                    let changed = omit?.0 == role && omit?.1 == name
                    return try .init(name: name, readers: changed && badReader ? [99] : [version, 99],
                        writers: changed && (badWriter || badReader) ? [99] : [version])
                }
                return try ReleaseComponent(role: role, identifier: "dev.remozio.role-\(role.rawValue)", generation: 4,
                    relativePath: "Contents/Helpers/role-\(role.rawValue)", codeDirectoryHash: role == .app ? nil : hash,
                    build: "4", teamID: "ABCDEFGHIJ", formats: formats, requests: [])
            }
            return SignedReleaseEvidence(manifest: try .init(release: "0.1.0", build: "4", components: components),
                codeDirectoryHashes: [.app: hash, .setupController: hash])
        }
        let good = try release(), policy = try AuthorityCodePolicy(entries: good.manifest.components.map {
            try AuthorityCodeEntry(role: $0.role, teamID: $0.teamID, identifier: $0.identifier,
                installedGeneration: 4, minimumGeneration: 2, codeDirectoryHash: hash, active: true)
        })
        try Contract.validate(good, policy: policy)
        for role in roles { for name in names {
            XCTAssertThrowsError(try Contract.validate(release(omit: (role, name)), policy: policy))
            XCTAssertThrowsError(try Contract.validate(release(omit: (role, name), badReader: true), policy: policy))
            XCTAssertThrowsError(try Contract.validate(release(omit: (role, name), badWriter: true), policy: policy))
        } }
        XCTAssertEqual(Contract.version, 12)
        XCTAssertFalse(AdministrativeSetupInterface.supportedVersions.contains(Contract.version))
        _ = NSXPCInterface(with: RetainedRuntimeSetupXPCProtocol.self)
    }
}
