import Foundation
import XCTest
@testable import RemozioCore

final class ImmutableRecordEncodingCacheTests: XCTestCase {
    private enum Wire: Encodable {
        case data(Data), uuid(UUID), number(UInt64), object([String: Wire])
        func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            switch self {
            case .data(let value): try container.encode(value)
            case .uuid(let value): try container.encode(value)
            case .number(let value): try container.encode(value)
            case .object(let value): try container.encode(value)
            }
        }
        var changed: Self {
            switch self {
            case .data(let value): return .data(Data(repeating: 99, count: value.count))
            case .uuid: return .uuid(UUID(uuidString: "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF")!)
            case .number(let value): return .number(value + 1)
            case .object: return .object(["device": .number(1), "inode": .number(99)])
            }
        }
    }
    private struct Box<Value: Codable & Equatable>: Codable, Equatable {
        let value: Value
    }
    private func encode<Value: Encodable>(_ value: Value) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(value)
    }
    private func runtimeFields(version: UInt64 = 2) -> [String: Wire] {
        let identity = Wire.data(Data(repeating: 1, count: 16)), digest = Wire.data(Data(repeating: 2, count: 32))
        let uuid = Wire.uuid(UUID(uuidString: "12345678-1234-1234-1234-123456789ABC")!)
        var fields: [String: Wire] = ["formatVersion": .number(version), "activationAttempt": uuid,
            "macID": identity, "installationID": identity, "accountID": identity,
            "candidateDigest": digest, "sourceInventoryDigest": digest, "admissionDigest": digest,
            "sourceAccountDigest": digest, "sourcePolicyRevision": uuid, "sourcePolicyDigest": digest,
            "previousInstalledReleaseDigest": digest, "installedReleaseDigest": digest, "updateID": digest,
            "startupPolicyDigest": digest, "completionPolicyDigest": digest]
        if version == 2 { fields["runtimeReferenceDigest"] = digest }
        return fields
    }
    private func activationFields(version: UInt64 = 1, phase: UInt64 = 1) -> [String: Wire] {
        let identity = Wire.data(Data(repeating: 3, count: 16)), digest = Wire.data(Data(repeating: 4, count: 32))
        let uuid = Wire.uuid(UUID(uuidString: "23456789-2345-2345-2345-23456789ABCD")!)
        var fields: [String: Wire] = ["formatVersion": .number(version), "attemptID": uuid, "revision": uuid,
            "macID": identity, "installationID": identity, "updateID": digest, "generation": .number(7),
            "candidateDigest": digest, "inventoryDigest": digest, "admissionDigest": digest,
            "machineAdmission": .object(["device": .number(1), "inode": .number(12)]), "phase": .number(phase)]
        if version >= 2 { fields["policyPreflightDigest"] = digest }
        return fields
    }

    func testRuntimeBytesAndEqualitySurviveCachedAndNestedDecodeForBothVersions() throws {
        for version: UInt64 in 1...2 {
            let expected = try encode(runtimeFields(version: version))
            let uncached = try JSONDecoder().decode(RuntimeReleaseBinding.self, from: expected)
            let cached = try RuntimeReleaseBinding.decode(expected)
            XCTAssertEqual(cached, uncached)
            XCTAssertEqual(try cached.encoded, expected)
            XCTAssertEqual(try uncached.encoded, expected)
            XCTAssertEqual(try encode(cached), expected)
            let nestedBytes = try encode(Box(value: cached))
            let nested = try JSONDecoder().decode(Box<RuntimeReleaseBinding>.self, from: nestedBytes)
            XCTAssertEqual(nested.value, cached)
            XCTAssertEqual(try nested.value.encoded, expected)
            XCTAssertEqual(try encode(nested), nestedBytes)
        }
    }

    func testActivationBytesAndEqualitySurviveCachedAndNestedDecodeForAllRetainedPhases() throws {
        for (version, phase): (UInt64, UInt64) in [(1, 1), (1, 2), (1, 3), (1, 4), (2, 2), (2, 3), (3, 5), (4, 6)] {
            let expected = try encode(activationFields(version: version, phase: phase))
            let uncached = try JSONDecoder().decode(MachineUpdateActivationRecord.self, from: expected)
            let cached = try MachineUpdateActivationRecord.decode(expected)
            XCTAssertEqual(cached, uncached)
            XCTAssertEqual(try cached.encoded, expected)
            XCTAssertEqual(try uncached.encoded, expected)
            XCTAssertEqual(try encode(cached), expected)
            let nestedBytes = try encode(Box(value: cached))
            let nested = try JSONDecoder().decode(Box<MachineUpdateActivationRecord>.self, from: nestedBytes)
            XCTAssertEqual(nested.value, cached)
            XCTAssertEqual(try nested.value.encoded, expected)
            XCTAssertEqual(try encode(nested), nestedBytes)
        }
    }

    func testEqualityStillComparesEveryOriginalField() throws {
        let runtime = runtimeFields(), activation = activationFields(version: 2, phase: 2)
        let binding = try RuntimeReleaseBinding.decode(encode(runtime))
        let record = try MachineUpdateActivationRecord.decode(encode(activation))
        for (key, value) in runtime {
            var changed = runtime; changed[key] = value.changed
            let other = try JSONDecoder().decode(RuntimeReleaseBinding.self, from: encode(changed))
            XCTAssertNotEqual(binding, other, key)
        }
        for (key, value) in activation {
            var changed = activation; changed[key] = value.changed
            let other = try JSONDecoder().decode(MachineUpdateActivationRecord.self, from: encode(changed))
            XCTAssertNotEqual(record, other, key)
        }
    }

    func testReturnedDataCopiesCannotChangeEitherRecord() throws {
        let runtimeBytes = try encode(runtimeFields()), activationBytes = try encode(activationFields())
        let binding = try RuntimeReleaseBinding.decode(runtimeBytes)
        let record = try MachineUpdateActivationRecord.decode(activationBytes)
        var a = try binding.encoded, b = try record.encoded
        a[a.startIndex] ^= 0xff; b.removeAll(keepingCapacity: false)
        XCTAssertNotEqual(a, runtimeBytes); XCTAssertNotEqual(b, activationBytes)
        XCTAssertEqual(try binding.encoded, runtimeBytes)
        XCTAssertEqual(try record.encoded, activationBytes)
    }

    func testNestedDecodeRetainsValidationAndUncheckedTransitionFallback() throws {
        var runtime = runtimeFields(); runtime["accountID"] = .data(Data([1]))
        let binding = try JSONDecoder().decode(Box<RuntimeReleaseBinding>.self,
            from: encode(["value": Wire.object(runtime)])).value
        XCTAssertThrowsError(try binding.encoded) { XCTAssertEqual($0 as? RuntimePreparationError, .invalidRecord) }
        var activation = activationFields(); activation["generation"] = .number(0)
        let record = try JSONDecoder().decode(Box<MachineUpdateActivationRecord>.self,
            from: encode(["value": Wire.object(activation)])).value
        XCTAssertThrowsError(try record.encoded) { XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord) }
        let started = try record.starting(policyPreflightDigest: Data(repeating: 8, count: 32))
        XCTAssertEqual(started.phase, .activationStarted)
        XCTAssertThrowsError(try started.encoded) { XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord) }
    }

    func testCachesCannotAdmitNoncanonicalOrExtraFields() throws {
        let runtime = try encode(runtimeFields()), activation = try encode(activationFields())
        for invalid in [runtime + Data([0x20]), try encode(runtimeFields().merging(["storedEncoded": .data(runtime)]) { _, new in new })] {
            XCTAssertThrowsError(try RuntimeReleaseBinding.decode(invalid))
        }
        for invalid in [activation + Data([0x20]), try encode(activationFields().merging(["storedEncoded": .data(activation)]) { _, new in new })] {
            XCTAssertThrowsError(try MachineUpdateActivationRecord.decode(invalid))
        }
    }
}
