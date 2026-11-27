import Foundation
import XCTest

struct CommandCarrierVectors: Decodable {
    struct Carrier: Decodable {
        let valid: [Row]
        let invalid: [Row]
    }

    struct Row: Decodable {
        private enum FormatError: Error { case oddHexLength(String) }

        let name: String
        let hex: String

        func bytes() throws -> Data {
            let characters = Array(hex.utf8)
            guard characters.count.isMultiple(of: 2) else { throw FormatError.oddHexLength(name) }
            return try Data(stride(from: 0, to: characters.count, by: 2).map { offset in
                let pair = String(decoding: characters[offset..<(offset + 2)], as: UTF8.self)
                return try XCTUnwrap(UInt8(pair, radix: 16), "Invalid hex for \(name)")
            })
        }
    }

    struct SignedCarrier: Decodable {
        let valid: [Row]
        let invalid: [Row]
        let signingInputs: [Row]
    }

    let decisionRefusalFrame: SignedCarrier
    let approvalMessage: Carrier
    let sessionEnvelope: Carrier
    let requestStatusQuery: Carrier
    let requestDeliveryResult: Carrier
    struct RepairNotices: Decodable {
        let valid: [Row]
        let invalid: [Row]
        let signingInput: [Row]
        let decisionKey: [Row]
    }
    let phoneRepairNotice: RepairNotices

    static func load() throws -> Self {
        let protocolRoot = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let file = protocolRoot.appendingPathComponent("vectors/command-carriers-v1.json")
        return try JSONDecoder().decode(Self.self, from: Data(contentsOf: file))
    }
}
