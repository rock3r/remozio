import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class CommandHandshakeCodecTests: XCTestCase {
    private let nonce = Data(repeating: 1, count: 32)
    private let mac = Data(repeating: 2, count: 16)
    private let account = Data(repeating: 3, count: 16)
    private func profile(wire: UInt64 = 1, input: UInt64 = 2) -> CommandHandshakeProfile {
        .init(wireVersion: wire, submissionSchemaVersion: 1, inputCarrierVersion: input,
            callerBinding: Data(repeating: 4, count: 16), macID: mac, accountID: account)
    }
    func testCurrentOfferRoundTripAndProfileMatch() throws {
        let offer = try CommandHandshakeOffer(nonce: nonce)
        XCTAssertEqual(try CommandHandshakeOffer(canonicalBytes: offer.canonicalBytes), offer)
        let selected = profile()
        let reply = try CommandHandshakeReply(nonce: nonce, profile: selected).bytes
        XCTAssertEqual(try CommandHandshakeReply.decode(reply, offer: offer, macID: mac, accountID: account), selected)
    }
    func testEmptyOversizedZeroAndDuplicateCapabilityDeclarationsFail() throws {
        for values: Set<UInt64> in [[], [0], [65536], Set(1...17)] {
            XCTAssertThrowsError(try CommandHandshakeCapabilities(wireVersions: values, submissionSchemaVersions: [1], inputCarrierVersions: [2]))
        }
        let limits = try CommandHandshakeOffer.limits()
        for versions: [CBORValue] in [[.unsigned(1), .unsigned(1)], [.unsigned(2), .unsigned(1)], [.text("1")]] {
            let raw: CBORValue = .map([0: .unsigned(1), 1: .bytes(nonce), 2: .map([
                0: .array(versions), 1: .array([.unsigned(1)]), 2: .array([.unsigned(2)]),
            ])])
            XCTAssertThrowsError(try CommandHandshakeOffer(canonicalBytes: DeterministicCBOR.encode(raw, limits: limits)))
        }
    }
    func testUnknownCriticalFieldsAndFormatVersionAreRejected() throws {
        let limits = try CommandHandshakeOffer.limits()
        for fields: [UInt64: CBORValue] in [
            [0: .unsigned(2), 1: .bytes(nonce), 2: CommandHandshakeCapabilities.current.fields],
            [0: .unsigned(1), 1: .bytes(nonce), 2: CommandHandshakeCapabilities.current.fields, 3: .text("ignored?")],
        ] {
            XCTAssertThrowsError(try CommandHandshakeOffer(canonicalBytes: DeterministicCBOR.encode(.map(fields), limits: limits)))
        }
        XCTAssertThrowsError(try CommandHandshakeOffer(canonicalBytes: Data(count: CommandHandshakeOffer.maximumBytes + 1)))
    }
    func testReplyRequiresExactOfferNonceScopeAndKnownSelection() throws {
        let offer = try CommandHandshakeOffer(nonce: nonce)
        let wrongNonce = try CommandHandshakeReply(nonce: Data(repeating: 9, count: 32), profile: profile()).bytes
        XCTAssertThrowsError(try CommandHandshakeReply.decode(wrongNonce, offer: offer, macID: mac, accountID: account))
        let reply = try CommandHandshakeReply(nonce: nonce, profile: profile()).bytes
        for scope in [(Data(repeating: 9, count: 16), account), (mac, Data(repeating: 9, count: 16))] {
            XCTAssertThrowsError(try CommandHandshakeReply.decode(reply, offer: offer, macID: scope.0, accountID: scope.1)) {
                XCTAssertEqual($0 as? MachCommandHandshakeError, .wrongBinding)
            }
        }
        for selected in [profile(wire: 2), profile(input: 1)] {
            XCTAssertThrowsError(try CommandHandshakeReply.decode(CommandHandshakeReply(nonce: nonce, profile: selected).bytes,
                offer: offer, macID: mac, accountID: account)) {
                XCTAssertEqual($0 as? MachCommandHandshakeError, .incompatible)
            }
        }
    }
    func testIncompatibilityCannotCarryAnAcceptedProfileAndUnknownReplyStatusFails() throws {
        let offer = try CommandHandshakeOffer(nonce: nonce), limits = try CommandHandshakeOffer.limits()
        for status: UInt64 in [0, 2, 3] {
            let bytes = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(nonce),
                2: .unsigned(status), 3: profile().fields]), limits: limits)
            XCTAssertThrowsError(try CommandHandshakeReply.decode(bytes, offer: offer, macID: mac, accountID: account)) {
                XCTAssertEqual($0 as? MachCommandHandshakeError, .invalidMessage)
            }
        }
        let rejected = try CommandHandshakeReply(nonce: nonce, profile: nil).bytes
        XCTAssertThrowsError(try CommandHandshakeReply.decode(rejected, offer: offer, macID: mac, accountID: account)) {
            XCTAssertEqual($0 as? MachCommandHandshakeError, .incompatible)
        }
    }
    func testAdmissionReplyCarrierRequiresExplicitOfferAndLegacySelectionStaysUnchanged() throws {
        let offer = try CommandHandshakeOffer(nonce: nonce, capabilities: .admissionReplies), selected = profile(input: 3)
        let reply = try CommandHandshakeReply(nonce: nonce, profile: selected).bytes
        XCTAssertEqual(try CommandHandshakeReply.decode(reply, offer: offer, macID: mac, accountID: account), selected)
        XCTAssertThrowsError(try CommandHandshakeReply.decode(reply, offer: CommandHandshakeOffer(nonce: nonce), macID: mac, accountID: account))
        XCTAssertThrowsError(try CommandHandshakeReply.decode(CommandHandshakeReply(nonce: nonce, profile: profile()).bytes,
            offer: offer, macID: mac, accountID: account))
        XCTAssertEqual(CommandHandshakeCapabilities.current.inputCarrierVersions, [2])
        XCTAssertEqual(CommandHandshakeCapabilities.admissionReplies.inputCarrierVersions, [3])
    }

    func testTypedResultWireNeedsExplicitNegotiationAndTheReplyCarrier() throws {
        let selected = profile(wire: 2, input: 3), offer = try CommandHandshakeOffer(nonce: nonce, capabilities: .admissionResults)
        let bytes = try CommandHandshakeReply(nonce: nonce, profile: selected).bytes
        XCTAssertEqual(try CommandHandshakeReply.decode(bytes, offer: offer, macID: mac, accountID: account), selected)
        for old in [CommandHandshakeCapabilities.current, .admissionReplies] {
            XCTAssertThrowsError(try CommandHandshakeReply.decode(bytes, offer: CommandHandshakeOffer(nonce: nonce, capabilities: old), macID: mac, accountID: account))
        }
        let incompatible = try CommandHandshakeOffer(nonce: nonce, capabilities: .init(wireVersions: [2], submissionSchemaVersions: [1], inputCarrierVersions: [2]))
        XCTAssertThrowsError(try CommandHandshakeReply.decode(CommandHandshakeReply(nonce: nonce, profile: profile(wire: 2, input: 2)).bytes,
            offer: incompatible, macID: mac, accountID: account))
        XCTAssertEqual(CommandHandshakeCapabilities.current.wireVersions, [1])
    }

    func testExecutionChannelsRequireWireThreeAndCarrierFourWithoutChangingLegacyProfiles() throws {
        let selected = profile(wire: 3, input: 4)
        let offer = try CommandHandshakeOffer(nonce: nonce, capabilities: .executionChannels)
        let bytes = try CommandHandshakeReply(nonce: nonce, profile: selected).bytes
        XCTAssertEqual(try CommandHandshakeReply.decode(bytes, offer: offer, macID: mac, accountID: account), selected)
        XCTAssertTrue(selected.supportsExecutionChannels); XCTAssertTrue(selected.supportsAdmissionResults)
        for old in [CommandHandshakeCapabilities.current, .admissionReplies, .admissionResults] {
            XCTAssertThrowsError(try CommandHandshakeReply.decode(bytes,
                offer: CommandHandshakeOffer(nonce: nonce, capabilities: old), macID: mac, accountID: account))
        }
        for invalid in [profile(wire: 3, input: 3), profile(wire: 2, input: 4), profile(wire: 1, input: 4)] {
            XCTAssertFalse(invalid.supported(by: .executionChannels))
        }
        XCTAssertEqual(CommandHandshakeCapabilities.current.wireVersions, [1])
        XCTAssertEqual(CommandHandshakeCapabilities.current.inputCarrierVersions, [2])
        XCTAssertEqual(CommandHandshakeCapabilities.admissionResults.wireVersions, [2])
        XCTAssertEqual(CommandHandshakeCapabilities.admissionResults.inputCarrierVersions, [3])
    }

}
