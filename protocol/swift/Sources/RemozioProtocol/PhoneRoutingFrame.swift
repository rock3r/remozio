import Foundation

public enum PhoneRoutingFailure: UInt64, Sendable { case unavailable = 0, incompatible = 1 }

/// Bounded carrier for the dedicated enrolled channel. Parsing never establishes current routing or action authority.
public enum PhoneRoutingFrame: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    case status(queryNonce: Data)
    case challenge(queryNonce: Data, expectedRevision: UInt64)
    case apply(queryNonce: Data, canonicalControl: Data, signature: Data)
    case response(queryNonce: Data, canonicalPayload: Data, signature: Data)
    case failure(queryNonce: Data, reason: PhoneRoutingFailure)
    public static let applicationProtocol = "remozio-routing/1"
    public static let maximumBytes = 4096
    private static let domain = "dev.remozio.phone.routing"
    private static var limits: CBORLimits { get throws { try .init(maxBytes: maximumBytes, maxDepth: 3, maxItems: 20) } }
    private static var controlLimits: CBORLimits { get throws { try .init(maxBytes: 1024, maxDepth: 2, maxItems: 32) } }
    public var queryNonce: Data {
        switch self {
        case .status(let n), .challenge(let n, _), .apply(let n, _, _), .response(let n, _, _), .failure(let n, _): n
        }
    }
    public var description: String { "PhoneRoutingFrame(redacted)" }
    public var debugDescription: String { description }
    public func encode() throws -> Data {
        let kind: UInt64, payload: CBORValue
        guard queryNonce.count == 32 else { throw RoutingStatusError.invalidMessage }
        switch self {
        case .status: kind = 0; payload = .null
        case .challenge(_, let revision): kind = 1; payload = .unsigned(revision)
        case .apply(_, let control, let signature):
            guard signature.count == 64 else { throw RoutingStatusError.invalidMessage }
            _ = try RoutingAwayControl.decode(control, limits: Self.controlLimits)
            kind = 2; payload = .array([.bytes(control), .bytes(signature)])
        case .response(_, let body, let signature):
            guard signature.count == 64, try RoutingStatusResponse.decode(body).queryNonce == queryNonce else {
                throw RoutingStatusError.invalidMessage
            }
            kind = 3; payload = .array([.bytes(body), .bytes(signature)])
        case .failure(_, let reason): kind = 4; payload = .unsigned(reason.rawValue)
        }
        return try DeterministicCBOR.encode(.map([0: .text(Self.domain), 1: .unsigned(1), 2: .unsigned(kind),
            3: .bytes(queryNonce), 4: payload]), limits: Self.limits)
    }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case let .map(f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...4),
              f[0] == .text(domain), f[1] == .unsigned(1), case let .unsigned(kind) = f[2],
              case let .bytes(nonce) = f[3], let payload = f[4] else { throw RoutingStatusError.invalidMessage }
        let frame: Self
        switch (kind, payload) {
        case (0, .null): frame = .status(queryNonce: nonce)
        case (1, .unsigned(let revision)): frame = .challenge(queryNonce: nonce, expectedRevision: revision)
        case (2, .array(let fields)) where fields.count == 2:
            guard case let .bytes(body) = fields[0], case let .bytes(signature) = fields[1] else { throw RoutingStatusError.invalidMessage }
            frame = .apply(queryNonce: nonce, canonicalControl: body, signature: signature)
        case (3, .array(let fields)) where fields.count == 2:
            guard case let .bytes(body) = fields[0], case let .bytes(signature) = fields[1] else { throw RoutingStatusError.invalidMessage }
            frame = .response(queryNonce: nonce, canonicalPayload: body, signature: signature)
        case (4, .unsigned(let value)):
            guard let reason = PhoneRoutingFailure(rawValue: value) else { throw RoutingStatusError.invalidMessage }
            frame = .failure(queryNonce: nonce, reason: reason)
        default: throw RoutingStatusError.invalidMessage
        }
        guard try frame.encode() == bytes else { throw RoutingStatusError.invalidMessage }; return frame
    }
}
