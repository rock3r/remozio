import Foundation
import RemozioProtocol

/// Sent only by the authenticated Root connection. This snapshot does not replace signed mapping controls or revocation history.
public struct GatewayHostSnapshot: Sendable {
    public let registration: GatewayRegistrationIdentity
    public let rootEpoch: UUID
    public let sequence: UInt64
    public let observedAtMilliseconds: UInt64
    public let leaseDeadlineMilliseconds: UInt64
    public let enrollments: [GatewayPhoneEnrollment]
    public let active: Bool
    public let phoneRouting: Bool
    public let canonicalBytes: Data

    public init(registration: GatewayRegistrationIdentity, rootEpoch: UUID, sequence: UInt64, observedAtMilliseconds: UInt64, leaseDeadlineMilliseconds: UInt64,
                enrollments: [GatewayPhoneEnrollment], active: Bool, phoneRouting: Bool) throws {
        guard sequence > 0, leaseDeadlineMilliseconds > observedAtMilliseconds,
              enrollments.count <= 1024, Set(enrollments.map(\.phoneID)).count == enrollments.count else {
            throw GatewayServiceError.invalidMessage
        }
        self.registration = registration; self.rootEpoch = rootEpoch; self.sequence = sequence; self.observedAtMilliseconds = observedAtMilliseconds
        self.leaseDeadlineMilliseconds = leaseDeadlineMilliseconds; self.active = active; self.phoneRouting = phoneRouting
        self.enrollments = enrollments.sorted { $0.phoneID.lexicographicallyPrecedes($1.phoneID) }
        canonicalBytes = try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(Self.bytes(rootEpoch)),
            2: .unsigned(sequence), 3: .unsigned(observedAtMilliseconds), 4: .unsigned(leaseDeadlineMilliseconds),
            5: .array(self.enrollments.map { .array([.bytes($0.phoneID), .bytes($0.epoch), .bytes($0.tag), .boolean($0.active)]) }),
            6: .boolean(active), 7: .boolean(phoneRouting), 8: .bytes(registration.encode())]), limits: Self.limits)
    }

    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(fields.keys) == Set(UInt64(0)...8), fields[0] == .unsigned(1), case .bytes(let epoch) = fields[1],
              case .unsigned(let sequence) = fields[2], case .unsigned(let observed) = fields[3],
              case .unsigned(let deadline) = fields[4], case .array(let entries) = fields[5], entries.count <= 1024,
              case .boolean(let active) = fields[6], case .boolean(let routing) = fields[7], case .bytes(let registration) = fields[8] else {
            throw GatewayServiceError.invalidMessage
        }
        let enrollments = try entries.map { item -> GatewayPhoneEnrollment in
            guard case .array(let value) = item, value.count == 4, case .bytes(let phone) = value[0],
                  case .bytes(let epoch) = value[1], case .bytes(let tag) = value[2], case .boolean(let active) = value[3] else {
                throw GatewayServiceError.invalidMessage
            }
            return try GatewayPhoneEnrollment(phoneID: phone, epoch: epoch, tag: tag, active: active)
        }
        let result = try Self(registration: GatewayRegistrationIdentity.decode(registration), rootEpoch: uuid(epoch), sequence: sequence, observedAtMilliseconds: observed,
            leaseDeadlineMilliseconds: deadline, enrollments: enrollments, active: active, phoneRouting: routing)
        guard result.canonicalBytes == bytes else { throw GatewayServiceError.invalidMessage }
        return result
    }
    static var limits: CBORLimits { get throws { try CBORLimits(maxBytes: 131072, maxDepth: 3, maxItems: 6200) } }
    static func bytes(_ value: UUID) -> Data { var tuple = value.uuid; return withUnsafeBytes(of: &tuple) { Data($0) } }
    static func uuid(_ bytes: Data) throws -> UUID {
        guard bytes.count == 16 else { throw GatewayServiceError.invalidMessage }
        return bytes.withUnsafeBytes { UUID(uuid: $0.loadUnaligned(as: uuid_t.self)) }
    }
}
