import Darwin
import Foundation

public enum AuthorityClockError: Error, Equatable { case invalidTimebase, overflow }

/// One authority incarnation's sleep-inclusive clock. Share this value across its request owners.
public struct AuthorityClock: Sendable {
    public let epoch: UUID
    private let numerator: UInt32
    private let denominator: UInt32

    public init() throws { try self.init(epoch: UUID()) }

    init(epoch: UUID) throws {
        var timebase = mach_timebase_info_data_t()
        guard mach_timebase_info(&timebase) == KERN_SUCCESS,
              timebase.numer != 0, timebase.denom != 0 else { throw AuthorityClockError.invalidTimebase }
        self.epoch = epoch; numerator = timebase.numer; denominator = timebase.denom
    }

    public func now() throws -> AuthorityMoment {
        AuthorityMoment(epoch: epoch, milliseconds: try Self.milliseconds(
            ticks: mach_continuous_time(), numerator: numerator, denominator: denominator))
    }

    static func milliseconds(ticks: UInt64, numerator: UInt32, denominator: UInt32) throws -> UInt64 {
        guard numerator != 0, denominator != 0 else { throw AuthorityClockError.invalidTimebase }
        let product = ticks.multipliedFullWidth(by: UInt64(numerator))
        let divisor = UInt64(denominator) * 1_000_000
        guard product.high < divisor else { throw AuthorityClockError.overflow }
        return divisor.dividingFullWidth(product).quotient
    }
}
