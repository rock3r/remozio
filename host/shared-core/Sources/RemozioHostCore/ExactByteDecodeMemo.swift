import Foundation
import Synchronization

/// Remembers pure immutable results for exact bytes. Failed decodes leave no entry.
final class ExactByteDecodeMemo<Value: Sendable>: Sendable {
    private let values = Mutex<[Data: Value]>([:])
    private let capacity: Int
    init(capacity: Int = 32) {
        precondition(capacity > 0)
        self.capacity = capacity
    }
    func value(for bytes: Data, _ decode: () throws -> Value) rethrows -> Value {
        if let known = values.withLock({ $0[bytes] }) { return known }
        let value = try decode()
        values.withLock {
            if $0.count >= capacity { $0.removeAll() }
            $0[bytes] = value
        }
        return value
    }
}
