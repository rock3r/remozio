import Foundation

/// A checkpointed historical observation. It cannot authorize a request or execution.
public enum HistoricalJournalLookup<Value: Sendable>: Sendable {
    case present(Value)
    case retired
    case absent
    case unavailable
}

extension HistoricalJournalLookup: Equatable where Value: Equatable {}
