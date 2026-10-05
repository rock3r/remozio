import Foundation
import Security

/// Internal identity primitive. The calling host supplies a requirement from protected policy.
enum DynamicCodeValidation {
    enum Failure: Error, Equatable { case invalidRequirement, unavailable, security(OSStatus) }

    static func validateSelf(requirement expression: String) throws {
        var requirement: SecRequirement?
        try checked(SecRequirementCreateWithString(expression as CFString, [], &requirement))
        guard let requirement else { throw Failure.invalidRequirement }
        var code: SecCode?
        try checked(SecCodeCopySelf([], &code))
        guard let code else { throw Failure.unavailable }
        try checked(SecCodeCheckValidity(code, [], requirement))
    }

    private static func checked(_ status: OSStatus) throws {
        guard status == errSecSuccess else { throw Failure.security(status) }
    }
}
