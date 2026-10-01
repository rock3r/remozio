import Darwin
import Foundation

// This executable deliberately has no listener, keys, or execution interface.
guard CommandLine.arguments == [CommandLine.arguments[0], "--describe"] else {
    FileHandle.standardError.write(Data("Packaging probe only; pass --describe.\n".utf8))
    exit(EX_UNAVAILABLE)
}
#if SESSION_PROBE
let role = "session-probe"
#elseif AUTHORITY_PROBE
let role = "authority-probe"
#else
#error("A probe role must be selected by its Xcode target")
#endif
let description = ["role": role, "capability": "packaging-only"]
let data = try JSONSerialization.data(withJSONObject: description, options: [.sortedKeys])
FileHandle.standardOutput.write(data + Data([10]))
