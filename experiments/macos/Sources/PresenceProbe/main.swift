import CoreGraphics
import Foundation

let usage = "Usage: remozio-presence-probe --sample-after SECONDS (0...300), or --help\n"
let arguments = Array(CommandLine.arguments.dropFirst())
if arguments == ["--help"] {
    print(usage, terminator: "")
    exit(0)
}
guard arguments.count == 2, arguments[0] == "--sample-after",
      let delay = UInt(arguments[1]), delay <= 300 else {
    FileHandle.standardError.write(Data(usage.utf8))
    exit(64)
}

// Waiting permits a single observation without typing at the sampling instant.
Thread.sleep(forTimeInterval: Double(delay))
let started = ProcessInfo.processInfo.systemUptime
let session = CGSessionCopyCurrentDictionary() as? [String: Any]
@MainActor func sessionFlag(_ key: String) -> Any {
    guard let value = session?[key] as? NSNumber,
          CFGetTypeID(value) == CFBooleanGetTypeID() else { return NSNull() }
    return value.boolValue
}
func elapsed(_ source: CGEventSourceStateID) -> Any {
    let seconds = CGEventSource.secondsSinceLastEventType(source, eventType: .init(rawValue: UInt32.max)!)
    guard seconds.isFinite, seconds >= 0 else { return NSNull() }
    return seconds.rounded(.down)
}
func onlineDisplays() -> [CGDirectDisplayID]? {
    // One extra slot distinguishes a complete bounded result from truncation.
    var values = [CGDirectDisplayID](repeating: 0, count: 33)
    var count: UInt32 = 0
    guard CGGetOnlineDisplayList(33, &values, &count) == .success, count <= 32 else { return nil }
    return Array(values.prefix(Int(count))).sorted()
}
let before = onlineDisplays()
let displays: [[String: Any]]? = before?.enumerated().map { index, display in
    ["sampleIndex": index, "builtIn": CGDisplayIsBuiltin(display) != 0,
     "online": CGDisplayIsOnline(display) != 0, "active": CGDisplayIsActive(display) != 0,
     "asleep": CGDisplayIsAsleep(display) != 0, "brightness": NSNull()]
}
let after = onlineDisplays()
let stableTopology = before != nil && before == after
let result: [String: Any] = [
    "schema": 1,
    "purpose": "candidate-signals-only",
    "sessionDictionaryAvailable": session != nil,
    "onConsole": sessionFlag(kCGSessionOnConsoleKey),
    "loginCompleted": sessionFlag(kCGSessionLoginDoneKey),
    "combinedSessionInputAgeSeconds": session == nil ? NSNull() : elapsed(.combinedSessionState),
    "hardwareInputAgeSeconds": session == nil ? NSNull() : elapsed(.hidSystemState),
    "displayListStable": stableTopology,
    "displays": stableTopology ? displays! : NSNull(),
    "lockState": NSNull(),
    "usableRemoteDesktop": NSNull(),
    "routingDecision": "not-evaluated",
    "samplingDurationSeconds": max(0, ProcessInfo.processInfo.systemUptime - started),
]
do {
    let data = try JSONSerialization.data(withJSONObject: result, options: [.prettyPrinted, .sortedKeys])
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data("\n".utf8))
} catch {
    FileHandle.standardError.write(Data("Could not encode the observation.\n".utf8))
    exit(1)
}
