import AppKit
import Darwin
import Foundation

@main
struct BootstrapProbe {
    static func emit(_ value: [String: Any]) {
        do {
            let bytes = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
            FileHandle.standardOutput.write(bytes); FileHandle.standardOutput.write(Data([10]))
        } catch { exit(EX_SOFTWARE) }
    }
    static func main() {
        guard getuid() > 0, getuid() == geteuid() else { exit(EX_NOPERM) }
        switch Array(CommandLine.arguments.dropFirst()) {
        case ["--describe"]:
            emit(["schemaVersion": 1, "capability": "disposable-bootstrap-file-experiment",
                  "defaultPrompts": false, "productionInstallation": false])
        case ["--preflight"]: emit(AuthorizedReplacement.preflight())
        case ["--ordinary"]:
            do { emit(try OrdinaryReplacement.run()) }
            catch { emit(["schemaVersion": 1, "ordinaryProbeFailed": true]); exit(EX_SOFTWARE) }
        case ["--authorize-file-operations", "--confirm-disposable-only"]:
            let app = NSApplication.shared
            app.setActivationPolicy(.regular)
            Task { @MainActor in
                emit(await AuthorizedReplacement.run())
                app.terminate(nil)
            }
            app.run()
        default:
            FileHandle.standardError.write(Data("Use --describe, --preflight or --ordinary. Interactive file operations require both explicit authorization flags.\n".utf8))
            exit(EX_USAGE)
        }
    }
}
