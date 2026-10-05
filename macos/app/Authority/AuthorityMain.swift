import Darwin
import Foundation
import RemozioCore

@main
struct AuthorityMain {
    static func main() {
        guard CommandLine.arguments.count == 3, CommandLine.arguments[1] == "--configuration" else {
            fail("Usage: RemozioAuthority --configuration /absolute/protected/configuration.cbor", code: EX_USAGE)
        }
        guard geteuid() == 0 else { fail("Authority startup requires root.", code: EX_NOPERM) }
        do {
            let runner = try AuthorityServiceRunner(configurationPath: CommandLine.arguments[2], report: report)
            // Dispatch sources retain the owner until orderly shutdown completes.
            signal(SIGTERM, SIG_IGN)
            signal(SIGINT, SIG_IGN)
            let termination = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
            let interruption = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
            let shutdown: @Sendable () -> Void = {
                do { try runner.close(); exit(EX_OK) }
                catch { fail("Authority shutdown failed.", code: EX_SOFTWARE) }
            }
            termination.setEventHandler(handler: shutdown)
            interruption.setEventHandler(handler: shutdown)
            termination.resume(); interruption.resume()
            try runner.start()
            withExtendedLifetime((runner, termination, interruption)) { dispatchMain() }
        } catch {
            fail("Authority startup failed. Check protected provisioning and configuration.", code: EX_CONFIG)
        }
    }
    private static func report(_ status: AuthorityServiceRunner.Status) {
        // Startup inputs can contain private identifiers. Do not print them or storage paths.
        switch status {
        case .idle, .starting, .closed: break
        case .running:
            log("Authority trust service started.")
        case .waiting(let milliseconds):
            log("Authority starting: storage is temporarily unavailable. Retrying in \(milliseconds) milliseconds.")
        case .failed(.historyRecoveryRequired):
            fail("Authority starting: history recovery is pending.", code: EX_TEMPFAIL)
        case .failed(.repairRequired):
            fail("Authority continuity requires repair.", code: EX_CONFIG)
        case .failed(.temporaryStorageFailure):
            fail("Authority starting: storage is temporarily unavailable.", code: EX_TEMPFAIL)
        case .failed(.configurationFailure):
            fail("Authority startup failed. Check protected provisioning and configuration.", code: EX_CONFIG)
        }
    }
    private static func log(_ message: String) {
        FileHandle.standardError.write(Data((message + "\n").utf8))
    }
    private static func fail(_ message: String, code: Int32) -> Never {
        log(message)
        exit(code)
    }
}
