import Darwin
import Foundation
import RemozioCore
import RemozioProtocol

@main
struct AuthorityMain {
    static func main() {
        guard CommandLine.arguments.count == 3, CommandLine.arguments[1] == "--configuration" else {
            fail("Usage: RemozioAuthority --configuration /absolute/protected/configuration.cbor", code: EX_USAGE)
        }
        guard geteuid() == 0 else { fail("Authority startup requires root.", code: EX_NOPERM) }
        do {
            let configuration = try AuthorityServiceConfiguration.load(path: CommandLine.arguments[2])
            let limits = try CBORLimits(maxBytes: 16_777_216, maxDepth: 32, maxItems: 262_144)
            let service = try AuthorityService(configuration: configuration, database: JournalDatabase.open(
                directoryPath: configuration.journalDirectory, macID: configuration.macID, accountID: configuration.accountID,
                recordLimits: limits, descriptorLimits: limits, decisionLimits: limits,
                maximumConsumptions: 1_000_000, busyMilliseconds: 5000))
            // Dispatch sources retain the owner until orderly shutdown completes.
            signal(SIGTERM, SIG_IGN)
            signal(SIGINT, SIG_IGN)
            let termination = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
            let interruption = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
            let shutdown: @Sendable () -> Void = {
                do { try service.close(); exit(EX_OK) }
                catch { fail("Authority shutdown failed.", code: EX_SOFTWARE) }
            }
            termination.setEventHandler(handler: shutdown)
            interruption.setEventHandler(handler: shutdown)
            termination.resume(); interruption.resume()
            try service.start()
            withExtendedLifetime((service, termination, interruption)) { dispatchMain() }
        } catch {
            // Startup inputs can contain private identifiers. Do not print them or storage paths.
            fail("Authority startup failed. Check protected provisioning and configuration.", code: EX_CONFIG)
        }
    }
    private static func fail(_ message: String, code: Int32) -> Never {
        FileHandle.standardError.write(Data((message + "\n").utf8))
        exit(code)
    }
}
