import AppKit
import RemozioCore
import SwiftUI

#if DEBUG
@main
struct RenderSetupPreview {
    @MainActor static func main() throws {
        guard CommandLine.arguments.count == 2 else { fatalError("Supply a snapshot output directory") }
        let output = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
        let app = NSApplication.shared
        app.setActivationPolicy(.prohibited)
        let defaults = try SharedSetupDefaults(
            presence: PresenceConfiguration(observationLifetimeMilliseconds: 5000, unavailableGraceMilliseconds: 1000),
            wake: GatewayWakePolicy(maximumEntries: 8, maximumAttempts: 2, minimumEnrollmentIntervalMillis: 1000, maximumLifetimeMillis: 60_000, maximumTTLSeconds: 60),
            delivery: GatewayDeliveryPolicy(maximumFlights: 2, minimumSendIntervalMillis: 100))
        let scope = try SetupCloudflareConfiguration(accountID: String(repeating: "a", count: 32), zoneID: String(repeating: "b", count: 32),
                                                    dnsSuffix: "remozio.example.invalid", apiToken: "synthetic-not-used")
        let preview = PortableSetup(defaults: defaults, cloudflare: scope).preview
        for (name, view) in [
            ("empty-light", SetupFilePreview()),
            ("scope-light", SetupFilePreview(snapshotPreview: preview)),
            ("scope-dark", SetupFilePreview(snapshotPreview: preview)),
            ("error-light", SetupFilePreview(snapshotPreview: nil, snapshotError: "Could not open this setup file. Check the password and use a supported Remozio export.")),
        ] {
            let dark = name.hasSuffix("dark")
            app.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
            let host = NSHostingView(rootView: view.background(.background).environment(\.colorScheme, dark ? .dark : .light))
            host.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
            host.frame = NSRect(x: 0, y: 0, width: 540, height: name.hasPrefix("scope") ? 590 : 340)
            let window = NSWindow(contentRect: host.frame, styleMask: [.borderless], backing: .buffered, defer: false)
            window.contentView = host
            host.layoutSubtreeIfNeeded()
            RunLoop.current.run(until: Date().addingTimeInterval(0.2))
            guard let bitmap = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { fatalError("No bitmap") }
            host.cacheDisplay(in: host.bounds, to: bitmap)
            guard let png = bitmap.representation(using: .png, properties: [:]) else { fatalError("No PNG") }
            try png.write(to: output.appendingPathComponent(name + ".png"))
            window.contentView = nil
            print(name + ": rendered synthetic preview")
        }
    }
}

#else
@main
struct RenderSetupPreviewUnavailable {
    static func main() { fatalError("Synthetic snapshots require a Debug build") }
}
#endif
