import AppKit
import SwiftUI

@main
struct RemozioApp: App {
    @AppStorage("showMenuBarExtra") private var showMenuBarExtra = true

    var body: some Scene {
        Window("Remozio", id: "main") {
            SetupOverview()
        }
        .defaultSize(width: 600, height: 440)
        .windowResizability(.contentMinSize)

        MenuBarExtra("Remozio", systemImage: "hand.raised", isInserted: $showMenuBarExtra) {
            RemozioMenu()
        }

        Settings {
            Form {
                Section {
                    Toggle("Show Remozio in the menu bar", isOn: $showMenuBarExtra)
                    Text("You can always open Remozio from the Dock or Applications.")
                        .foregroundStyle(.secondary)
                }
                Section("Request delivery") {
                    Label("Setup is not available yet", systemImage: "wrench.and.screwdriver")
                    Text("Routing, device pairing, and background services are still being built.")
                        .foregroundStyle(.secondary)
                }
            }
            .formStyle(.grouped)
            .frame(minWidth: 440, idealWidth: 500, minHeight: 240)
        }
    }
}

private struct SetupOverview: View {
    @State private var showingSetupPreview = false
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Remozio").font(.largeTitle).accessibilityAddTraits(.isHeader)
                    Text("Approvals from your Macs, on your Android devices.")
                        .font(.title3).foregroundStyle(.secondary)
                }
                GroupBox {
                    VStack(alignment: .leading, spacing: 12) {
                        Label("This Mac is not configured", systemImage: "macbook.and.iphone")
                            .font(.headline)
                        Text("This early build cannot pair devices, send requests, or approve actions.")
                        Text("No background services are installed or started by this app.")
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(12)
                }
                Button("Preview setup file…") { showingSetupPreview = true }
                HStack {
                    SettingsLink()
                    Spacer()
                    Text("Development build").font(.caption).foregroundStyle(.secondary)
                }
            }
            .padding(28)
            .frame(maxWidth: 720)
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
        .frame(minWidth: 440, minHeight: 340)
        .sheet(isPresented: $showingSetupPreview) { SetupFilePreview() }
    }
}

private struct RemozioMenu: View {
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Text("Not configured")
        Button("Open Remozio") {
            openWindow(id: "main")
            NSApplication.shared.activate()
        }
        SettingsLink()
        Divider()
        Button("Quit Remozio") { NSApplication.shared.terminate(nil) }
            .keyboardShortcut("q")
    }
}
