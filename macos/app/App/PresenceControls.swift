import Darwin
import Foundation
import Observation
import RemozioCore
import SwiftUI

/// Root supplies current state. UserDefaults never supplies a mode or a successful operation receipt.
@MainActor @Observable
final class PresenceControls {
    private(set) var status: AuthorityPresenceStatus?
    private(set) var changing = false
    private(set) var configured = false
    private(set) var notice: String?
    @ObservationIgnored private var channel: AuthorityPresenceChannel?
    @ObservationIgnored private var worker: Task<Void, Never>?
    @ObservationIgnored private var refreshing = false
    @ObservationIgnored private var incarnation: UUID?
    deinit { worker?.cancel(); channel?.abort() }

    var headline: String {
        guard let status else { return configured ? String(localized: "Mac service unavailable") : String(localized: "Not configured") }
        switch status.state.mode {
        case .automatic: return String(localized: "Automatic")
        case .present: return String(localized: "Present")
        case .away: return String(localized: "Away")
        }
    }
    var detail: String {
        guard let status else { return configured ? String(localized: "Reconnect to read this Mac’s current state.") : String(localized: "Set up this Mac to control request delivery.") }
        if status.routing.detectionLimited { return String(localized: "Presence detection is limited. You can set Present or Away here.") }
        return status.routing.destination == .localMac ? String(localized: "New requests stay on this Mac.") : String(localized: "New requests go to your phones.")
    }
    func start() {
        guard worker == nil else { return }
        worker = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refresh()
                do { try await Task.sleep(for: .seconds(2)) } catch { return }
            }
        }
    }
    func setMode(_ mode: RoutingMode) async {
        guard !changing, channel != nil, status != nil else { return }
        changing = true; notice = nil
        defer { changing = false }
        // Wait for the current refresh, then use its revision. Polling stops while this user action is pending.
        while refreshing {
            do { try await Task.sleep(for: .milliseconds(10)) } catch { return }
        }
        guard let channel, let status, let id = incarnation else { return }
        do {
            let result = try await channel.setMode(mode, expectedRevision: status.state.revision)
            guard incarnation == id else { return }
            self.status = result
            if result.conflict { notice = String(localized: "The mode changed elsewhere. Review the current mode and try again.") }
        } catch {
            guard incarnation == id else { return }
            notice = String(localized: "The reply was lost. Reconnecting will check whether the mode changed.")
            disconnect(id: id)
        }
    }
    private func refresh() async {
        guard !changing else { return }
        refreshing = true
        defer { refreshing = false }
        if let channel, let id = incarnation {
            do {
                let current = try await channel.current()
                guard incarnation == id else { return }
                status = current
            } catch { disconnect(id: id) }
            return
        }
        let configuration: AuthorityPresenceClientConfiguration
        do {
            configuration = try .load(path: "/Library/Application Support/Remozio/presence-client-\(getuid()).cbor")
            configured = true
        } catch {
            status = nil
            // Missing metadata is setup state. Unsafe or unreadable metadata must not claim a working service.
            if case JournalLeaseError.system(let code) = error, code == ENOENT { configured = false }
            else { configured = true }
            return
        }
        let id = UUID()
        let next = AuthorityPresenceChannel(configuration: configuration, onClose: { [weak self] in
            Task { @MainActor in self?.disconnect(id: id) }
        })
        channel = next; incarnation = id
        do {
            let current = try await next.start()
            guard incarnation == id else { return }
            status = current
            notice = nil
        } catch { disconnect(id: id) }
    }
    private func disconnect(id: UUID) {
        guard incarnation == id else { return }
        let previous = channel
        channel = nil; incarnation = nil; status = nil
        previous?.abort()
    }
}

struct PresenceSettingsSection: View {
    let controls: PresenceControls
    var body: some View {
        Section("Request delivery") {
            Text(controls.headline).font(.headline)
            Text(controls.detail).foregroundStyle(.secondary)
            HStack {
                ForEach([RoutingMode.automatic, .present, .away], id: \.rawValue) { mode in
                    Button(title(mode)) { Task { await controls.setMode(mode) } }
                        .disabled(controls.status == nil || controls.changing)
                }
            }
            if let notice = controls.notice { Text(notice).foregroundStyle(.secondary) }
            if controls.status != nil {
                Text("Automatic and Present can only be set on this Mac.")
                    .foregroundStyle(.secondary)
            }
        }
    }
    private func title(_ mode: RoutingMode) -> String {
        switch mode { case .automatic: String(localized: "Automatic"); case .present: String(localized: "Present"); case .away: String(localized: "Away") }
    }
}
