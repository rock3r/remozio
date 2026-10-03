import RemozioCore
import SwiftUI
import UniformTypeIdentifiers

struct SetupFilePreview: View {
    @Environment(\.dismiss) private var dismiss
    @State private var choosingFile = false
    @State private var file: URL?
    @State private var password = ""
    @State private var preview: SetupPreview?
    @State private var failure: LocalizedStringKey?
    @State private var work: Task<Void, Never>?
    @FocusState private var passwordFocused: Bool

    init() {}
    #if DEBUG
    init(snapshotPreview: SetupPreview?, snapshotError: LocalizedStringKey? = nil) {
        _preview = State(initialValue: snapshotPreview)
        _failure = State(initialValue: snapshotError)
    }
    #endif

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            VStack(alignment: .leading, spacing: 8) {
                Text("Preview setup file").font(.title2).accessibilityAddTraits(.isHeader)
                Text("Inspect shared configuration exported from another Mac.")
                    .foregroundStyle(Color.primary.opacity(0.8))
            }
            if let preview {
                SetupScopePreview(preview: preview)
            } else {
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Button("Choose file…") { choosingFile = true }.disabled(work != nil)
                        if let file {
                            Text(verbatim: file.lastPathComponent).lineLimit(1).truncationMode(.middle)
                                .help(file.lastPathComponent)
                        }
                    }
                    SecureField("Export password", text: $password)
                        .focused($passwordFocused).disabled(file == nil || work != nil)
                        .onSubmit { startPreview() }
                    if work != nil { ProgressView("Opening encrypted file…").controlSize(.small) }
                    if let failure {
                        Label {
                            Text(failure).foregroundStyle(.primary)
                        } icon: {
                            Image(systemName: "exclamationmark.triangle").foregroundStyle(.red)
                        }
                        .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            Text("This preview does not apply settings or create Mac resources. Setup is still being built.")
                .font(.callout).foregroundStyle(Color.primary.opacity(0.8)).fixedSize(horizontal: false, vertical: true)
            HStack {
                Spacer()
                Button("Close") { close() }.keyboardShortcut(.cancelAction)
                if preview == nil {
                    Button("Preview") { startPreview() }.keyboardShortcut(.defaultAction)
                        .disabled(file == nil || password.isEmpty || work != nil)
                }
            }
        }
        .padding(24)
        .frame(width: 540)
        .fileImporter(isPresented: $choosingFile, allowedContentTypes: [.data]) { result in
            switch result {
            case let .success(url): file = url; password = ""; failure = nil; passwordFocused = true
            case .failure: failure = "Could not open the file picker. Try choosing the file again."
            }
        }
        .onDisappear { work?.cancel(); password = "" }
    }

    private func startPreview() {
        guard let file, !password.isEmpty, work == nil else { return }
        let enteredPassword = password
        password = ""; failure = nil
        work = Task {
            do {
                let result = try await SetupFilePreviewReader.shared.preview(file: file, password: enteredPassword)
                guard !Task.isCancelled else { return }
                preview = result
            } catch is CancellationError { return }
            catch {
                guard !Task.isCancelled else { return }
                if case SetupPreviewReadError.unreadable = error {
                    failure = "Could not read this file. Choose a local setup file and try again."
                } else {
                    failure = "Could not open this setup file. Check the password and use a supported Remozio export."
                }
                passwordFocused = true
            }
            work = nil
        }
    }
    private func close() { work?.cancel(); password = ""; dismiss() }
}

struct SetupScopePreview: View {
    let preview: SetupPreview
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Included configuration").font(.headline).accessibilityAddTraits(.isHeader)
                    Label("Presence and push defaults", systemImage: "slider.horizontal.3")
                    if preview.categories.contains(.fcmCredentials) {
                        Label("Firebase push credentials", systemImage: "bell")
                    }
                    if preview.categories.contains(.cloudflareProvisioning) {
                        Label("Cloudflare provisioning credentials", systemImage: "network")
                    }
                }
                if let project = preview.firebaseProject {
                    scope("Firebase project", value: project)
                }
                if let account = preview.cloudflareAccount {
                    VStack(alignment: .leading, spacing: 12) {
                        scope("Cloudflare account", value: account)
                        if let zone = preview.cloudflareZone { scope("DNS zone", value: zone) }
                        if let suffix = preview.dnsSuffix { scope("DNS suffix", value: suffix) }
                    }
                }
                if preview.firebaseProject != nil || preview.cloudflareAccount != nil {
                    Text("Provider access has not been checked. Credential values stay hidden.")
                        .foregroundStyle(Color.primary.opacity(0.8))
                }
                Text("Pairings, approval keys, audit history, and ADB grants are not included.")
                    .foregroundStyle(Color.primary.opacity(0.8))
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(maxHeight: 360)
    }
    private func scope(_ title: LocalizedStringKey, value: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.headline)
            Text(verbatim: value).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
        }
    }
}
