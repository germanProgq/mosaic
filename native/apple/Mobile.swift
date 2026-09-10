import SwiftUI
import UniformTypeIdentifiers

@main
struct MosaicApp: App {
    var body: some Scene { WindowGroup { ConnectionView() } }
}

struct ConnectionView: View {
    @State private var message = "Import a private configuration to connect."
    @State private var importing = false
    @State private var busy = false
    private let manager = MosaicManager()

    var body: some View {
        VStack(spacing: 24) {
            Text("Mosaic").font(.largeTitle)
            Text(message).textSelection(.enabled)
            Button("Import configuration") { importing = true }
            Button("Connect") { perform { try await manager.connect() } }
            Button("Disconnect") { perform { try await manager.disconnect() } }
            Button("Connection status") { perform {} }
            Text("IPv4 traffic and DNS use Mosaic. Public IPv6 is blocked while connected. System networking permissions are required.").font(.footnote)
        }
        .padding(32)
        .disabled(busy)
        .fileImporter(isPresented: $importing, allowedContentTypes: [.data]) { result in
            perform {
                let url = try result.get()
                let access = url.startAccessingSecurityScopedResource()
                defer { if access { url.stopAccessingSecurityScopedResource() } }
                try await manager.importProfile(MosaicManager.readProfile(url))
            }
        }
        .task {
            while !Task.isCancelled {
                if !busy { message = (try? await manager.status()) ?? "Cannot read connection status" }
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
        }
    }

    private func perform(_ action: @escaping @MainActor () async throws -> Void) {
        busy = true
        Task { @MainActor in
            do { try await action(); message = try await manager.status() }
            catch { message = error.localizedDescription }
            busy = false
        }
    }
}
