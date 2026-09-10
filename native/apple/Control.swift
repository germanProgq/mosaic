import AppKit
import Foundation
import SystemExtensions

@MainActor
final class Activation: NSObject, @preconcurrency OSSystemExtensionRequestDelegate {
    private var completion: CheckedContinuation<Void, Error>?

    func apply(remove: Bool = false) async throws {
        let identifier = Bundle.main.object(forInfoDictionaryKey: "MosaicProvider") as? String ?? "net.mosaic.client.tunnel"
        try await withCheckedThrowingContinuation { continuation in
            completion = continuation
            let request = remove ? OSSystemExtensionRequest.deactivationRequest(forExtensionWithIdentifier: identifier, queue: .main) : OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: identifier, queue: .main)
            request.delegate = self
            OSSystemExtensionManager.shared.submitRequest(request)
        }
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        print("Approve Mosaic in System Settings, Privacy & Security, or Login Items & Extensions.")
    }

    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties, withExtension replacement: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction { .replace }

    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        if result == .completed { completion?.resume() }
        else { completion?.resume(throwing: NSError(domain: "Mosaic", code: 1, userInfo: [NSLocalizedDescriptionKey: "Restart macOS to complete extension setup or removal"])) }
        completion = nil
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        completion?.resume(throwing: NSError(domain: "Mosaic", code: 1, userInfo: [NSLocalizedDescriptionKey: "Extension setup failed; install the signed app in Applications and approve it in System Settings"]))
        completion = nil
    }
}

@main
struct Control {
    @MainActor static func main() async {
        let manager = MosaicManager()
        let activation = Activation()
        let args = Array(CommandLine.arguments.dropFirst())
        do {
            switch args.first {
            case "setup": try await activation.apply()
            case "import":
                guard args.count == 2 else { throw NSError(domain: "Mosaic", code: 1, userInfo: [NSLocalizedDescriptionKey: "Specify one private .mosaic configuration file"]) }
                let data = try MosaicManager.readProfile(URL(fileURLWithPath: args[1]))
                try await manager.importProfile(data)
            case "connect": try await manager.connect()
            case "disconnect": try await manager.disconnect()
            case "status":
                let status = try await manager.status()
                print(status)
                if status.hasPrefix("failed:") || status.contains("\"state\":\"failed\"") { exit(1) }
                return
            case "uninstall": try await manager.remove(); try await activation.apply(remove: true)
            default: print("Use setup, import FILE, connect, disconnect, status, or uninstall."); return
            }
            print("PASS: \(args[0])")
        } catch {
            print("FAIL: \(error.localizedDescription)")
            exit(1)
        }
    }
}
