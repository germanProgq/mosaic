import Foundation
import NetworkExtension
import Security

@MainActor
final class MosaicManager {
    private var manager: NETunnelProviderManager?
    private let provider = Bundle.main.object(forInfoDictionaryKey: "MosaicProvider") as? String ?? "net.mosaic.client.tunnel"

    func load() async throws {
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()
        let matches = managers.filter { ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == provider }
        guard matches.count <= 1 else { throw failure("Multiple Mosaic configurations exist; remove the duplicate in VPN settings") }
        manager = matches.first
    }

    nonisolated static func readProfile(_ url: URL) throws -> Data {
        let file = try FileHandle(forReadingFrom: url)
        defer { try? file.close() }
        guard let data = try file.read(upToCount: 98305), !data.isEmpty, data.count <= 98304 else {
            throw NSError(domain: "Mosaic", code: 1, userInfo: [NSLocalizedDescriptionKey: "Private configuration is empty or exceeds its size limit"])
        }
        return data
    }

    func importProfile(_ data: Data) async throws {
        guard data.count <= 98304,
              data.withUnsafeBytes({ mosaic_validate_profile($0.bindMemory(to: UInt8.self).baseAddress, data.count) }) == 1 else {
            throw failure("Invalid private Mosaic configuration")
        }
        try await load()
        if let current = manager, current.connection.status != .disconnected && current.connection.status != .invalid {
            throw failure("Disconnect Mosaic before replacing its configuration")
        }
        guard let group = Bundle.main.object(forInfoDictionaryKey: "MosaicKeychainGroup") as? String else {
            throw failure("The signed package is missing its keychain group")
        }
        let account = UUID().uuidString
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "Mosaic configuration", kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: group, kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData as String: data, kSecReturnPersistentRef as String: true]
        var item: CFTypeRef?
        guard SecItemAdd(query as CFDictionary, &item) == errSecSuccess, let reference = item as? Data else {
            throw failure("Cannot save private configuration in Keychain; check the package signing and unlock the device")
        }
        let selected = manager ?? NETunnelProviderManager()
        let oldReference = selected.protocolConfiguration?.passwordReference
        let configuration = NETunnelProviderProtocol()
        configuration.providerBundleIdentifier = provider
        configuration.serverAddress = "Mosaic relay"
        configuration.passwordReference = reference
        configuration.includeAllNetworks = true
        configuration.excludeLocalNetworks = false
        configuration.excludeAPNs = false
        selected.protocolConfiguration = configuration
        selected.localizedDescription = "Mosaic"
        selected.isEnabled = true
        selected.isOnDemandEnabled = false
        do {
            try await selected.saveToPreferences()
        } catch {
            deleteSecret(reference)
            throw failure("Cannot save VPN settings; approve Mosaic in system settings and try importing again")
        }
        manager = selected
        if let oldReference { deleteSecret(oldReference) }
        try await selected.loadFromPreferences()
    }

    func connect() async throws {
        try await load()
        guard let manager else { throw failure("Import a private Mosaic configuration first") }
        guard manager.connection.status == .disconnected || manager.connection.status == .invalid else {
            throw failure("Mosaic is already connected or connecting")
        }
        let rule = NEOnDemandRuleConnect()
        rule.interfaceTypeMatch = .any
        manager.onDemandRules = [rule]
        manager.isOnDemandEnabled = true
        manager.isEnabled = true
        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()
        do { try (manager.connection as? NETunnelProviderSession)?.startTunnel() }
        catch { throw failure("Cannot start Mosaic; check VPN permission and the installed tunnel extension") }
    }

    func disconnect() async throws {
        try await load()
        guard let manager else { return }
        manager.isOnDemandEnabled = false
        try await manager.saveToPreferences()
        manager.connection.stopVPNTunnel()
        for _ in 0..<100 {
            if manager.connection.status == .disconnected || manager.connection.status == .invalid { return }
            try await Task.sleep(nanoseconds: 100_000_000)
        }
        throw failure("Disconnect is still pending; check Mosaic in VPN settings")
    }

    func remove() async throws {
        try await disconnect()
        guard let manager else { return }
        let reference = manager.protocolConfiguration?.passwordReference
        try await manager.removeFromPreferences()
        if let reference { deleteSecret(reference) }
        self.manager = nil
    }

    func status() async throws -> String {
        try await load()
        guard let manager else { return "disconnected: import a private configuration" }
        if manager.connection.status == .connected || manager.connection.status == .reasserting,
           let session = manager.connection as? NETunnelProviderSession {
            let response: Data? = await withCheckedContinuation { continuation in
                let reply = StatusReply(continuation)
                DispatchQueue.main.asyncAfter(deadline: .now() + 5) { reply.finish(nil) }
                do { try session.sendProviderMessage(Data("status".utf8)) { reply.finish($0) } }
                catch { reply.finish(nil) }
            }
            if let response, let value = String(data: response, encoding: .utf8) { return value }
        }
        switch manager.connection.status {
        case .connected: return "failed: provider readiness could not be verified; disconnect to recover"
        case .connecting: return "connecting: preparing protected networking"
        case .reasserting: return "reconnecting: traffic remains protected"
        case .disconnecting: return "disconnecting: waiting for system cleanup"
        default: return "disconnected"
        }
    }

    private func deleteSecret(_ reference: Data) {
        SecItemDelete([kSecValuePersistentRef as String: reference] as CFDictionary)
    }

    private func failure(_ message: String) -> Error {
        NSError(domain: "Mosaic", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}

private final class StatusReply: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data?, Never>?
    init(_ continuation: CheckedContinuation<Data?, Never>) { self.continuation = continuation }
    func finish(_ value: Data?) {
        lock.lock()
        let waiting = continuation
        continuation = nil
        lock.unlock()
        waiting?.resume(returning: value)
    }
}
