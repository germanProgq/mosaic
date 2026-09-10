import Foundation
import Network
import NetworkExtension
import Security

final class PacketTunnel: NEPacketTunnelProvider {
    private let work = DispatchQueue(label: "mosaic.packets")
    private var handle: UInt64 = 0
    private var timer: DispatchSourceTimer?
    private var monitor: NWPathMonitor?
    private var configuring = false
    private var networkReady = false
    private var completion: ((Error?) -> Void)?
    private var reading = false

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        guard let configuration = protocolConfiguration as? NETunnelProviderProtocol,
              configuration.includeAllNetworks,
              let reference = configuration.passwordReference else {
            completionHandler(failure("Import a private configuration and enable full-device protection"))
            return
        }
        var item: CFTypeRef?
        let query: [String: Any] = [kSecValuePersistentRef as String: reference, kSecReturnData as String: true]
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let profile = item as? Data else {
            completionHandler(failure("Private configuration is unavailable; unlock the device or import it again"))
            return
        }
        work.async { [self] in
            self.handle = profile.withUnsafeBytes { mosaic_start($0.bindMemory(to: UInt8.self).baseAddress, profile.count) }
            guard self.handle != 0 else {
                completionHandler(self.failure("Invalid configuration or another tunnel is already running"))
                return
            }
            self.completion = completionHandler
            self.reasserting = true
            self.configure()
            let timer = DispatchSource.makeTimerSource(queue: self.work)
            timer.schedule(deadline: .now(), repeating: .milliseconds(10))
            timer.setEventHandler { [weak self] in self?.poll() }
            self.timer = timer
            timer.resume()
            let monitor = NWPathMonitor()
            var first = true
            monitor.pathUpdateHandler = { [weak self] _ in
                guard let self else { return }
                if first { first = false; return }
                self.reasserting = true
                mosaic_path_changed(self.handle)
            }
            self.monitor = monitor
            monitor.start(queue: self.work)
        }
    }

    private func poll() {
        guard handle != 0 else { return }
        let socket = mosaic_socket(handle)
        if socket >= 0 { mosaic_socket_ready(handle, socket, 1) }
        if mosaic_needs_network(handle) == 1 && networkReady { mosaic_network_ready(handle, 1) }
        var bytes = [UInt8](repeating: 0, count: 4096)
        let length = mosaic_status(handle, &bytes, bytes.count)
        if length > 0, let status = try? JSONSerialization.jsonObject(with: Data(bytes.prefix(Int(length)))) as? [String: Any],
           let state = status["state"] as? String {
            reasserting = state != "connected"
            if state == "connected" && !reading { reading = true; readPackets() }
        }
        for _ in 0..<256 {
            let count = mosaic_read_packet(handle, &bytes, bytes.count)
            if count <= 0 { break }
            if !packetFlow.writePackets([Data(bytes.prefix(Int(count)))], withProtocols: [NSNumber(value: AF_INET)]) {
                reasserting = true
                mosaic_network_ready(handle, -1)
                break
            }
        }
    }

    private func configure() {
        configuring = true
        var bytes = [UInt8](repeating: 0, count: 4096)
        let length = mosaic_settings(handle, &bytes, bytes.count)
        guard length > 0,
              let values = try? JSONSerialization.jsonObject(with: Data(bytes.prefix(Int(length)))) as? [String: Any],
              let relay = values["relay"] as? String,
              let address = values["address"] as? String else {
            mosaic_network_ready(handle, -1)
            if let ready = completion { completion = nil; ready(failure("Native settings are unavailable")) }
            return
        }
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: relay)
        let ipv4 = NEIPv4Settings(addresses: [address], subnetMasks: ["255.255.255.252"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4
        let dns = NEDNSSettings(servers: ["1.1.1.1"])
        dns.matchDomains = [""]
        dns.matchDomainsNoSearch = true
        settings.dnsSettings = dns
        settings.mtu = 1100
        setTunnelNetworkSettings(settings) { error in
            self.work.async {
                self.networkReady = error == nil
                if let ready = self.completion { self.completion = nil; ready(error) }
                self.reasserting = true
                if error != nil { mosaic_network_ready(self.handle, -1) }
            }
        }
    }

    private func readPackets() {
        packetFlow.readPackets { packets, protocols in
            self.work.async {
                guard self.handle != 0 else { return }
                for (packet, family) in zip(packets, protocols) where family.int32Value == AF_INET {
                    packet.withUnsafeBytes { data in
                        _ = mosaic_write_packet(self.handle, data.bindMemory(to: UInt8.self).baseAddress, packet.count)
                    }
                }
                self.readPackets()
            }
        }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard messageData == Data("status".utf8) else { completionHandler?(nil); return }
        work.async {
            var bytes = [UInt8](repeating: 0, count: 4096)
            let count = mosaic_status(self.handle, &bytes, bytes.count)
            completionHandler?(count > 0 ? Data(bytes.prefix(Int(count))) : nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        work.async {
            self.timer?.cancel()
            self.monitor?.cancel()
            mosaic_stop(self.handle)
            self.handle = 0
            self.reading = false
            self.configuring = false
            self.networkReady = false
            if let ready = self.completion { self.completion = nil; ready(self.failure("Connection stopped")) }
            completionHandler()
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        work.async { self.reasserting = true; mosaic_path_changed(self.handle); completionHandler() }
    }

    override func wake() {
        work.async { self.reasserting = true; mosaic_path_changed(self.handle) }
    }

    private func failure(_ message: String) -> Error {
        NSError(domain: "Mosaic", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
