import Darwin
import Combine
import Foundation

enum ShadowrocketConnectionState: Equatable {
    case unavailable
    case disconnected
    case connecting
    case connected
    case disconnecting
    case unknown(String)

    var title: String {
        switch self {
        case .unavailable: return "未找到 Shadowrocket"
        case .disconnected: return "未连接"
        case .connecting: return "连接中"
        case .connected: return "已连接"
        case .disconnecting: return "断开中"
        case let .unknown(value): return value.isEmpty ? "状态未知" : value
        }
    }

    var systemImage: String {
        switch self {
        case .connected: return "checkmark.circle.fill"
        case .connecting, .disconnecting: return "arrow.triangle.2.circlepath.circle"
        case .unavailable: return "questionmark.circle"
        case .disconnected, .unknown: return "circle"
        }
    }

    var isActive: Bool {
        switch self {
        case .connecting, .connected, .disconnecting: return true
        case .unavailable, .disconnected, .unknown: return false
        }
    }

    var shouldRestoreAfterBootstrap: Bool {
        switch self {
        case .connecting, .connected: return true
        case .unavailable, .disconnected, .disconnecting, .unknown: return false
        }
    }
}

struct ShadowrocketSnapshot: Equatable {
    var serviceName: String?
    var state: ShadowrocketConnectionState
    var rxBytes: Int64
    var txBytes: Int64
    var rxBytesPerSecond: Double
    var txBytesPerSecond: Double

    static let initial = ShadowrocketSnapshot(
        serviceName: nil,
        state: .unknown("正在检查"),
        rxBytes: 0,
        txBytes: 0,
        rxBytesPerSecond: 0,
        txBytesPerSecond: 0
    )
}

enum ShadowrocketControlError: LocalizedError {
    case serviceUnavailable
    case commandFailed(String)
    case timeout(String)

    var errorDescription: String? {
        switch self {
        case .serviceUnavailable:
            return "macOS 没有找到 Shadowrocket 的 VPN 服务。请确认 Shadowrocket 已安装并创建过 VPN 配置。"
        case let .commandFailed(message):
            return message
        case let .timeout(message):
            return message
        }
    }
}

struct ShadowrocketService {
    let identifier: String
    let name: String
}

enum ShadowrocketBootstrapOutcome {
    case ready(wasActive: Bool)
    case failed(error: Error, restoreNeeded: Bool)
}

enum ShadowrocketBootstrapRestoreOutcome {
    case notNeeded
    case restored
    case failed
}

private struct ProcessResult {
    let status: Int32
    let output: String
}

/// Monitors Shadowrocket through its NetworkExtension service and labelled
/// utun. `scutil --nc` is the primary control path. Some URL-scheme-started
/// tunnels are invisible to that service, so control falls back to the same
/// `open -g -j shadowrocket://...` path as the CLI; `-g -j` keeps the Catalyst
/// app hidden and out of the foreground.
final class ShadowrocketMonitor: ObservableObject {
    @Published private(set) var snapshot = ShadowrocketSnapshot.initial
    var onSnapshot: ((ShadowrocketSnapshot) -> Void)?

    private let queue = DispatchQueue(label: "com.heheyizhi.hitsz-connect.shadowrocket")
    private var timer: Timer?
    private var previousCounters: (rx: Int64, tx: Int64, time: Date)?
    // This lease is owned by the serial control queue rather than AppState.
    // It makes application termination safe even if the bootstrap completion
    // has not yet been delivered back to the main actor.
    private var bootstrapRestoreRequired = false

    init() {
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 1.5, repeats: true) { [weak self] _ in
            self?.refresh()
        }
    }

    deinit {
        timer?.invalidate()
    }

    func refresh() {
        queue.async { [weak self] in
            guard let self else { return }
            let raw = Self.readSystemSnapshot()
            DispatchQueue.main.async { [weak self] in
                self?.apply(raw)
            }
        }
    }

    /// Starts Shadowrocket's actual VPN service without opening its window.
    func connect(completion: ((Result<Void, Error>) -> Void)? = nil) {
        control(connected: true, completion: completion)
    }

    /// Stops Shadowrocket's actual VPN service without opening its window.
    func disconnect(completion: ((Result<Void, Error>) -> Void)? = nil) {
        control(connected: false, completion: completion)
    }

    /// Completes a pending bootstrap lease synchronously and reports whether
    /// no lease existed, restoration succeeded, or restoration failed.
    func restoreBootstrapStateAndWait(timeout: TimeInterval = 5) -> ShadowrocketBootstrapRestoreOutcome {
        queue.sync {
            guard bootstrapRestoreRequired else { return .notNeeded }
            guard case .success = Self.controlSynchronously(connected: true, timeout: timeout) else {
                return .failed
            }
            bootstrapRestoreRequired = false
            return .restored
        }
    }

    /// Before aTrust authentication, pause an already-active Shadowrocket
    /// tunnel. HITSZ rules commonly send the aTrust IdP through the local
    /// SOCKS listener; that listener does not exist until aTrust is ready.
    /// Returning the previous state lets AppState restore it afterwards.
    func prepareForATrustBootstrap(completion: @escaping (ShadowrocketBootstrapOutcome) -> Void) {
        queue.async {
            let initial = Self.readSystemSnapshot()
            let shouldRestore = initial.state.shouldRestoreAfterBootstrap
            self.bootstrapRestoreRequired = false
            guard initial.state.isActive else {
                DispatchQueue.main.async { completion(.ready(wasActive: false)) }
                return
            }

            switch Self.controlSynchronously(connected: false, timeout: 10) {
            case .success:
                self.bootstrapRestoreRequired = shouldRestore
                DispatchQueue.main.async { completion(.ready(wasActive: shouldRestore)) }
            case let .failure(error):
                let restoreNeeded = shouldRestore
                self.bootstrapRestoreRequired = restoreNeeded
                DispatchQueue.main.async {
                    completion(.failed(error: error, restoreNeeded: restoreNeeded))
                }
            }
        }
    }

    /// Synchronous shutdown helper used only while the app is terminating.
    @discardableResult
    func disconnectAndWait(timeout: TimeInterval = 5) -> Bool {
        queue.sync {
            guard Self.readSystemSnapshot().state.isActive else { return true }
            if case .success = Self.controlSynchronously(connected: false, timeout: timeout) {
                bootstrapRestoreRequired = false
                return true
            }
            return false
        }
    }

    /// Synchronous counterpart used during app termination when the App had
    /// paused an existing Shadowrocket tunnel for aTrust bootstrap.
    @discardableResult
    func connectAndWait(timeout: TimeInterval = 5) -> Bool {
        queue.sync {
            if case .success = Self.controlSynchronously(connected: true, timeout: timeout) {
                bootstrapRestoreRequired = false
                return true
            }
            return false
        }
    }

    private func control(connected: Bool, completion: ((Result<Void, Error>) -> Void)?) {
        queue.async { [weak self] in
            let result = Self.controlSynchronously(connected: connected, timeout: 12)
            let snapshot = Self.readSystemSnapshot()
            if case .success = result {
                self?.bootstrapRestoreRequired = false
            }
            DispatchQueue.main.async { [weak self] in
                self?.apply(snapshot)
                switch result {
                case .success:
                    completion?(.success(()))
                case let .failure(error):
                    completion?(.failure(error))
                }
            }
        }
    }

    private func apply(_ raw: ShadowrocketSnapshot) {
        var next = raw
        let now = Date()
        if raw.state == .connected,
           let previousCounters,
           raw.rxBytes >= previousCounters.rx,
           raw.txBytes >= previousCounters.tx {
            let elapsed = now.timeIntervalSince(previousCounters.time)
            if elapsed > 0 {
                next.rxBytesPerSecond = Double(raw.rxBytes - previousCounters.rx) / elapsed
                next.txBytesPerSecond = Double(raw.txBytes - previousCounters.tx) / elapsed
            }
        } else {
            next.rxBytesPerSecond = 0
            next.txBytesPerSecond = 0
        }

        if raw.state == .connected {
            previousCounters = (raw.rxBytes, raw.txBytes, now)
        } else {
            previousCounters = nil
        }
        snapshot = next
        onSnapshot?(next)
    }

    private static func readSystemSnapshot() -> ShadowrocketSnapshot {
        let list = runScutil(["--nc", "list"])
        let service = shadowrocketService(from: list.output)
        let interfaceOutput = runProcess("/sbin/ifconfig", ["-v"])
        let interface = shadowrocketInterface(from: interfaceOutput.output)

        var state: ShadowrocketConnectionState
        if let service {
            state = parseState(runScutil(["--nc", "status", service.identifier]).output)
        } else {
            state = .unavailable
        }
        // In some app/sandbox contexts scutil reports Disconnected while the
        // NetworkExtension utun is already carrying traffic. The descriptor
        // is the authoritative fallback for Shadowrocket's actual tunnel.
        if interface != nil && (state == .disconnected || state == .unavailable || isUnknown(state)) {
            state = .connected
        }

        var counters = (rx: Int64(0), tx: Int64(0))
        if let interface, let interfaceCounters = interfaceCounters(interface) {
            counters = interfaceCounters
        } else if let service {
            counters = parseCounters(runScutil(["--nc", "statistics", service.identifier]).output)
        }

        return ShadowrocketSnapshot(
            serviceName: service?.name ?? interface,
            state: state,
            rxBytes: counters.rx,
            txBytes: counters.tx,
            rxBytesPerSecond: 0,
            txBytesPerSecond: 0
        )
    }

    private static func waitForState(active: Bool, service: ShadowrocketService, timeout: TimeInterval) -> Result<Void, Error> {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            let serviceState = parseState(runScutil(["--nc", "status", service.identifier]).output)
            let interface = shadowrocketInterface(from: runProcess("/sbin/ifconfig", ["-v"]).output)
            let reachedTarget: Bool
            if active {
                // The labelled utun is packet-tunnel truth. scutil may claim
                // Connected before NetworkExtension has created the interface.
                reachedTarget = interface != nil
            } else {
                // A disconnected scutil line is not sufficient: on some
                // macOS/NetworkExtension combinations it is printed while a
                // Shadowrocket-labelled utun is still carrying traffic. Wait
                // for both the service and its tunnel descriptor to disappear.
                reachedTarget = serviceState == .disconnected && interface == nil
                    || (isUnknown(serviceState) && interface == nil)
            }
            if reachedTarget {
                return .success(())
            }
            Thread.sleep(forTimeInterval: 0.2)
        }
        let desired = active ? "连接" : "断开"
        return .failure(ShadowrocketControlError.timeout("等待 Shadowrocket \(desired)超时（服务：\(service.name)）。"))
    }

    private static func waitForTunnel(active: Bool, timeout: TimeInterval) -> Result<Void, Error> {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            let interface = shadowrocketInterface(from: runProcess("/sbin/ifconfig", ["-v"]).output)
            if (interface != nil) == active {
                return .success(())
            }
            Thread.sleep(forTimeInterval: 0.2)
        }
        let desired = active ? "连接" : "断开"
        return .failure(ShadowrocketControlError.timeout("等待 Shadowrocket \(desired)超时。"))
    }

    private static func controlSynchronously(connected: Bool, timeout: TimeInterval) -> Result<Void, Error> {
        let action = connected ? "start" : "stop"
        if let service = shadowrocketService(from: runScutil(["--nc", "list"]).output) {
            let command = runScutil(["--nc", action, service.identifier])
            if command.status == 0,
               case .success = waitForState(active: connected, service: service, timeout: min(2, timeout)) {
                return .success(())
            }
        }

        // A URL-scheme-created tunnel can have a live labelled utun while its
        // scutil service remains Disconnected. Use the CLI's hidden background
        // control path as an idempotent fallback and verify packet-tunnel truth.
        let fallback = runShadowrocketURL(connected ? "connect" : "disconnect")
        guard fallback.status == 0 else {
            let detail = fallback.output.trimmingCharacters(in: .whitespacesAndNewlines)
            let suffix = detail.isEmpty ? "命令退出状态 \(fallback.status)" : detail
            let verb = connected ? "启动" : "断开"
            return .failure(ShadowrocketControlError.commandFailed("Shadowrocket 静默\(verb)失败：\(suffix)"))
        }
        return waitForTunnel(active: connected, timeout: max(0.5, timeout - min(2, timeout)))
    }

    private static func runScutil(_ arguments: [String]) -> ProcessResult {
        runProcess("/usr/sbin/scutil", arguments)
    }

    private static func runShadowrocketURL(_ action: String) -> ProcessResult {
        if action == "connect" {
            let launch = runProcess("/usr/bin/open", shadowrocketBundleArguments())
            if launch.status != 0 {
                return launch
            }
        }
        return runProcess("/usr/bin/open", shadowrocketURLArguments(action))
    }

    static func shadowrocketBundleArguments() -> [String] {
        ["-g", "-j", "-b", "com.liguangming.Shadowrocket"]
    }

    static func shadowrocketURLArguments(_ action: String) -> [String] {
        ["-g", "-j", "shadowrocket://\(action)"]
    }

    private static func runProcess(_ executable: String, _ arguments: [String]) -> ProcessResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        let output = Pipe()
        process.standardOutput = output
        process.standardError = output
        do {
            try process.run()
            let data = output.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            return ProcessResult(
                status: process.terminationStatus,
                output: String(data: data, encoding: .utf8) ?? ""
            )
        } catch {
            return ProcessResult(status: -1, output: error.localizedDescription)
        }
    }

    static func shadowrocketService(from listOutput: String) -> ShadowrocketService? {
        var fallback: ShadowrocketService?
        for rawLine in listOutput.split(whereSeparator: \.isNewline) {
            let line = String(rawLine)
            guard line.localizedCaseInsensitiveContains("com.liguangming.Shadowrocket") else { continue }
            guard let identifier = firstCapture(#"([0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12})"#, in: line) else { continue }
            let name = firstCapture(#"\"([^\"]+)\""#, in: line) ?? "Shadowrocket"
            let service = ShadowrocketService(identifier: identifier, name: name)
            if line.localizedCaseInsensitiveContains("(Connected)")
                || line.localizedCaseInsensitiveContains("(Connecting)") {
                return service
            }
            if fallback == nil {
                fallback = service
            }
        }
        return fallback
    }

    static func shadowrocketInterface(from ifconfigOutput: String) -> String? {
        var currentInterface: String?
        var currentInterfaceIsRunning = false
        for rawLine in ifconfigOutput.split(whereSeparator: \.isNewline) {
            let line = String(rawLine)
            if !line.hasPrefix(" "), let colon = line.firstIndex(of: ":"), line[line.index(after: colon)...].contains("flags=") {
                currentInterface = String(line[..<colon])
                currentInterfaceIsRunning = line.contains("<UP,") && line.contains("RUNNING")
            }
            if currentInterfaceIsRunning,
               line.localizedCaseInsensitiveContains("desc:\"VPN: Shadowrocket\"") {
                return currentInterface
            }
        }
        return nil
    }

    static func parseState(_ output: String) -> ShadowrocketConnectionState {
        let state = output
            .split(whereSeparator: \.isNewline)
            .first
            .map(String.init)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        switch state.lowercased() {
        case "disconnecting": return .disconnecting
        case "disconnected": return .disconnected
        case "connecting": return .connecting
        case "connected": return .connected
        default: return .unknown(state)
        }
    }

    private static func isUnknown(_ state: ShadowrocketConnectionState) -> Bool {
        if case .unknown = state { return true }
        return false
    }

    private static func parseCounters(_ output: String) -> (rx: Int64, tx: Int64) {
        var rx: Int64 = 0
        var tx: Int64 = 0
        for rawLine in output.split(whereSeparator: \.isNewline) {
            let line = String(rawLine).lowercased()
            guard let value = firstCapture(#"([0-9]+)"#, in: line).flatMap(Int64.init) else { continue }
            if line.contains("input") || line.contains("bytes in") || line.contains("bytesin") || line.contains("received") || line.contains("rx") {
                rx = value
            } else if line.contains("output") || line.contains("bytes out") || line.contains("bytesout") || line.contains("sent") || line.contains("tx") {
                tx = value
            }
        }
        return (rx, tx)
    }

    private static func interfaceCounters(_ interfaceName: String) -> (rx: Int64, tx: Int64)? {
        var addresses: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&addresses) == 0, let first = addresses else { return nil }
        defer { freeifaddrs(first) }

        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let address = cursor {
            defer { cursor = address.pointee.ifa_next }
            guard let name = address.pointee.ifa_name,
                  String(cString: name) == interfaceName,
                  let data = address.pointee.ifa_data,
                  let socketAddress = address.pointee.ifa_addr,
                  socketAddress.pointee.sa_family == UInt8(AF_LINK) else { continue }
            let statistics = data.assumingMemoryBound(to: if_data.self).pointee
            return (Int64(statistics.ifi_ibytes), Int64(statistics.ifi_obytes))
        }
        return nil
    }

    private static func firstCapture(_ pattern: String, in text: String) -> String? {
        guard let regex = try? NSRegularExpression(pattern: pattern),
              let match = regex.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)),
              match.numberOfRanges > 1,
              let range = Range(match.range(at: 1), in: text) else {
            return nil
        }
        return String(text[range])
    }
}
