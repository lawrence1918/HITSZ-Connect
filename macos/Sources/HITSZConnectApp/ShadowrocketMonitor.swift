import AppKit
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

/// Reads the macOS NetworkConnection state rather than inferring Shadowrocket
/// status from whether its URL scheme was launched.  `scutil --nc` exposes the
/// actual connected state and per-service byte counters maintained by macOS.
final class ShadowrocketMonitor: ObservableObject {
    @Published private(set) var snapshot = ShadowrocketSnapshot.initial
    var onSnapshot: ((ShadowrocketSnapshot) -> Void)?

    private let queue = DispatchQueue(label: "com.heheyizhi.hitsz-connect.shadowrocket")
    private var timer: Timer?
    private var previousCounters: (rx: Int64, tx: Int64, time: Date)?

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

    @discardableResult
    func connect() -> Bool {
        let result = NSWorkspace.shared.open(URL(string: "shadowrocket://connect")!)
        refresh()
        return result
    }

    @discardableResult
    func disconnect() -> Bool {
        let result = NSWorkspace.shared.open(URL(string: "shadowrocket://disconnect")!)
        refresh()
        return result
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
        guard let service = serviceName(from: list) else {
            return ShadowrocketSnapshot(
                serviceName: nil,
                state: .unavailable,
                rxBytes: 0,
                txBytes: 0,
                rxBytesPerSecond: 0,
                txBytesPerSecond: 0
            )
        }

        let statusOutput = runScutil(["--nc", "status", service])
        let state = parseState(statusOutput)
        let statistics = runScutil(["--nc", "statistics", service])
        let counters = parseCounters(statistics)
        return ShadowrocketSnapshot(
            serviceName: service,
            state: state,
            rxBytes: counters.rx,
            txBytes: counters.tx,
            rxBytesPerSecond: 0,
            txBytesPerSecond: 0
        )
    }

    private static func runScutil(_ arguments: [String]) -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/scutil")
        process.arguments = arguments
        let output = Pipe()
        process.standardOutput = output
        process.standardError = Pipe()
        do {
            try process.run()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else { return "" }
            return String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        } catch {
            return ""
        }
    }

    private static func serviceName(from listOutput: String) -> String? {
        for line in listOutput.split(whereSeparator: \.isNewline) {
            let text = String(line)
            guard text.localizedCaseInsensitiveContains("shadowrocket") else { continue }
            if let quoted = firstCapture(#"\"([^\"]*[Ss]hadowrocket[^\"]*)\""#, in: text) {
                return quoted
            }
            if let identifier = firstCapture(#"([0-9A-Fa-f]{8}-[0-9A-Fa-f-]{27,})"#, in: text) {
                return identifier
            }
            // The common scutil form has the service name as the final token.
            let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty { return trimmed }
        }
        return nil
    }

    private static func parseState(_ output: String) -> ShadowrocketConnectionState {
        let state = output.trimmingCharacters(in: .whitespacesAndNewlines)
        let lower = state.lowercased()
        if lower.contains("disconnected") { return .disconnected }
        if lower.contains("disconnecting") { return .disconnecting }
        if lower.contains("connecting") { return .connecting }
        if lower.contains("connected") { return .connected }
        return .unknown(state)
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
