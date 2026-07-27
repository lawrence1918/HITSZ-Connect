import Foundation

struct BridgeInboundEvent {
    let type: String
    let state: String?
    let message: String?
    let requestId: String?
    let clientData: String?
    let method: String?
    let atrust: BridgeTraffic?
    let listeners: BridgeListeners?

    static func decode(line: Data) -> BridgeInboundEvent? {
        guard let object = try? JSONSerialization.jsonObject(with: line),
              let values = object as? [String: Any],
              let type = values["type"] as? String else {
            return nil
        }

        let atrustValues = values["atrust"] as? [String: Any]
        let atrust: BridgeTraffic?
        if let atrustValues {
            atrust = BridgeTraffic(
                connected: bool(at: atrustValues, key: "connected") ?? false,
                rxBytes: int64(at: atrustValues, key: "rxBytes") ?? 0,
                txBytes: int64(at: atrustValues, key: "txBytes") ?? 0,
                rxBytesPerSecond: double(at: atrustValues, key: "rxBytesPerSecond") ?? 0,
                txBytesPerSecond: double(at: atrustValues, key: "txBytesPerSecond") ?? 0
            )
        } else {
            atrust = nil
        }

        let listenerValues = values["listeners"] as? [String: Any]
        let listeners: BridgeListeners?
        if let listenerValues {
            listeners = BridgeListeners(
                ready: bool(at: listenerValues, key: "ready") ?? false,
                socks: bool(at: listenerValues, key: "socks") ?? false,
                http: bool(at: listenerValues, key: "http") ?? false,
                dnsRelay: bool(at: listenerValues, key: "dnsRelay") ?? false
            )
        } else {
            listeners = nil
        }

        return BridgeInboundEvent(
            type: type,
            state: values["state"] as? String,
            message: values["message"] as? String,
            requestId: values["requestId"] as? String,
            clientData: values["clientData"] as? String,
            method: values["method"] as? String,
            atrust: atrust,
            listeners: listeners
        )
    }

    private static func bool(at values: [String: Any], key: String) -> Bool? {
        if let value = values[key] as? Bool { return value }
        if let value = values[key] as? NSNumber { return value.boolValue }
        return nil
    }

    private static func int64(at values: [String: Any], key: String) -> Int64? {
        if let value = values[key] as? Int64 { return value }
        if let value = values[key] as? Int { return Int64(value) }
        if let value = values[key] as? NSNumber { return value.int64Value }
        if let value = values[key] as? String { return Int64(value) }
        return nil
    }

    private static func double(at values: [String: Any], key: String) -> Double? {
        if let value = values[key] as? Double { return value }
        if let value = values[key] as? NSNumber { return value.doubleValue }
        if let value = values[key] as? String { return Double(value) }
        return nil
    }
}

/// Manages the local Go executable as a JSON-lines child process.  The only
/// cleartext credential path is this process's stdin pipe; `Process.arguments`
/// intentionally contains only `-app-bridge`.
final class BridgeClient {
    enum Event {
        case bridge(BridgeInboundEvent)
        case diagnostic(String)
        case terminated(Int32)
    }

    var onEvent: ((Event) -> Void)?

    private let queue = DispatchQueue(label: "com.heheyizhi.hitsz-connect.bridge")
    private var process: Process?
    private var stdin: FileHandle?
    private var stdout: FileHandle?
    private var stderr: FileHandle?
    private var stdoutBuffer = Data()
    private var stderrBuffer = Data()

    var isRunning: Bool {
        queue.sync { process?.isRunning ?? false }
    }

    func start(config: BridgeConnectionConfig, clientData: String?) throws {
        let executable = try executableURL()
        try queue.sync {
            guard process == nil || process?.isRunning == false else {
                throw BridgeClientError.alreadyRunning
            }
            cleanupHandles()

            let inputPipe = Pipe()
            let outputPipe = Pipe()
            let errorPipe = Pipe()
            let child = Process()
            child.executableURL = executable
            child.arguments = ["-app-bridge"]
            child.standardInput = inputPipe
            child.standardOutput = outputPipe
            child.standardError = errorPipe

            stdin = inputPipe.fileHandleForWriting
            stdout = outputPipe.fileHandleForReading
            stderr = errorPipe.fileHandleForReading
            process = child
            configureOutputHandlers()
            child.terminationHandler = { [weak self] terminatedChild in
                self?.queue.async {
                    self?.didTerminate(terminatedChild)
                }
            }
            do {
                try child.run()
                try sendLocked(BridgeCommand(type: "connect", config: config, clientData: clientData))
            } catch {
                cleanupHandles()
                process = nil
                throw error
            }
        }
    }

    func sendMFACode(_ code: String, requestId: String? = nil) throws {
        try queue.sync {
            try sendLocked(BridgeCommand(type: "mfaCode", requestId: requestId ?? UUID().uuidString.lowercased(), code: code))
        }
    }

    func stop() {
        queue.async { [weak self] in
            guard let self, self.process?.isRunning == true else { return }
            do {
                try self.sendLocked(BridgeCommand(type: "disconnect"))
            } catch {
                self.emit(.diagnostic("无法向 HITSZ Connect 发送断开命令：\(error.localizedDescription)"))
            }
        }
    }

    func forceStop() {
        queue.async { [weak self] in
            self?.process?.terminate()
        }
    }

    /// Synchronously requests shutdown for application termination.  The
    /// normal UI path stays asynchronous, while this path waits briefly so
    /// macOS does not leave a child process holding loopback listeners after
    /// the menu-bar app has quit.
    func stopAndWait(timeout: TimeInterval = 5) {
        let child: Process? = queue.sync {
            guard let process, process.isRunning else { return nil }
            do {
                try sendLocked(BridgeCommand(type: "disconnect"))
            } catch {
                emit(.diagnostic("无法向 HITSZ Connect 发送断开命令：\(error.localizedDescription)"))
            }
            return process
        }
        guard let child else { return }

        let deadline = Date().addingTimeInterval(max(0, timeout))
        while child.isRunning && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.05)
        }
        if child.isRunning {
            child.terminate()
            let forceDeadline = Date().addingTimeInterval(1)
            while child.isRunning && Date() < forceDeadline {
                Thread.sleep(forTimeInterval: 0.05)
            }
        }
        if !child.isRunning {
            queue.sync {
                didTerminate(child)
            }
        }
    }

    private func executableURL() throws -> URL {
        if let bundled = Bundle.main.url(forResource: "hitsz-connect", withExtension: nil),
           FileManager.default.isExecutableFile(atPath: bundled.path) {
            return bundled
        }
        throw BridgeClientError.executableNotFound("应用包 Contents/Resources/hitsz-connect")
    }

    private func configureOutputHandlers() {
        stdout?.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            self?.queue.async { self?.consume(data, isError: false) }
        }
        stderr?.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            self?.queue.async { self?.consume(data, isError: true) }
        }
    }

    private func sendLocked(_ command: BridgeCommand) throws {
        guard let stdin, process?.isRunning == true else {
            throw BridgeClientError.notRunning
        }
        let encoder = JSONEncoder()
        let payload = try encoder.encode(command) + Data([0x0A])
        try stdin.write(contentsOf: payload)
    }

    private func consume(_ data: Data, isError: Bool) {
        if data.isEmpty { return }
        if isError {
            stderrBuffer.append(data)
            drain(&stderrBuffer, isError: true)
        } else {
            stdoutBuffer.append(data)
            drain(&stdoutBuffer, isError: false)
        }
    }

    private func drain(_ buffer: inout Data, isError: Bool) {
        while let newline = buffer.firstIndex(of: 0x0A) {
            let line = buffer.prefix(upTo: newline)
            buffer.removeSubrange(...newline)
            guard !line.isEmpty else { continue }
            if isError {
                let text = String(data: line, encoding: .utf8) ?? "HITSZ Connect 输出了无法识别的诊断信息。"
                emit(.diagnostic(text))
            } else if let event = BridgeInboundEvent.decode(line: Data(line)) {
                emit(.bridge(event))
            } else if let text = String(data: line, encoding: .utf8), !text.isEmpty {
                emit(.diagnostic(text))
            }
        }
    }

    private func didTerminate(_ child: Process) {
        guard process === child else { return }
        let status = child.terminationStatus
        cleanupHandles()
        process = nil
        emit(.terminated(status))
    }

    private func cleanupHandles() {
        stdout?.readabilityHandler = nil
        stderr?.readabilityHandler = nil
        try? stdin?.close()
        try? stdout?.close()
        try? stderr?.close()
        stdin = nil
        stdout = nil
        stderr = nil
        stdoutBuffer.removeAll(keepingCapacity: false)
        stderrBuffer.removeAll(keepingCapacity: false)
    }

    private func emit(_ event: Event) {
        onEvent?(event)
    }
}

enum BridgeClientError: LocalizedError {
    case alreadyRunning
    case notRunning
    case executableNotFound(String)

    var errorDescription: String? {
        switch self {
        case .alreadyRunning:
            return "HITSZ Connect 已在运行。"
        case .notRunning:
            return "HITSZ Connect 尚未运行。"
        case let .executableNotFound(path):
            return "找不到内置 HITSZ Connect 命令行程序（\(path)）。请重新安装应用。"
        }
    }
}
