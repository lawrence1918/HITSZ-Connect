import AppKit
import Foundation
import SwiftUI

struct AppAlert: Identifiable {
    let id = UUID()
    let title: String
    let message: String
}

@MainActor
final class AppState: ObservableObject {
    @Published private(set) var profiles: [SecureProfilePayload] = []
    @Published var selectedProfileID: String? {
        didSet {
            if let selectedProfileID {
                UserDefaults.standard.set(selectedProfileID, forKey: Self.selectedProfileDefaultsKey)
            } else {
                UserDefaults.standard.removeObject(forKey: Self.selectedProfileDefaultsKey)
            }
        }
    }
    @Published private(set) var phase: ConnectionPhase = .disconnected
    @Published private(set) var atrustTraffic: BridgeTraffic = .empty
    @Published private(set) var listeners: BridgeListeners = .empty
    @Published private(set) var shadowrocketSnapshot = ShadowrocketSnapshot.initial
    @Published private(set) var awaitingBridgeTermination = false
    @Published var activityMessage = "请选择或创建一个加密配置文件。"
    @Published var alert: AppAlert?
    @Published var mfaPrompt: MFAPrompt?

    let profileStore: SecureProfileStore
    let shadowrocketMonitor: ShadowrocketMonitor
    private let bridge: BridgeClient
    private var activeProfileID: String?
    private var hasShutdown = false
    private var connectionAttemptID: UUID?
    private var bootstrapInFlight = false
    private var bridgeFailed = false
    private var bridgeFailureMessage: String?
    private var bridgeCleanupCompleted = false
    private var atrustReachedReady = false
    // Set when the app paused a tunnel which was already active before an
    // aTrust attempt. Keep it set until a successful restore (or an explicit
    // user disconnect) so every failure/cancellation path can preserve the
    // user's previous VPN state.
    private var shadowrocketRestoreNeeded = false
    private var shadowrocketRestoreInFlight = false
    private var shadowrocketRestoreWaiters: [(Bool) -> Void] = []
    private var shadowrocketInitiallyActive = false
    private var shadowrocketStartedBySession = false
    private var shouldConnectShadowrocketAfterReady = false

    private static let selectedProfileDefaultsKey = "com.heheyizhi.hitsz-connect.selected-profile-id"

    init(
        profileStore: SecureProfileStore = .shared,
        bridge: BridgeClient = BridgeClient(),
        shadowrocketMonitor: ShadowrocketMonitor = ShadowrocketMonitor()
    ) {
        self.profileStore = profileStore
        self.bridge = bridge
        self.shadowrocketMonitor = shadowrocketMonitor
        selectedProfileID = UserDefaults.standard.string(forKey: Self.selectedProfileDefaultsKey)

        bridge.onEvent = { [weak self] event in
            DispatchQueue.main.async {
                self?.handleBridgeEvent(event)
            }
        }
        shadowrocketMonitor.onSnapshot = { [weak self] snapshot in
            self?.shadowrocketSnapshot = snapshot
        }
        reloadProfiles()
    }

    var selectedProfile: SecureProfilePayload? {
        guard let selectedProfileID else { return nil }
        return profiles.first(where: { $0.id == selectedProfileID })
    }

    var isBridgeRunning: Bool {
        bridge.isRunning
    }

    var isBusy: Bool {
        phase == .connecting || phase == .disconnecting || bootstrapInFlight || shadowrocketRestoreInFlight
    }

    var canConnect: Bool {
        selectedProfile != nil && phase != .connected && !isBusy && !bridge.isRunning
            && !awaitingBridgeTermination && !shadowrocketRestoreNeeded
    }

    func reloadProfiles() {
        do {
            let listing = try profileStore.listProfiles()
            profiles = listing.profiles
            if let selectedProfileID, profiles.contains(where: { $0.id == selectedProfileID }) {
                // Keep the user's selection.
            } else {
                selectedProfileID = profiles.first?.id
            }
            if !listing.unreadableFiles.isEmpty {
                let names = listing.unreadableFiles.map(\.lastPathComponent).joined(separator: "、")
                alert = AppAlert(
                    title: "部分配置无法读取",
                    message: "以下加密配置无法用本机钥匙串打开：\(names)。它们没有被修改。"
                )
            }
            if profiles.isEmpty {
                activityMessage = "在 \(profileStore.directoryURL.path) 创建第一个加密配置。"
            }
        } catch {
            alert = AppAlert(title: "无法读取配置", message: error.localizedDescription)
        }
    }

    @discardableResult
    func saveProfile(_ draft: SecureProfilePayload) -> Bool {
        var sanitized = draft
        sanitized.name = sanitized.name.trimmingCharacters(in: .whitespacesAndNewlines)
        if sanitized.name.isEmpty {
            sanitized.name = "我的 HITSZ 连接"
        }
        do {
            let saved = try profileStore.save(sanitized)
            if let index = profiles.firstIndex(where: { $0.id == saved.id }) {
                profiles[index] = saved
            } else {
                profiles.append(saved)
                profiles.sort { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
            }
            selectedProfileID = saved.id
            activityMessage = "已将连接参数加密保存到 \(profileStore.directoryURL.lastPathComponent)。"
            return true
        } catch {
            alert = AppAlert(title: "无法保存配置", message: error.localizedDescription)
            return false
        }
    }

    func importProfile(from url: URL) {
        let hasSecurityScope = url.startAccessingSecurityScopedResource()
        defer {
            if hasSecurityScope { url.stopAccessingSecurityScopedResource() }
        }
        do {
            let imported = try profileStore.importProfile(from: url)
            if let index = profiles.firstIndex(where: { $0.id == imported.id }) {
                profiles[index] = imported
            } else {
                profiles.append(imported)
                profiles.sort { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
            }
            selectedProfileID = imported.id
            activityMessage = "已导入并验证加密配置。"
        } catch {
            alert = AppAlert(title: "无法导入配置", message: error.localizedDescription)
        }
    }

    func deleteSelectedProfile() {
        guard let profile = selectedProfile else { return }
        guard activeProfileID != profile.id else {
            alert = AppAlert(title: "无法删除", message: "请先关闭使用此配置的连接。")
            return
        }
        do {
            try profileStore.delete(profile)
            profiles.removeAll { $0.id == profile.id }
            selectedProfileID = profiles.first?.id
            activityMessage = "已删除加密配置及其本机钥匙串密钥。"
        } catch {
            alert = AppAlert(title: "无法删除配置", message: error.localizedDescription)
        }
    }

    func startSelectedProfile() {
        guard let profile = selectedProfile else {
            alert = AppAlert(title: "请选择配置", message: "先创建或选择一个加密配置文件。")
            return
        }
        guard canConnect else { return }
        let config = profile.config
        guard !config.username.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              !config.password.isEmpty else {
            alert = AppAlert(title: "信息不完整", message: "请在配置中填写统一认证账号和密码。")
            return
        }
        if config.mfaMethod.lowercased() == "otp", config.mfaOTPSecret.isEmpty {
            alert = AppAlert(title: "缺少 OTP 种子", message: "OTP 方式需要在配置中填写 OTP 种子。")
            return
        }

        let attemptID = UUID()
        connectionAttemptID = attemptID
        bootstrapInFlight = true
        bridgeFailed = false
        bridgeFailureMessage = nil
        bridgeCleanupCompleted = false
        atrustReachedReady = false
        phase = .connecting
        atrustTraffic = .empty
        listeners = .empty
        activeProfileID = profile.id
        activityMessage = "正在启动 HITSZ Connect…"

        // A previously connected Shadowrocket profile can capture the HITSZ
        // IdP into 127.0.0.1:1080 before aTrust has created that listener.
        // Pause it first, then let the bridge authenticate over system routing
        // and restore/start Shadowrocket after the bridge is ready.
        shadowrocketRestoreNeeded = false
        shadowrocketRestoreInFlight = false
        shadowrocketInitiallyActive = false
        shadowrocketStartedBySession = false
        shouldConnectShadowrocketAfterReady = config.shadowrocket.lowercased() == "connect"
        shadowrocketMonitor.prepareForATrustBootstrap { [weak self] result in
            guard let self else { return }
            self.bootstrapInFlight = false
            switch result {
            case let .ready(wasActive):
                guard self.connectionAttemptID == attemptID,
                      self.phase == .connecting else {
                    self.shadowrocketInitiallyActive = wasActive
                    self.shadowrocketRestoreNeeded = wasActive
                    self.finishCancelledBootstrap()
                    return
                }
                self.shadowrocketInitiallyActive = wasActive
                self.shadowrocketRestoreNeeded = wasActive
                self.shouldConnectShadowrocketAfterReady = wasActive || config.shadowrocket.lowercased() == "connect"
                if wasActive {
                    self.activityMessage = "已静默暂停 Shadowrocket，正在启动 aTrust…"
                }
                self.launchBridge(profile, attemptID: attemptID)
            case let .failed(error, restoreNeeded):
                self.shadowrocketInitiallyActive = restoreNeeded
                self.shadowrocketRestoreNeeded = restoreNeeded
                guard self.connectionAttemptID == attemptID,
                      self.phase == .connecting else {
                    self.finishCancelledBootstrap()
                    return
                }
                self.failConnection("无法准备 aTrust 连接：\(error.localizedDescription)")
            }
        }
    }

    private func launchBridge(_ profile: SecureProfilePayload, attemptID: UUID) {
        guard connectionAttemptID == attemptID, phase == .connecting else { return }
        // The App owns bootstrap routing and Shadowrocket lifecycle; the
        // saved user preferences remain unchanged.
        let runtimeConfig = profile.config.preparedForAppBridge()
        do {
            try bridge.start(config: runtimeConfig, clientData: profile.clientData)
            awaitingBridgeTermination = true
        } catch {
            awaitingBridgeTermination = false
            failConnection("无法启动连接：\(error.localizedDescription)")
        }
    }

    private func failConnection(_ message: String, restoreShadowrocket: Bool = true) {
        connectionAttemptID = nil
        bridgeFailed = true
        bridgeFailureMessage = message
        phase = .failed
        activityMessage = message
        mfaPrompt = nil
        activeProfileID = nil
        bridgeCleanupCompleted = true
        alert = AppAlert(title: "连接失败", message: message)
        if restoreShadowrocket {
            restoreShadowrocketIfNeeded()
        }
    }

    private func restoreShadowrocketIfNeeded(completion: ((Bool) -> Void)? = nil) {
        if let completion {
            shadowrocketRestoreWaiters.append(completion)
        }
        guard shadowrocketRestoreNeeded else {
            completeShadowrocketRestoreWaiters(restored: true)
            return
        }
        guard !shadowrocketRestoreInFlight else { return }
        shadowrocketRestoreInFlight = true
        shouldConnectShadowrocketAfterReady = false
        shadowrocketMonitor.connect { [weak self] result in
            guard let self else { return }
            self.shadowrocketRestoreInFlight = false
            switch result {
            case .success:
                self.shadowrocketRestoreNeeded = false
                if self.phase == .failed {
                    self.activityMessage += "（连接前的 Shadowrocket 状态已恢复。）"
                } else if self.phase == .connected {
                    self.activityMessage = "aTrust 与 Shadowrocket 已连接。"
                } else {
                    self.activityMessage = "已恢复连接前的 Shadowrocket 状态。"
                }
                self.completeShadowrocketRestoreWaiters(restored: true)
            case let .failure(error):
                // Keep the flag set. A later stop/termination or an explicit
                // retry can attempt restoration again instead of silently
                // leaving the user's original tunnel disconnected.
                let restorationError = "无法恢复连接前的 Shadowrocket 状态：\(error.localizedDescription)"
                if self.phase == .failed {
                    self.activityMessage += "（\(restorationError)）"
                } else {
                    self.activityMessage = restorationError
                }
                self.alert = AppAlert(title: "无法恢复 Shadowrocket", message: restorationError)
                self.completeShadowrocketRestoreWaiters(restored: false)
            }
        }
    }

    private func completeShadowrocketRestoreWaiters(restored: Bool) {
        let waiters = shadowrocketRestoreWaiters
        shadowrocketRestoreWaiters.removeAll(keepingCapacity: false)
        for waiter in waiters {
            waiter(restored)
        }
    }

    private func finishCancelledBootstrap() {
        shouldConnectShadowrocketAfterReady = false
        activeProfileID = nil
        if hasShutdown {
            if shadowrocketRestoreNeeded, shadowrocketMonitor.connectAndWait() {
                shadowrocketRestoreNeeded = false
            }
            return
        }
        let wasRestoringShadowrocket = shadowrocketRestoreNeeded
        phase = .disconnecting
        activityMessage = "正在恢复连接前的网络状态…"
        restoreShadowrocketIfNeeded { [weak self] restored in
            guard let self else { return }
            self.phase = restored ? .disconnected : .failed
            if restored {
                self.activityMessage = wasRestoringShadowrocket ? "已取消连接，并恢复 Shadowrocket。" : "已取消连接。"
            }
        }
    }

    func stopConnection() {
        guard !shadowrocketRestoreInFlight else { return }
        guard phase != .disconnected || bridge.isRunning else { return }
        connectionAttemptID = nil
        shouldConnectShadowrocketAfterReady = false
        if !bridge.isRunning {
            if bootstrapInFlight {
                phase = .disconnecting
                activityMessage = "正在取消连接准备…"
            } else {
                finishCancelledBootstrap()
            }
            return
        }
        phase = .disconnecting
        activityMessage = "正在关闭 HITSZ Connect…"
        bridge.stop()
        DispatchQueue.main.asyncAfter(deadline: .now() + 10) { [weak self] in
            guard let self, self.phase == .disconnecting, self.bridge.isRunning else { return }
            self.activityMessage = "连接进程未在规定时间内退出，正在停止它。"
            self.bridge.forceStop()
        }
    }

    func sendMFACode(_ code: String) {
        guard !code.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            alert = AppAlert(title: "验证码为空", message: "请输入 App 或短信验证码。")
            return
        }
        do {
            try bridge.sendMFACode(code, requestId: mfaPrompt?.requestId)
            mfaPrompt = nil
            activityMessage = "验证码已安全发送到本地连接进程。"
        } catch {
            alert = AppAlert(title: "无法提交验证码", message: error.localizedDescription)
        }
    }

    func cancelMFAPrompt() {
        mfaPrompt = nil
        stopConnection()
    }

    func connectShadowrocket() {
        guard phase != .connecting, phase != .disconnecting, !bootstrapInFlight else { return }
        shadowrocketMonitor.connect { [weak self] result in
            guard let self else { return }
            if case .success = result {
                self.shadowrocketRestoreNeeded = false
            }
            if case let .failure(error) = result {
                self.alert = AppAlert(title: "无法连接 Shadowrocket", message: error.localizedDescription)
            }
        }
    }

    func disconnectShadowrocket() {
        guard phase != .connecting, phase != .disconnecting, !bootstrapInFlight else { return }
        // An explicit user action takes precedence over automatic restoration.
        shadowrocketRestoreNeeded = false
        shadowrocketMonitor.disconnect { [weak self] result in
            if case let .failure(error) = result {
                self?.alert = AppAlert(title: "无法断开 Shadowrocket", message: error.localizedDescription)
            }
        }
    }

    func openProfilesFolder() {
        do {
            try profileStore.ensureDirectory()
            NSWorkspace.shared.open(profileStore.directoryURL)
        } catch {
            alert = AppAlert(title: "无法打开配置目录", message: error.localizedDescription)
        }
    }

    /// Called at application termination.  It keeps the configured behavior
    /// for Shadowrocket distinct from the aTrust process's shutdown.
    func shutdown() {
        guard !hasShutdown else { return }
        hasShutdown = true
        let profileID = activeProfileID
        bridge.stopAndWait(timeout: 5)
        if !bridgeFailed,
           atrustReachedReady,
           let profileID,
           let profile = profiles.first(where: { $0.id == profileID }),
           profile.config.shadowrocketDisconnectOnExit {
            shadowrocketRestoreNeeded = false
            shadowrocketMonitor.disconnectAndWait()
            return
        }
        // This synchronous queue-owned lease also covers quitting while the
        // asynchronous bootstrap callback is still waiting for the main actor.
        switch shadowrocketMonitor.restoreBootstrapStateAndWait() {
        case .restored:
            shadowrocketRestoreNeeded = false
            return
        case .failed:
            return
        case .notNeeded:
            break
        }
    }

    private func handleBridgeEvent(_ event: BridgeClient.Event) {
        switch event {
        case let .bridge(message):
            apply(message)
        case let .diagnostic(text):
            // The bridge's structured event is preferred, but retaining a
            // short diagnostic makes a packaging/launch failure explainable.
            if !text.isEmpty, phase != .connected, !bridgeFailed {
                activityMessage = text
            }
        case let .terminated(status):
            awaitingBridgeTermination = false
            let endingProfileID = activeProfileID
            if status != 0 && phase != .disconnecting && !bridgeFailed {
                bridgeFailed = true
                phase = .failed
                activityMessage = "HITSZ Connect 意外退出（状态 \(status)）。"
                bridgeFailureMessage = activityMessage
                alert = AppAlert(title: "连接失败", message: activityMessage)
            } else if !bridgeFailed {
                phase = .disconnected
                activityMessage = "HITSZ Connect 已关闭。"
            }
            atrustTraffic = .empty
            listeners = .empty
            mfaPrompt = nil
            connectionAttemptID = nil
            completeBridgeSession(profileID: endingProfileID, failed: bridgeFailed)
        }
    }

    private func apply(_ message: BridgeInboundEvent) {
        let messageType = message.type.lowercased()
        // Keep the original failure visible when the Go bridge follows its
        // error event with a normal stopped event during cleanup.
        let acceptsMessage: Bool
        switch messageType {
        case "phase", "ready", "mfarequired":
            acceptsMessage = !bridgeFailed && phase == .connecting && connectionAttemptID != nil
        case "status", "clientdata":
            acceptsMessage = !bridgeFailed && (phase == .connecting || phase == .connected)
        case "stopped":
            acceptsMessage = false
        default:
            acceptsMessage = !bridgeFailed
        }
        if acceptsMessage {
            if let text = message.message, !text.isEmpty {
                activityMessage = text
            }
            if let error = message.error, !error.isEmpty {
                activityMessage = error
            }
        }
        if let traffic = message.atrust {
            atrustTraffic = traffic
        }
        if let listeners = message.listeners {
            self.listeners = listeners
        }

        switch messageType {
        case "phase":
            guard !bridgeFailed, phase != .disconnecting else { break }
            phase = ConnectionPhase(bridgeValue: message.state)
        case "ready":
            guard !bridgeFailed,
                  phase == .connecting,
                  let attemptID = connectionAttemptID else {
                // A ready event can race with a user cancellation. Keep the
                // stop latch authoritative and never start Shadowrocket for
                // a session which is already being torn down.
                if bridge.isRunning { bridge.stop() }
                break
            }
            atrustReachedReady = true
            phase = .connected
            startShadowrocketAfterReady(attemptID: attemptID)
        case "status":
            guard !bridgeFailed, phase != .disconnecting else { break }
            if let state = message.state {
                phase = ConnectionPhase(bridgeValue: state)
            } else if message.atrust?.connected == true {
                phase = .connected
            }
        case "clientdata":
            if let clientData = message.clientData {
                persistClientData(clientData)
            }
        case "mfarequired":
            guard !bridgeFailed, phase == .connecting, connectionAttemptID != nil else { break }
            mfaPrompt = MFAPrompt(
                method: message.method ?? selectedProfile?.config.mfaMethod ?? "",
                message: message.message ?? "请输入收到的验证码。",
                requestId: message.requestId
            )
        case "error":
            bridgeFailed = true
            connectionAttemptID = nil
            shouldConnectShadowrocketAfterReady = false
            phase = .failed
            mfaPrompt = nil
            let error = message.error ?? message.message ?? "aTrust 返回了未说明的错误。"
            if bridgeFailureMessage == nil {
                bridgeFailureMessage = error
                activityMessage = error
                alert = AppAlert(title: "aTrust 连接失败", message: error)
            }
            bridge.stop()
            DispatchQueue.main.asyncAfter(deadline: .now() + 10) { [weak self] in
                guard let self, self.bridgeFailed, self.bridge.isRunning else { return }
                self.bridge.forceStop()
            }
        case "stopped":
            let endingProfileID = activeProfileID
            let failed = bridgeFailed
            if !failed {
                phase = .disconnected
            }
            atrustTraffic = .empty
            listeners = .empty
            mfaPrompt = nil
            connectionAttemptID = nil
            completeBridgeSession(profileID: endingProfileID, failed: failed)
        default:
            break
        }
    }

    private func persistClientData(_ clientData: String) {
        guard let id = activeProfileID ?? selectedProfileID,
              var profile = profiles.first(where: { $0.id == id }) else { return }
        profile.clientData = clientData
        do {
            let saved = try profileStore.save(profile)
            if let index = profiles.firstIndex(where: { $0.id == saved.id }) {
                profiles[index] = saved
            }
            if !bridgeFailed {
                activityMessage = "已加密更新 aTrust 会话数据。"
            }
        } catch {
            alert = AppAlert(title: "无法保存会话数据", message: error.localizedDescription)
        }
    }

    private func completeBridgeSession(profileID: String?, failed: Bool) {
        guard !bridgeCleanupCompleted else { return }
        bridgeCleanupCompleted = true
        shouldConnectShadowrocketAfterReady = false

        // A session which never reached ready always restores the VPN state it
        // paused, regardless of disconnect-on-exit. After ready, a normal user
        // stop honors the explicit option; a failure preserves a pre-existing
        // tunnel and only tears down one newly started by this session.
        let disconnectOnExit = profileID.flatMap { id in
            profiles.first(where: { $0.id == id })?.config.shadowrocketDisconnectOnExit
        } ?? false

        let shouldDisconnect: Bool
        if failed {
            shouldDisconnect = atrustReachedReady && !shadowrocketInitiallyActive && shadowrocketStartedBySession
        } else {
            shouldDisconnect = atrustReachedReady && disconnectOnExit
        }

        if failed {
            if shadowrocketRestoreNeeded {
                restoreShadowrocketIfNeeded()
            } else if shouldDisconnect {
                disconnectShadowrocketAfterSession()
            }
        } else if !atrustReachedReady {
            restoreShadowrocketIfNeeded()
        } else if shouldDisconnect {
            shadowrocketRestoreNeeded = false
            disconnectShadowrocketAfterSession()
        } else if shadowrocketRestoreNeeded {
            restoreShadowrocketIfNeeded()
        }
        activeProfileID = nil
    }

    private func disconnectShadowrocketAfterSession() {
        shadowrocketMonitor.disconnect { [weak self] result in
            if case let .failure(error) = result {
                self?.activityMessage = "aTrust 已关闭，但 Shadowrocket 断开失败：\(error.localizedDescription)"
            }
        }
    }

    private func startShadowrocketAfterReady(attemptID: UUID) {
        guard shouldConnectShadowrocketAfterReady else {
            return
        }
        shouldConnectShadowrocketAfterReady = false
        let wasInitiallyActive = shadowrocketInitiallyActive
        activityMessage = "aTrust 已连接，正在静默启动 Shadowrocket…"
        shadowrocketMonitor.connect { [weak self] result in
            guard let self else { return }
            guard self.connectionAttemptID == attemptID,
                  self.phase == .connected,
                  !self.bridgeFailed else {
                // If a late start completes after cancellation, preserve an
                // originally active tunnel but undo one newly created by this
                // obsolete session.
                if case .success = result {
                    if wasInitiallyActive {
                        self.shadowrocketRestoreNeeded = false
                    } else {
                        self.shadowrocketMonitor.disconnect()
                    }
                } else if wasInitiallyActive {
                    self.restoreShadowrocketIfNeeded()
                }
                return
            }
            switch result {
            case .success:
                self.shadowrocketRestoreNeeded = false
                self.shadowrocketStartedBySession = !wasInitiallyActive
                self.activityMessage = "aTrust 与 Shadowrocket 已连接。"
            case let .failure(error):
                self.alert = AppAlert(title: "Shadowrocket 连接失败", message: error.localizedDescription)
                self.activityMessage = "aTrust 已连接，但 Shadowrocket 启动失败。"
                self.restoreShadowrocketIfNeeded()
            }
        }
    }
}
