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
    @Published var activityMessage = "请选择或创建一个加密配置文件。"
    @Published var alert: AppAlert?
    @Published var mfaPrompt: MFAPrompt?

    let profileStore: SecureProfileStore
    let shadowrocketMonitor: ShadowrocketMonitor
    private let bridge: BridgeClient
    private var activeProfileID: String?
    private var hasShutdown = false

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
        phase == .connecting || phase == .disconnecting
    }

    var canConnect: Bool {
        selectedProfile != nil && phase != .connected && !isBusy && !bridge.isRunning
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

        let previousPhase = phase
        let previousActiveProfileID = activeProfileID
        phase = .connecting
        atrustTraffic = .empty
        listeners = .empty
        activeProfileID = profile.id
        activityMessage = "正在启动 HITSZ Connect…"
        do {
            try bridge.start(config: config, clientData: profile.clientData)
        } catch BridgeClientError.alreadyRunning {
            phase = previousPhase
            activeProfileID = previousActiveProfileID
            activityMessage = "HITSZ Connect 已在运行，正在等待其状态。"
        } catch {
            phase = .failed
            activeProfileID = nil
            alert = AppAlert(title: "无法启动连接", message: error.localizedDescription)
        }
    }

    func stopConnection() {
        guard phase != .disconnected || bridge.isRunning else { return }
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
        if !shadowrocketMonitor.connect() {
            alert = AppAlert(title: "无法唤起 Shadowrocket", message: "macOS 没有处理 shadowrocket:// URL。请确认 Shadowrocket 已安装。")
        }
    }

    func disconnectShadowrocket() {
        if !shadowrocketMonitor.disconnect() {
            alert = AppAlert(title: "无法唤起 Shadowrocket", message: "macOS 没有处理 shadowrocket:// URL。请确认 Shadowrocket 已安装。")
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
        let profileID = activeProfileID ?? selectedProfileID
        bridge.stopAndWait(timeout: 5)
        disconnectShadowrocketIfConfigured(profileID: profileID)
    }

    private func handleBridgeEvent(_ event: BridgeClient.Event) {
        switch event {
        case let .bridge(message):
            apply(message)
        case let .diagnostic(text):
            // The bridge's structured event is preferred, but retaining a
            // short diagnostic makes a packaging/launch failure explainable.
            if !text.isEmpty, phase != .connected {
                activityMessage = text
            }
        case let .terminated(status):
            let endingProfileID = activeProfileID
            if phase == .connecting && status != 0 {
                phase = .failed
                activityMessage = "HITSZ Connect 意外退出（状态 \(status)）。"
            } else if phase != .failed {
                phase = .disconnected
                activityMessage = "HITSZ Connect 已关闭。"
            }
            atrustTraffic = .empty
            listeners = .empty
            mfaPrompt = nil
            disconnectShadowrocketIfConfigured(profileID: endingProfileID)
            activeProfileID = nil
        }
    }

    private func apply(_ message: BridgeInboundEvent) {
        if let text = message.message, !text.isEmpty {
            activityMessage = text
        }
        if let traffic = message.atrust {
            atrustTraffic = traffic
        }
        if let listeners = message.listeners {
            self.listeners = listeners
        }

        switch message.type.lowercased() {
        case "phase":
            phase = ConnectionPhase(bridgeValue: message.state)
        case "ready":
            phase = .connected
        case "status":
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
            mfaPrompt = MFAPrompt(
                method: message.method ?? selectedProfile?.config.mfaMethod ?? "",
                message: message.message ?? "请输入收到的验证码。",
                requestId: message.requestId
            )
        case "error":
            phase = .failed
            mfaPrompt = nil
        case "stopped":
            let endingProfileID = activeProfileID
            phase = .disconnected
            atrustTraffic = .empty
            listeners = .empty
            mfaPrompt = nil
            disconnectShadowrocketIfConfigured(profileID: endingProfileID)
            activeProfileID = nil
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
            activityMessage = "已加密更新 aTrust 会话数据。"
        } catch {
            alert = AppAlert(title: "无法保存会话数据", message: error.localizedDescription)
        }
    }

    private func disconnectShadowrocketIfConfigured(profileID: String?) {
        guard let id = profileID,
              let profile = profiles.first(where: { $0.id == id }),
              profile.config.shadowrocketDisconnectOnExit else { return }
        _ = shadowrocketMonitor.disconnect()
    }
}
