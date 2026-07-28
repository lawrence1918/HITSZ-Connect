import AppKit
import Combine
import SwiftUI
import UniformTypeIdentifiers

/// These small reference models intentionally use public `@StateObject` and
/// `@Published` rather than the SDK's new `@State` macro.  That keeps the
/// SwiftPM build usable with Command Line Tools installations which ship the
/// SwiftUI framework but not the optional SwiftUIMacros plugin.
private final class ContentPresentationModel: ObservableObject {
    @Published var editingProfile: SecureProfilePayload?
    @Published var showingImporter = false
    @Published var showingDeletionConfirmation = false
}

private final class ProfileEditorModel: ObservableObject {
    @Published var draft: SecureProfilePayload
    @Published var showAdvanced = false
    @Published var serverPortText: String

    init(profile: SecureProfilePayload) {
        draft = profile
        serverPortText = profile.config.serverPort.map(String.init) ?? ""
    }
}

private final class MFAEntryModel: ObservableObject {
    @Published var code = ""
}

struct ContentView: View {
    @EnvironmentObject private var state: AppState
    @StateObject private var presentation = ContentPresentationModel()

    var body: some View {
        Group {
            if state.profiles.isEmpty {
                SetupView(
                    profilesDirectory: state.profileStore.directoryURL,
                    createProfile: { presentation.editingProfile = .newDefault() },
                    importProfile: { presentation.showingImporter = true },
                    openFolder: state.openProfilesFolder
                )
            } else {
                DashboardView(
                    presentation: presentation
                )
            }
        }
        .sheet(item: $presentation.editingProfile) { profile in
            ProfileEditorView(profile: profile) { edited in
                if state.saveProfile(edited) {
                    presentation.editingProfile = nil
                }
            }
        }
        .sheet(item: $state.mfaPrompt) { prompt in
            MFAEntryView(
                prompt: prompt,
                submit: state.sendMFACode,
                cancel: state.cancelMFAPrompt
            )
            .interactiveDismissDisabled()
        }
        .fileImporter(
            isPresented: $presentation.showingImporter,
            allowedContentTypes: [UTType(filenameExtension: "hcenc") ?? .data],
            allowsMultipleSelection: false
        ) { result in
            switch result {
            case let .success(urls):
                if let url = urls.first { state.importProfile(from: url) }
            case let .failure(error):
                state.alert = AppAlert(title: "无法选择配置", message: error.localizedDescription)
            }
        }
        .alert(item: $state.alert) { alert in
            Alert(
                title: Text(alert.title),
                message: Text(alert.message),
                dismissButton: .default(Text("好"))
            )
        }
        .confirmationDialog(
            "删除当前加密配置？",
            isPresented: $presentation.showingDeletionConfirmation,
            titleVisibility: .visible
        ) {
            Button("删除配置和本机钥匙串密钥", role: .destructive) {
                state.deleteSelectedProfile()
            }
        } message: {
            Text("此操作会删除 .hcenc 文件和这台 Mac 上对应的密钥，无法恢复。")
        }
    }
}

private struct SetupView: View {
    let profilesDirectory: URL
    let createProfile: () -> Void
    let importProfile: () -> Void
    let openFolder: () -> Void

    var body: some View {
        VStack(spacing: 22) {
            Image(systemName: "lock.shield")
                .font(.system(size: 52))
                .foregroundStyle(.tint)
            Text("欢迎使用 HITSZ Connect")
                .font(.title.bold())
            Text("首次连接会将账号、密码、OTP 种子和 aTrust 会话数据加密保存在本机钥匙串保护的配置文件中。")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .frame(maxWidth: 500)
            VStack(alignment: .leading, spacing: 8) {
                Label("配置目录", systemImage: "folder")
                Text(profilesDirectory.path)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                    .foregroundStyle(.secondary)
            }
            .padding()
            .background(.quaternary, in: RoundedRectangle(cornerRadius: 10))
            HStack {
                Button("创建第一个配置", action: createProfile)
                    .buttonStyle(.borderedProminent)
                Button("导入本机配置", action: importProfile)
                Button("打开配置目录", action: openFolder)
            }
            Text("导入的 .hcenc 文件必须来自同一台 Mac；密钥不会离开 macOS 钥匙串。")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

private struct DashboardView: View {
    @EnvironmentObject private var state: AppState
    @ObservedObject var presentation: ContentPresentationModel

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("HITSZ Connect")
                        .font(.largeTitle.bold())
                    Text(state.activityMessage)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }
                Spacer()
                connectionButton
            }

            HStack(spacing: 10) {
                Text("加密配置")
                    .foregroundStyle(.secondary)
                Picker("加密配置", selection: selectedProfileBinding) {
                    ForEach(state.profiles) { profile in
                        Text(profile.name).tag(profile.id)
                    }
                }
                .labelsHidden()
                .frame(maxWidth: 260)
                .disabled(state.isBusy || state.phase == .connected)

                Button("编辑") {
                    presentation.editingProfile = state.selectedProfile
                }
                .disabled(state.selectedProfile == nil || state.phase == .connected)
                Button("新建") { presentation.editingProfile = .newDefault() }
                    .disabled(state.isBusy || state.phase == .connected)
                Menu {
                    Button("导入本机配置") { presentation.showingImporter = true }
                    Button("打开配置目录") { state.openProfilesFolder() }
                    Divider()
                    Button("删除当前配置", role: .destructive) {
                        presentation.showingDeletionConfirmation = true
                    }
                    .disabled(state.selectedProfile == nil || state.phase == .connected)
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
                .menuStyle(.borderlessButton)
            }

            HStack(alignment: .top, spacing: 16) {
                StatusCard(
                    title: "aTrust 校园连接",
                    systemImage: state.phase.systemImage,
                    tint: phaseTint(state.phase),
                    status: state.phase.title,
                    incomingRate: state.atrustTraffic.rxBytesPerSecond,
                    outgoingRate: state.atrustTraffic.txBytesPerSecond,
                    incomingTotal: state.atrustTraffic.rxBytes,
                    outgoingTotal: state.atrustTraffic.txBytes,
                    footer: listenerDescription(state.listeners)
                )
                StatusCard(
                    title: "Shadowrocket",
                    systemImage: state.shadowrocketSnapshot.state.systemImage,
                    tint: shadowrocketTint(state.shadowrocketSnapshot.state),
                    status: state.shadowrocketSnapshot.state.title,
                    incomingRate: state.shadowrocketSnapshot.rxBytesPerSecond,
                    outgoingRate: state.shadowrocketSnapshot.txBytesPerSecond,
                    incomingTotal: state.shadowrocketSnapshot.rxBytes,
                    outgoingTotal: state.shadowrocketSnapshot.txBytes,
                    footer: state.shadowrocketSnapshot.serviceName.map { "网络服务：\($0)" } ?? "通过 scutil --nc 实时检测"
                )
            }

            HStack(spacing: 10) {
                Button("连接 Shadowrocket") { state.connectShadowrocket() }
                    .disabled(state.isBusy || state.shadowrocketSnapshot.state == .connected)
                Button("断开 Shadowrocket") { state.disconnectShadowrocket() }
                    .disabled(state.isBusy || state.shadowrocketSnapshot.state == .disconnected || state.shadowrocketSnapshot.state == .unavailable)
                Spacer()
                Text("配置均加密存储于 ~/Documents/hitsz-connect")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
        }
        .padding(24)
    }

    private var selectedProfileBinding: Binding<String> {
        Binding(
            get: { state.selectedProfileID ?? state.profiles.first?.id ?? "" },
            set: { state.selectedProfileID = $0 }
        )
    }

    @ViewBuilder
    private var connectionButton: some View {
        if state.phase == .connected || state.phase == .connecting || state.phase == .disconnecting {
            Button(state.phase == .disconnecting ? "断开中" : "关闭连接") {
                state.stopConnection()
            }
            .buttonStyle(.bordered)
            .disabled(state.phase == .disconnecting)
        } else {
            Button("发起连接") { state.startSelectedProfile() }
                .buttonStyle(.borderedProminent)
                .disabled(!state.canConnect)
        }
    }

    private func listenerDescription(_ listeners: BridgeListeners) -> String {
        let names = [
            listeners.socks ? "SOCKS" : nil,
            listeners.http ? "HTTP" : nil,
            listeners.dnsRelay ? "DNS relay" : nil
        ].compactMap { $0 }
        return names.isEmpty ? "等待本地代理服务" : "本地服务：\(names.joined(separator: " · "))"
    }
}

private struct StatusCard: View {
    let title: String
    let systemImage: String
    let tint: Color
    let status: String
    let incomingRate: Double
    let outgoingRate: Double
    let incomingTotal: Int64
    let outgoingTotal: Int64
    let footer: String

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Label(title, systemImage: systemImage)
                    .font(.headline)
                    .foregroundStyle(tint)
                Spacer()
                Text(status)
                    .font(.subheadline.weight(.medium))
                    .foregroundStyle(tint)
            }
            HStack(spacing: 20) {
                TransferMetric(title: "下载", systemImage: "arrow.down", rate: incomingRate, total: incomingTotal)
                TransferMetric(title: "上传", systemImage: "arrow.up", rate: outgoingRate, total: outgoingTotal)
            }
            Text(footer)
                .font(.footnote)
                .foregroundStyle(.secondary)
                .lineLimit(2)
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background, in: RoundedRectangle(cornerRadius: 14))
        .overlay {
            RoundedRectangle(cornerRadius: 14)
                .stroke(.quaternary, lineWidth: 1)
        }
    }
}

private struct TransferMetric: View {
    let title: String
    let systemImage: String
    let rate: Double
    let total: Int64

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Label(title, systemImage: systemImage)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(rate.transferRateDescription)
                .font(.system(.body, design: .monospaced).weight(.semibold))
            Text("累计 \(total.byteCountDescription)")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
    }
}

private struct ProfileEditorView: View {
    @Environment(\.dismiss) private var dismiss
    @StateObject private var model: ProfileEditorModel
    let save: (SecureProfilePayload) -> Void

    init(profile: SecureProfilePayload, save: @escaping (SecureProfilePayload) -> Void) {
        _model = StateObject(wrappedValue: ProfileEditorModel(profile: profile))
        self.save = save
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("配置名称") {
                    TextField("例如：主账号", text: $model.draft.name)
                }

                Section("HITSZ 统一认证") {
                    TextField("学号或手机号", text: $model.draft.config.username)
                        .textContentType(.username)
                    SecureField("统一认证密码", text: $model.draft.config.password)
                        .textContentType(.password)
                    Picker("多因素认证", selection: $model.draft.config.mfaMethod) {
                        Text("OTP（本地生成）").tag("otp")
                        Text("HITSZ App 验证码").tag("app")
                        Text("短信验证码").tag("sms")
                    }
                    if model.draft.config.mfaMethod == "otp" {
                        SecureField("OTP 种子", text: $model.draft.config.mfaOTPSecret)
                            .textContentType(.oneTimeCode)
                        Text("OTP 种子将随配置使用 AES-256-GCM 加密，并由本机钥匙串密钥保护。")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    } else {
                        Text("连接时会在应用内安全地请求验证码。")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }

                Section("Shadowrocket") {
                    Toggle("启动 aTrust 后连接 Shadowrocket", isOn: shadowrocketConnectBinding)
                    Toggle("aTrust 关闭时断开 Shadowrocket", isOn: $model.draft.config.shadowrocketDisconnectOnExit)
                    Toggle("连接时更新订阅", isOn: $model.draft.config.shadowrocketUpdateSubs)
                    Text("为避免 GUI 连接期间意外修改订阅，应用桥接会保持此操作关闭；该参数仍会加密保存，供直接使用加密配置的 CLI 使用。")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }

                Section {
                    DisclosureGroup("高级启动参数", isExpanded: $model.showAdvanced) {
                        TextField("服务器地址", text: optionalStringBinding(\.serverAddress))
                        TextField("服务器端口", text: $model.serverPortText)
                        TextField("登录域", text: optionalStringBinding(\.loginDomain))
                        TextField("认证类型", text: optionalStringBinding(\.authType))
                        TextField("SOCKS 监听地址", text: optionalStringBinding(\.socksBind))
                        TextField("HTTP 监听地址", text: optionalStringBinding(\.httpBind))
                        TextField("DNS relay 监听地址", text: optionalStringBinding(\.dnsRelayBind))
                        TextField("HITSZ DNS 服务器", text: optionalStringBinding(\.hitszDNSServer))
                        Toggle("记住统一认证会话", isOn: $model.draft.config.rememberSSO)
                        Toggle("记住多因素认证会话", isOn: $model.draft.config.rememberMFA)
                    }
                } footer: {
                    Text("默认值适用于 HITSZ aTrust。只有明确了解参数含义时才修改。")
                }

                Section("本机安全存储") {
                    Text("配置：~/Documents/hitsz-connect/*.hcenc")
                    Text("密钥：macOS 钥匙串（不会写入配置文件）")
                }
                .font(.footnote)
                .foregroundStyle(.secondary)
            }
            .formStyle(.grouped)
            .navigationTitle(model.draft.name.isEmpty ? "HITSZ 连接配置" : model.draft.name)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("保存") {
                        model.draft.config.serverPort = Int(model.serverPortText.trimmingCharacters(in: .whitespacesAndNewlines))
                        save(model.draft)
                    }
                    .keyboardShortcut(.defaultAction)
                }
            }
        }
        .frame(minWidth: 570, minHeight: 650)
    }

    private var shadowrocketConnectBinding: Binding<Bool> {
        Binding(
            get: { model.draft.config.shadowrocket.lowercased() == "connect" },
            set: { model.draft.config.shadowrocket = $0 ? "connect" : "off" }
        )
    }

    private func optionalStringBinding(_ keyPath: WritableKeyPath<BridgeConnectionConfig, String?>) -> Binding<String> {
        Binding(
            get: { model.draft.config[keyPath: keyPath] ?? "" },
            set: { model.draft.config[keyPath: keyPath] = $0.nilIfBlank }
        )
    }
}

private struct MFAEntryView: View {
    let prompt: MFAPrompt
    let submit: (String) -> Void
    let cancel: () -> Void
    @StateObject private var model = MFAEntryModel()

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Image(systemName: "number.square")
                .font(.system(size: 36))
                .foregroundStyle(.tint)
            Text(prompt.title)
                .font(.title2.bold())
            Text(prompt.message)
                .foregroundStyle(.secondary)
            TextField("验证码", text: $model.code)
                .textFieldStyle(.roundedBorder)
                .textContentType(.oneTimeCode)
                .onSubmit { submit(model.code) }
            HStack {
                Button("取消并关闭连接", role: .cancel, action: cancel)
                Spacer()
                Button("提交验证码") { submit(model.code) }
                    .buttonStyle(.borderedProminent)
                    .disabled(model.code.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding(28)
        .frame(width: 420)
    }
}

struct StatusMenuView: View {
    @EnvironmentObject private var state: AppState

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("HITSZ Connect")
                .font(.headline)
            Label("aTrust：\(state.phase.title)", systemImage: state.phase.systemImage)
            Text("↓ \(state.atrustTraffic.rxBytesPerSecond.transferRateDescription)   ↑ \(state.atrustTraffic.txBytesPerSecond.transferRateDescription)")
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)
            Divider()
            Label("Shadowrocket：\(state.shadowrocketSnapshot.state.title)", systemImage: state.shadowrocketSnapshot.state.systemImage)
            Text("↓ \(state.shadowrocketSnapshot.rxBytesPerSecond.transferRateDescription)   ↑ \(state.shadowrocketSnapshot.txBytesPerSecond.transferRateDescription)")
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)
            Divider()
            HStack {
                if state.phase == .connected || state.phase == .connecting || state.phase == .disconnecting {
                    Button("关闭 aTrust") { state.stopConnection() }
                        .disabled(state.phase == .disconnecting)
                } else {
                    Button("连接 aTrust") { state.startSelectedProfile() }
                        .disabled(!state.canConnect)
                }
                Button("Shadowrocket") {
                    if state.shadowrocketSnapshot.state == .connected {
                        state.disconnectShadowrocket()
                    } else {
                        state.connectShadowrocket()
                    }
                }
                .disabled(state.isBusy)
            }
            Divider()
            Button("打开主窗口") { bringMainWindowToFront() }
            Button("退出 HITSZ Connect") {
                state.shutdown()
                NSApp.terminate(nil)
            }
        }
        .padding(14)
        .frame(width: 310)
    }

    private func bringMainWindowToFront() {
        NSApp.activate(ignoringOtherApps: true)
        let window = NSApp.windows.first(where: { $0.isVisible }) ?? NSApp.windows.first
        window?.makeKeyAndOrderFront(nil)
    }
}

private func phaseTint(_ phase: ConnectionPhase) -> Color {
    switch phase {
    case .connected: return .green
    case .connecting, .disconnecting: return .orange
    case .failed: return .red
    case .disconnected, .unknown: return .secondary
    }
}

private func shadowrocketTint(_ state: ShadowrocketConnectionState) -> Color {
    switch state {
    case .connected: return .green
    case .connecting, .disconnecting: return .orange
    case .unavailable, .disconnected, .unknown: return .secondary
    }
}

private extension String {
    var nilIfBlank: String? {
        let trimmed = trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}
