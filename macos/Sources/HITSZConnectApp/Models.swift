import Foundation

/// The plaintext held inside an encrypted `.hcenc` profile.  Its JSON layout
/// is intentionally shared with the CLI secure-config implementation.
struct SecureProfilePayload: Codable, Identifiable, Equatable {
    var id: String
    var name: String
    var config: BridgeConnectionConfig
    var clientData: String?
    var createdAt: String
    var updatedAt: String

    static func newDefault() -> SecureProfilePayload {
        let now = Date.iso8601UTCString
        return SecureProfilePayload(
            id: UUID().uuidString.lowercased(),
            name: "我的 HITSZ 连接",
            config: BridgeConnectionConfig(),
            clientData: nil,
            createdAt: now,
            updatedAt: now
        )
    }

    mutating func touch() {
        updatedAt = Date.iso8601UTCString
    }
}

/// A Codable JSON value that permits an encrypted profile to retain fields
/// added by newer CLI releases.  Decoding a profile into a narrowly typed
/// Swift struct and saving it again would otherwise silently discard startup
/// options the GUI does not currently expose.
indirect enum JSONValue: Codable, Equatable {
    case null
    case bool(Bool)
    case string(String)
    case int(Int64)
    case uint(UInt64)
    case double(Double)
    case array([JSONValue])
    case object([String: JSONValue])

    init(from decoder: Decoder) throws {
        let single = try decoder.singleValueContainer()
        if single.decodeNil() {
            self = .null
        } else if let value = try? single.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? single.decode(Int64.self) {
            self = .int(value)
        } else if let value = try? single.decode(UInt64.self) {
            self = .uint(value)
        } else if let value = try? single.decode(Double.self) {
            self = .double(value)
        } else if let value = try? single.decode(String.self) {
            self = .string(value)
        } else if var values = try? decoder.unkeyedContainer() {
            var array: [JSONValue] = []
            while !values.isAtEnd {
                array.append(try values.decode(JSONValue.self))
            }
            self = .array(array)
        } else {
            let values = try decoder.container(keyedBy: DynamicCodingKey.self)
            var object: [String: JSONValue] = [:]
            for key in values.allKeys {
                object[key.stringValue] = try values.decode(JSONValue.self, forKey: key)
            }
            self = .object(object)
        }
    }

    func encode(to encoder: Encoder) throws {
        switch self {
        case .null:
            var container = encoder.singleValueContainer()
            try container.encodeNil()
        case let .bool(value):
            var container = encoder.singleValueContainer()
            try container.encode(value)
        case let .string(value):
            var container = encoder.singleValueContainer()
            try container.encode(value)
        case let .int(value):
            var container = encoder.singleValueContainer()
            try container.encode(value)
        case let .uint(value):
            var container = encoder.singleValueContainer()
            try container.encode(value)
        case let .double(value):
            var container = encoder.singleValueContainer()
            try container.encode(value)
        case let .array(values):
            var container = encoder.unkeyedContainer()
            for value in values {
                try container.encode(value)
            }
        case let .object(values):
            var container = encoder.container(keyedBy: DynamicCodingKey.self)
            for key in values.keys.sorted() {
                try container.encode(values[key], forKey: DynamicCodingKey(key))
            }
        }
    }

    var stringValue: String? {
        guard case let .string(value) = self else { return nil }
        return value
    }

    var boolValue: Bool? {
        guard case let .bool(value) = self else { return nil }
        return value
    }

    var intValue: Int? {
        switch self {
        case let .int(value): return Int(exactly: value)
        case let .uint(value): return Int(exactly: value)
        default: return nil
        }
    }
}

private struct DynamicCodingKey: CodingKey, Hashable {
    let stringValue: String
    let intValue: Int?

    init(_ stringValue: String) {
        self.stringValue = stringValue
        intValue = nil
    }

    init?(stringValue: String) {
        self.init(stringValue)
    }

    init?(intValue: Int) {
        stringValue = String(intValue)
        self.intValue = intValue
    }
}

/// A lossless flat representation of `secureconfig.StoredConfig`.  Public
/// computed properties serve the GUI, while the backing map re-emits unknown
/// keys intact when a client-data event updates an existing profile.
struct BridgeConnectionConfig: Codable, Equatable {
    private var values: [String: JSONValue]

    init() {
        values = Self.defaultValues
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: DynamicCodingKey.self)
        var decoded: [String: JSONValue] = [:]
        for key in container.allKeys {
            decoded[key.stringValue] = try container.decode(JSONValue.self, forKey: key)
        }
        values = Self.sanitize(Self.defaultValues.merging(decoded) { _, decodedValue in decodedValue })
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: DynamicCodingKey.self)
        let sanitized = Self.sanitize(values)
        for key in sanitized.keys.sorted() {
            try container.encode(sanitized[key]!, forKey: DynamicCodingKey(key))
        }
    }

    var profile: String {
        get { string("profile", default: "hitsz") }
        set { values["profile"] = .string(newValue) }
    }

    var username: String {
        get { string("username") }
        set { values["username"] = .string(newValue) }
    }

    var password: String {
        get { string("password") }
        set { values["password"] = .string(newValue) }
    }

    var mfaMethod: String {
        get { string("mfaMethod", default: "otp") }
        set { values["mfaMethod"] = .string(newValue) }
    }

    var mfaOTPSecret: String {
        get { string("mfaOTPSecret") }
        set { values["mfaOTPSecret"] = .string(newValue) }
    }

    var shadowrocket: String {
        get { string("shadowrocket", default: "connect") }
        set { values["shadowrocket"] = .string(newValue) }
    }

    var serverAddress: String? {
        get { optionalString("serverAddress") }
        set { setOptionalString(newValue, for: "serverAddress") }
    }

    var serverPort: Int? {
        get { values["serverPort"]?.intValue }
        set {
            if let newValue {
                values["serverPort"] = .int(Int64(newValue))
            } else {
                values.removeValue(forKey: "serverPort")
            }
        }
    }

    var loginDomain: String? {
        get { optionalString("loginDomain") }
        set { setOptionalString(newValue, for: "loginDomain") }
    }

    var authType: String? {
        get { optionalString("authType") }
        set { setOptionalString(newValue, for: "authType") }
    }

    var socksBind: String? {
        get { optionalString("socksBind") }
        set { setOptionalString(newValue, for: "socksBind") }
    }

    var httpBind: String? {
        get { optionalString("httpBind") }
        set { setOptionalString(newValue, for: "httpBind") }
    }

    var dnsRelayBind: String? {
        get { optionalString("dnsRelayBind") }
        set { setOptionalString(newValue, for: "dnsRelayBind") }
    }

    var hitszDNSServer: String? {
        get { optionalString("hitszDNSServer") }
        set { setOptionalString(newValue, for: "hitszDNSServer") }
    }

    var rememberSSO: Bool {
        get { bool("rememberSSO", default: true) }
        set { values["rememberSSO"] = .bool(newValue) }
    }

    var rememberMFA: Bool {
        get { bool("rememberMFA", default: true) }
        set { values["rememberMFA"] = .bool(newValue) }
    }

    var shadowrocketDisconnectOnExit: Bool {
        get { bool("shadowrocketDisconnectOnExit") }
        set { values["shadowrocketDisconnectOnExit"] = .bool(newValue) }
    }

    var shadowrocketUpdateSubs: Bool {
        get { bool("shadowrocketUpdateSubs") }
        set { values["shadowrocketUpdateSubs"] = .bool(newValue) }
    }

    private func string(_ key: String, default defaultValue: String = "") -> String {
        values[key]?.stringValue ?? defaultValue
    }

    private func optionalString(_ key: String) -> String? {
        values[key]?.stringValue
    }

    private mutating func setOptionalString(_ value: String?, for key: String) {
        if let value {
            values[key] = .string(value)
        } else {
            values.removeValue(forKey: key)
        }
    }

    private func bool(_ key: String, default defaultValue: Bool = false) -> Bool {
        values[key]?.boolValue ?? defaultValue
    }

    private static let runtimeOnlyKeys: Set<String> = [
        "graphCodeFile", "mfaCode", "mfaOTPSecretFile", "shadowrocketAddNodeFile",
        "clientDataFile", "casTicket", "oauth2Code", "sid", "deviceID", "signKey", "resourceFile"
    ]

    private static func sanitize(_ values: [String: JSONValue]) -> [String: JSONValue] {
        values.filter { !runtimeOnlyKeys.contains($0.key) }
    }

    // The defaults cover every safe field in secureconfig.StoredConfig.  The
    // bridge itself rejects/clears runtime-only values such as MFA codes,
    // OAuth/CAS tickets, client/resource file paths, and debug session IDs.
    private static let defaultValues: [String: JSONValue] = [
        "protocol": .string("atrust"),
        "serverAddress": .string("trust.hitsz.edu.cn"),
        "serverPort": .int(443),
        "username": .string(""),
        "password": .string(""),
        "socksBind": .string("127.0.0.1:1080"),
        "socksUser": .string(""),
        "socksPasswd": .string(""),
        "httpBind": .string("127.0.0.1:1081"),
        "portForwardingList": .array([]),
        "shadowsocksURL": .string(""),
        "dialDirectProxy": .string(""),
        "disableZJUConfig": .bool(false),
        "disableRemoteDNS": .bool(false),
        "dnsTTL": .uint(3600),
        "remoteDNSServer": .string("auto"),
        "secondaryDNSServer": .string("114.114.114.114"),
        "dnsServerBind": .string(""),
        "customDNSList": .array([]),
        "disableKeepAlive": .bool(false),
        "keepAliveURL": .string(""),
        "tcpTunnelMode": .bool(false),
        "tunMode": .bool(false),
        "addRoute": .bool(false),
        "dnsHijack": .bool(false),
        "fakeIP": .bool(false),
        "debugDump": .bool(false),
        "bindInterface": .string(""),
        "autoDetectInterface": .bool(false),
        "profile": .string("hitsz"),
        "noSystemDNSMutation": .bool(true),
        "mfaMethod": .string("otp"),
        "mfaOTPSecret": .string(""),
        "nonInteractive": .bool(false),
        "rememberSSO": .bool(true),
        "rememberMFA": .bool(true),
        "dnsRelayBind": .string("127.0.0.1:53535"),
        "hitszDNSServer": .string("10.248.98.30"),
        "shadowrocket": .string("connect"),
        "shadowrocketUpdateSubs": .bool(false),
        "shadowrocketDisconnectOnExit": .bool(false),
        "shadowrocketConfigFragment": .string(""),
        "totpSecret": .string(""),
        "certFile": .string(""),
        "certPassword": .string(""),
        "disableServerConfig": .bool(false),
        "skipDomainResource": .bool(false),
        "disableMultiLine": .bool(false),
        "proxyAll": .bool(true),
        "customProxyDomain": .array([]),
        "twfID": .string(""),
        "authType": .string("auth/hitsz-sso"),
        "phone": .string(""),
        "loginDomain": .string("hitcas"),
        "updateBestNodesInterval": .int(300),
        "skipTCPTunnelWait": .bool(false)
    ]
}

enum ConnectionPhase: String, CaseIterable {
    case disconnected
    case connecting
    case connected
    case disconnecting
    case failed
    case unknown

    init(bridgeValue: String?) {
        switch bridgeValue?.lowercased() {
        case "connected", "ready", "running": self = .connected
        case "connecting", "starting", "startingservices", "authenticating", "waitingformfa": self = .connecting
        case "disconnecting", "stopping": self = .disconnecting
        case "disconnected", "stopped", "idle": self = .disconnected
        case "error", "failed": self = .failed
        default: self = .unknown
        }
    }

    var title: String {
        switch self {
        case .disconnected: return "未连接"
        case .connecting: return "连接中"
        case .connected: return "已连接"
        case .disconnecting: return "断开中"
        case .failed: return "连接失败"
        case .unknown: return "等待状态"
        }
    }

    var systemImage: String {
        switch self {
        case .connected: return "checkmark.circle.fill"
        case .connecting, .disconnecting: return "arrow.triangle.2.circlepath.circle"
        case .failed: return "exclamationmark.triangle.fill"
        case .disconnected, .unknown: return "circle"
        }
    }
}

struct BridgeTraffic: Equatable {
    var connected: Bool
    var rxBytes: Int64
    var txBytes: Int64
    var rxBytesPerSecond: Double
    var txBytesPerSecond: Double

    static let empty = BridgeTraffic(
        connected: false,
        rxBytes: 0,
        txBytes: 0,
        rxBytesPerSecond: 0,
        txBytesPerSecond: 0
    )
}

struct BridgeListeners: Equatable {
    var ready: Bool
    var socks: Bool
    var http: Bool
    var dnsRelay: Bool

    static let empty = BridgeListeners(ready: false, socks: false, http: false, dnsRelay: false)
}

struct MFAPrompt: Identifiable, Equatable {
    let id = UUID()
    let method: String
    let message: String
    let requestId: String?

    var title: String {
        switch method.lowercased() {
        case "sms": return "输入短信验证码"
        case "app": return "输入 App 验证码"
        default: return "输入多因素验证码"
        }
    }
}

struct BridgeCommand: Encodable {
    let type: String
    let requestId: String
    let config: BridgeConnectionConfig?
    let clientData: String?
    let code: String?

    init(
        type: String,
        requestId: String = UUID().uuidString.lowercased(),
        config: BridgeConnectionConfig? = nil,
        clientData: String? = nil,
        code: String? = nil
    ) {
        self.type = type
        self.requestId = requestId
        self.config = config
        self.clientData = clientData
        self.code = code
    }
}

extension Date {
    static var iso8601UTCString: String {
        ISO8601DateFormatter().string(from: Date())
    }
}

extension Int64 {
    var byteCountDescription: String {
        ByteCountFormatter.string(fromByteCount: self, countStyle: .binary)
    }
}

extension Double {
    var transferRateDescription: String {
        ByteCountFormatter.string(fromByteCount: Int64(max(0, self)), countStyle: .binary) + "/s"
    }
}
