import CryptoKit
import Darwin
import Foundation
import Security

enum SecureProfileError: LocalizedError {
    case invalidEnvelope
    case malformedCiphertext
    case missingKey(String)
    case keychain(OSStatus)
    case profileIdentifier

    var errorDescription: String? {
        switch self {
        case .invalidEnvelope:
            return "配置文件不是有效的 HITSZ Connect 加密配置。"
        case .malformedCiphertext:
            return "配置文件中的加密数据不完整。"
        case .missingKey:
            return "此配置文件的密钥不在本机钥匙串中，无法打开。"
        case let .keychain(status):
            let description = SecCopyErrorMessageString(status, nil) as String? ?? "未知错误"
            return "无法访问 macOS 钥匙串：\(description) (\(status))"
        case .profileIdentifier:
            return "配置文件缺少有效的 UUID 标识。"
        }
    }
}

/// On-disk layout shared with the Go secure-config implementation.  Data uses
/// JSON's standard Base64 encoding, not URL-safe Base64.
private struct EncryptedProfileEnvelope: Codable {
    let magic: String
    let version: Int
    let id: String
    let nonce: Data
    let ciphertext: Data
}

private enum ProfileKeychain {
    static let service = "com.heheyizhi.hitsz-connect.config-key.v1"

    static func key(for id: String) throws -> SymmetricKey {
        if let existing = try existingKey(for: id) {
            return existing
        }

        var bytes = [UInt8](repeating: 0, count: 32)
        let randomStatus = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard randomStatus == errSecSuccess else {
            throw SecureProfileError.keychain(randomStatus)
        }
        let keyData = Data(bytes)
        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: id,
            kSecValueData as String: keyData,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any
        ]
        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        if addStatus == errSecSuccess {
            return SymmetricKey(data: keyData)
        }
        // A concurrent save can win between the lookup and insert.  Read its
        // key rather than overwriting it, otherwise old profiles become lost.
        if addStatus == errSecDuplicateItem, let existing = try existingKey(for: id) {
            return existing
        }
        throw SecureProfileError.keychain(addStatus)
    }

    static func existingKey(for id: String) throws -> SymmetricKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: id,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnData as String: true
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, let data = result as? Data else {
            throw SecureProfileError.keychain(status)
        }
        guard data.count == 32 else {
            throw SecureProfileError.invalidEnvelope
        }
        return SymmetricKey(data: data)
    }

    static func removeKey(for id: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: id,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SecureProfileError.keychain(status)
        }
    }
}

private enum ProfileCryptor {
    static let magic = "hitsz-connect-config"
    static let version = 1
    static let aadPrefix = "com.heheyizhi.hitsz-connect.config.v1:"

    static func seal(_ profile: SecureProfilePayload) throws -> Data {
        guard UUID(uuidString: profile.id) != nil else {
            throw SecureProfileError.profileIdentifier
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let plaintext = try encoder.encode(profile)
        let key = try ProfileKeychain.key(for: profile.id)
        let nonce = AES.GCM.Nonce()
        let sealed = try AES.GCM.seal(
            plaintext,
            using: key,
            nonce: nonce,
            authenticating: Data((aadPrefix + profile.id).utf8)
        )

        // Go's gcm.Seal produces ciphertext followed by the 16-byte tag.
        let combinedCiphertext = sealed.ciphertext + sealed.tag
        let envelope = EncryptedProfileEnvelope(
            magic: magic,
            version: version,
            id: profile.id,
            nonce: Data(nonce),
            ciphertext: combinedCiphertext
        )
        return try encoder.encode(envelope)
    }

    static func open(_ data: Data) throws -> SecureProfilePayload {
        let decoder = JSONDecoder()
        let envelope = try decoder.decode(EncryptedProfileEnvelope.self, from: data)
        guard envelope.magic == magic,
              envelope.version == version,
              UUID(uuidString: envelope.id) != nil else {
            throw SecureProfileError.invalidEnvelope
        }
        guard envelope.nonce.count == 12, envelope.ciphertext.count >= 16 else {
            throw SecureProfileError.malformedCiphertext
        }
        guard let key = try ProfileKeychain.existingKey(for: envelope.id) else {
            throw SecureProfileError.missingKey(envelope.id)
        }

        let ciphertext = envelope.ciphertext.dropLast(16)
        let tag = envelope.ciphertext.suffix(16)
        let box = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: envelope.nonce),
            ciphertext: ciphertext,
            tag: tag
        )
        let plaintext = try AES.GCM.open(
            box,
            using: key,
            authenticating: Data((aadPrefix + envelope.id).utf8)
        )
        let profile = try decoder.decode(SecureProfilePayload.self, from: plaintext)
        guard profile.id == envelope.id else {
            throw SecureProfileError.invalidEnvelope
        }
        return profile
    }
}

struct ProfileListing {
    let profiles: [SecureProfilePayload]
    let unreadableFiles: [URL]
}

/// Writes a replacement in the target directory with mode 0600 from creation
/// through rename.  `Data.write(options: .atomic)` creates a file with default
/// permissions before a later chmod; using an exclusive temporary inode avoids
/// that brief exposure and replaces a malicious destination symlink rather
/// than following it.
private enum SecureAtomicFileWriter {
    static func write(_ data: Data, to destination: URL) throws {
        let temporary = destination.deletingLastPathComponent().appendingPathComponent(
            ".\(destination.lastPathComponent).\(UUID().uuidString.lowercased()).tmp"
        )
        var descriptor = open(
            temporary.path,
            O_WRONLY | O_CREAT | O_EXCL,
            S_IRUSR | S_IWUSR
        )
        guard descriptor >= 0 else { throw currentPOSIXError() }

        var shouldRemoveTemporary = true
        defer {
            if descriptor >= 0 { _ = close(descriptor) }
            if shouldRemoveTemporary { _ = unlink(temporary.path) }
        }

        try data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) throws in
            var offset = 0
            while offset < bytes.count {
                guard let address = bytes.baseAddress?.advanced(by: offset) else {
                    throw currentPOSIXError()
                }
                let result = Darwin.write(descriptor, address, bytes.count - offset)
                if result > 0 {
                    offset += result
                } else if result < 0, errno == EINTR {
                    continue
                } else {
                    throw currentPOSIXError()
                }
            }
        }
        guard fsync(descriptor) == 0 else { throw currentPOSIXError() }
        guard close(descriptor) == 0 else { throw currentPOSIXError() }
        descriptor = -1
        guard rename(temporary.path, destination.path) == 0 else { throw currentPOSIXError() }
        shouldRemoveTemporary = false
    }

    private static func currentPOSIXError() -> POSIXError {
        POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
}

/// Owns only encrypted profile files.  The fixed path is deliberately not a
/// cache or application-support location so a user can find and back up the
/// encrypted files at `~/Documents/hitsz-connect`.
final class SecureProfileStore {
    static let shared = SecureProfileStore()

    let directoryURL: URL

    init(fileManager: FileManager = .default) {
        directoryURL = fileManager.homeDirectoryForCurrentUser
            .appendingPathComponent("Documents", isDirectory: true)
            .appendingPathComponent("hitsz-connect", isDirectory: true)
    }

    func ensureDirectory() throws {
        try FileManager.default.createDirectory(
            at: directoryURL,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        // `createDirectory` applies attributes only on initial creation. Keep
        // an existing profile directory private as well, matching the CLI
        // secure-config store's 0700 requirement.
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directoryURL.path)
    }

    func listProfiles() throws -> ProfileListing {
        try ensureDirectory()
        let files = try FileManager.default.contentsOfDirectory(
            at: directoryURL,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles]
        )
        var profiles: [SecureProfilePayload] = []
        var unreadableFiles: [URL] = []
        for file in files where file.pathExtension.lowercased() == "hcenc" {
            do {
                profiles.append(try load(url: file))
            } catch {
                unreadableFiles.append(file)
            }
        }
        return ProfileListing(
            profiles: profiles.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending },
            unreadableFiles: unreadableFiles.sorted { $0.lastPathComponent < $1.lastPathComponent }
        )
    }

    func load(id: String) throws -> SecureProfilePayload {
        try load(url: fileURL(for: id))
    }

    func load(url: URL) throws -> SecureProfilePayload {
        try ProfileCryptor.open(Data(contentsOf: url))
    }

    @discardableResult
    func save(_ draft: SecureProfilePayload) throws -> SecureProfilePayload {
        try ensureDirectory()
        var profile = draft
        if profile.id.isEmpty {
            profile.id = UUID().uuidString.lowercased()
        }
        if profile.createdAt.isEmpty {
            profile.createdAt = Date.iso8601UTCString
        }
        profile.touch()
        let encoded = try ProfileCryptor.seal(profile)
        let url = fileURL(for: profile.id)
        try SecureAtomicFileWriter.write(encoded, to: url)
        return profile
    }

    /// Imports only a profile that can already be authenticated with this
    /// Mac's Keychain key.  The method re-seals rather than blindly copies it,
    /// so the destination gets the standard file permissions.
    @discardableResult
    func importProfile(from sourceURL: URL) throws -> SecureProfilePayload {
        let profile = try load(url: sourceURL)
        return try save(profile)
    }

    func delete(_ profile: SecureProfilePayload) throws {
        let url = fileURL(for: profile.id)
        if FileManager.default.fileExists(atPath: url.path) {
            try FileManager.default.removeItem(at: url)
        }
        try ProfileKeychain.removeKey(for: profile.id)
    }

    func fileURL(for id: String) -> URL {
        directoryURL.appendingPathComponent("\(id.lowercased()).hcenc", isDirectory: false)
    }
}
