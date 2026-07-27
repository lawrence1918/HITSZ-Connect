// Package secureconfig stores HITSZ Connect connection profiles in encrypted
// files. The data encryption key for each profile is kept separately in the
// macOS Keychain; the encrypted file therefore never contains a credential or
// key in plaintext.
package secureconfig

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mythologyli/zju-connect/configs"
)

const (
	// EnvelopeMagic identifies a HITSZ Connect encrypted configuration file.
	EnvelopeMagic = "hitsz-connect-config"
	// EnvelopeVersion is the on-disk encrypted configuration format version.
	EnvelopeVersion = 1
	// KeychainService is the generic-password service used for per-profile DEKs.
	KeychainService = "com.heheyizhi.hitsz-connect.config-key.v1"

	configFileExtension = ".hcenc"
	keyLength           = 32
	nonceLength         = 12
	maxEnvelopeBytes    = 16 << 20
)

var (
	// ErrUnsupportedPlatform is returned when the platform does not provide the
	// macOS Keychain implementation required by NewDefaultStore.
	ErrUnsupportedPlatform = errors.New("secureconfig: macOS Keychain is not available on this platform")
	// ErrKeyNotFound indicates that the Keychain item for an encrypted profile
	// is unavailable. A replacement key must not be generated for an existing
	// encrypted file, because it would make the data permanently unreadable.
	ErrKeyNotFound = errors.New("secureconfig: encryption key not found")
	// ErrNotFound indicates that no encrypted profile exists for an ID.
	ErrNotFound = errors.New("secureconfig: connection not found")
	// ErrInvalidID indicates an ID that is not a canonical UUID.
	ErrInvalidID = errors.New("secureconfig: invalid connection ID")
	// ErrInvalidName indicates a missing or malformed display name.
	ErrInvalidName = errors.New("secureconfig: invalid connection name")
	// ErrInvalidEnvelope indicates a malformed, unsupported, or modified
	// encrypted configuration file.
	ErrInvalidEnvelope = errors.New("secureconfig: invalid encrypted configuration envelope")
	// ErrInsecurePermissions indicates a configuration file exposed to a group
	// or other users. The caller should repair it before trying again.
	ErrInsecurePermissions = errors.New("secureconfig: insecure configuration permissions")
)

// Envelope is the portable encrypted file format. Nonce and Ciphertext are
// standard Base64 strings. Ciphertext is exactly the byte sequence produced by
// cipher.AEAD.Seal: encrypted bytes followed by the 16-byte GCM tag.
//
// Swift/CryptoKit compatibility:
//   - nonce is a 12-byte AES.GCM.Nonce
//   - ciphertext is sealedBox.ciphertext followed by sealedBox.tag
//   - AAD is AssociatedDataForID(envelope.id)
type Envelope struct {
	Magic      string `json:"magic"`
	Version    int    `json:"version"`
	ID         string `json:"id"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// StoredConnection is the plaintext JSON encrypted inside an Envelope. It is
// deliberately a self-contained representation: Config contains every
// persistent runtime setting and ClientData contains the aTrust persisted
// session state. One-time credentials and external session/resource source
// paths are deliberately excluded. JSON field names are camelCase so the
// native macOS app can use the same format without a Go-specific decoder.
type StoredConnection struct {
	ID         string       `json:"id"`
	Name       string       `json:"name"`
	Config     StoredConfig `json:"config"`
	ClientData []byte       `json:"clientData,omitempty"`
	CreatedAt  time.Time    `json:"createdAt"`
	UpdatedAt  time.Time    `json:"updatedAt"`
}

// StoredConfig is the camelCase, serializable equivalent of the persistent
// portion of configs.Config. It intentionally does not retain one-time MFA
// codes, SSO/OAuth tickets, external resource/session source paths, or raw
// aTrust debug-session fields. The encrypted ClientData field on
// StoredConnection is the only persisted aTrust session state.
//
// Keep this type in sync with configs.Config; the conversion helpers below are
// intentionally explicit so adding a config field cannot silently omit a
// persistent setting from encrypted profiles.
type StoredConfig struct {
	Protocol            string                 `json:"protocol"`
	ServerAddress       string                 `json:"serverAddress"`
	ServerPort          int                    `json:"serverPort"`
	Username            string                 `json:"username"`
	Password            string                 `json:"password"`
	SocksBind           string                 `json:"socksBind"`
	SocksUser           string                 `json:"socksUser"`
	SocksPasswd         string                 `json:"socksPasswd"`
	HTTPBind            string                 `json:"httpBind"`
	PortForwardingList  []StoredPortForwarding `json:"portForwardingList,omitempty"`
	ShadowsocksURL      string                 `json:"shadowsocksURL"`
	DialDirectProxy     string                 `json:"dialDirectProxy"`
	DisableZJUConfig    bool                   `json:"disableZJUConfig"`
	DisableRemoteDNS    bool                   `json:"disableRemoteDNS"`
	DNSTTL              uint64                 `json:"dnsTTL"`
	RemoteDNSServer     string                 `json:"remoteDNSServer"`
	SecondaryDNSServer  string                 `json:"secondaryDNSServer"`
	DNSServerBind       string                 `json:"dnsServerBind"`
	CustomDNSList       []StoredCustomDNS      `json:"customDNSList,omitempty"`
	DisableKeepAlive    bool                   `json:"disableKeepAlive"`
	KeepAliveURL        string                 `json:"keepAliveURL"`
	TCPTunnelMode       bool                   `json:"tcpTunnelMode"`
	TUNMode             bool                   `json:"tunMode"`
	AddRoute            bool                   `json:"addRoute"`
	DNSHijack           bool                   `json:"dnsHijack"`
	FakeIP              bool                   `json:"fakeIP"`
	GraphCodeFile       string                 `json:"graphCodeFile,omitempty"`
	DebugDump           bool                   `json:"debugDump"`
	BindInterface       string                 `json:"bindInterface"`
	AutoDetectInterface bool                   `json:"autoDetectInterface"`
	Profile             string                 `json:"profile"`
	NoSystemDNSMutation bool                   `json:"noSystemDNSMutation"`

	MFAMethod                    string `json:"mfaMethod"`
	MFACode                      string `json:"mfaCode,omitempty"`
	MFAOTPSecret                 string `json:"mfaOTPSecret"`
	MFAOTPSecretFile             string `json:"mfaOTPSecretFile,omitempty"`
	NonInteractive               bool   `json:"nonInteractive"`
	RememberSSO                  bool   `json:"rememberSSO"`
	RememberMFA                  bool   `json:"rememberMFA"`
	DNSRelayBind                 string `json:"dnsRelayBind"`
	HITSZDNSServer               string `json:"hitszDNSServer"`
	Shadowrocket                 string `json:"shadowrocket"`
	ShadowrocketUpdateSubs       bool   `json:"shadowrocketUpdateSubs"`
	ShadowrocketAddNodeFile      string `json:"shadowrocketAddNodeFile,omitempty"`
	ShadowrocketDisconnectOnExit bool   `json:"shadowrocketDisconnectOnExit"`
	ShadowrocketConfigFragment   string `json:"shadowrocketConfigFragment"`

	TOTPSecret          string   `json:"totpSecret"`
	CertFile            string   `json:"certFile"`
	CertPassword        string   `json:"certPassword"`
	DisableServerConfig bool     `json:"disableServerConfig"`
	SkipDomainResource  bool     `json:"skipDomainResource"`
	DisableMultiLine    bool     `json:"disableMultiLine"`
	ProxyAll            bool     `json:"proxyAll"`
	CustomProxyDomain   []string `json:"customProxyDomain,omitempty"`
	TwfID               string   `json:"twfID"`

	AuthType                string `json:"authType"`
	Phone                   string `json:"phone"`
	LoginDomain             string `json:"loginDomain"`
	ClientDataFile          string `json:"clientDataFile,omitempty"`
	CasTicket               string `json:"casTicket,omitempty"`
	OAuth2Code              string `json:"oauth2Code,omitempty"`
	SID                     string `json:"sid,omitempty"`
	DeviceID                string `json:"deviceID,omitempty"`
	SignKey                 string `json:"signKey,omitempty"`
	ResourceFile            string `json:"resourceFile,omitempty"`
	UpdateBestNodesInterval int    `json:"updateBestNodesInterval"`
	SkipTCPTunnelWait       bool   `json:"skipTCPTunnelWait"`
}

// StoredPortForwarding is the serializable equivalent of
// configs.SinglePortForwarding.
type StoredPortForwarding struct {
	NetworkType   string `json:"networkType"`
	BindAddress   string `json:"bindAddress"`
	RemoteAddress string `json:"remoteAddress"`
}

// StoredCustomDNS is the serializable equivalent of configs.SingleCustomDNS.
type StoredCustomDNS struct {
	HostName string `json:"hostName"`
	IP       string `json:"ip"`
}

// StoredConfigFromConfig converts all fields in a runtime config into the
// portable encrypted-profile representation.
func StoredConfigFromConfig(config configs.Config) StoredConfig {
	stored := StoredConfig{
		Protocol:                     config.Protocol,
		ServerAddress:                config.ServerAddress,
		ServerPort:                   config.ServerPort,
		Username:                     config.Username,
		Password:                     config.Password,
		SocksBind:                    config.SocksBind,
		SocksUser:                    config.SocksUser,
		SocksPasswd:                  config.SocksPasswd,
		HTTPBind:                     config.HTTPBind,
		ShadowsocksURL:               config.ShadowsocksURL,
		DialDirectProxy:              config.DialDirectProxy,
		DisableZJUConfig:             config.DisableZJUConfig,
		DisableRemoteDNS:             config.DisableRemoteDNS,
		DNSTTL:                       config.DNSTTL,
		RemoteDNSServer:              config.RemoteDNSServer,
		SecondaryDNSServer:           config.SecondaryDNSServer,
		DNSServerBind:                config.DNSServerBind,
		DisableKeepAlive:             config.DisableKeepAlive,
		KeepAliveURL:                 config.KeepAliveURL,
		TCPTunnelMode:                config.TCPTunnelMode,
		TUNMode:                      config.TUNMode,
		AddRoute:                     config.AddRoute,
		DNSHijack:                    config.DNSHijack,
		FakeIP:                       config.FakeIP,
		DebugDump:                    config.DebugDump,
		BindInterface:                config.BindInterface,
		AutoDetectInterface:          config.AutoDetectInterface,
		Profile:                      config.Profile,
		NoSystemDNSMutation:          config.NoSystemDNSMutation,
		MFAMethod:                    config.MFAMethod,
		MFAOTPSecret:                 config.MFAOTPSecret,
		NonInteractive:               config.NonInteractive,
		RememberSSO:                  config.RememberSSO,
		RememberMFA:                  config.RememberMFA,
		DNSRelayBind:                 config.DNSRelayBind,
		HITSZDNSServer:               config.HITSZDNSServer,
		Shadowrocket:                 config.Shadowrocket,
		ShadowrocketUpdateSubs:       config.ShadowrocketUpdateSubs,
		ShadowrocketDisconnectOnExit: config.ShadowrocketDisconnectOnExit,
		ShadowrocketConfigFragment:   config.ShadowrocketConfigFragment,
		TOTPSecret:                   config.TOTPSecret,
		CertFile:                     config.CertFile,
		CertPassword:                 config.CertPassword,
		DisableServerConfig:          config.DisableServerConfig,
		SkipDomainResource:           config.SkipDomainResource,
		DisableMultiLine:             config.DisableMultiLine,
		ProxyAll:                     config.ProxyAll,
		TwfID:                        config.TwfID,
		AuthType:                     config.AuthType,
		Phone:                        config.Phone,
		LoginDomain:                  config.LoginDomain,
		UpdateBestNodesInterval:      config.UpdateBestNodesInterval,
		SkipTCPTunnelWait:            config.SkipTCPTunnelWait,
	}

	if len(config.PortForwardingList) > 0 {
		stored.PortForwardingList = make([]StoredPortForwarding, len(config.PortForwardingList))
		for index, forwarding := range config.PortForwardingList {
			stored.PortForwardingList[index] = StoredPortForwarding{
				NetworkType:   forwarding.NetworkType,
				BindAddress:   forwarding.BindAddress,
				RemoteAddress: forwarding.RemoteAddress,
			}
		}
	}
	if len(config.CustomDNSList) > 0 {
		stored.CustomDNSList = make([]StoredCustomDNS, len(config.CustomDNSList))
		for index, entry := range config.CustomDNSList {
			stored.CustomDNSList[index] = StoredCustomDNS{HostName: entry.HostName, IP: entry.IP}
		}
	}
	stored.CustomProxyDomain = cloneStrings(config.CustomProxyDomain)
	return sanitizeStoredConfig(stored)
}

// ConfigFromStored converts a serialized config back into the runtime config
// used by the existing zju-connect client.
func ConfigFromStored(stored StoredConfig) configs.Config {
	return stored.ToConfig()
}

// ToConfig converts a serialized config back into the runtime config used by
// the existing zju-connect client.
func (stored StoredConfig) ToConfig() configs.Config {
	stored = sanitizeStoredConfig(stored)
	config := configs.Config{
		Protocol:                     stored.Protocol,
		ServerAddress:                stored.ServerAddress,
		ServerPort:                   stored.ServerPort,
		Username:                     stored.Username,
		Password:                     stored.Password,
		SocksBind:                    stored.SocksBind,
		SocksUser:                    stored.SocksUser,
		SocksPasswd:                  stored.SocksPasswd,
		HTTPBind:                     stored.HTTPBind,
		ShadowsocksURL:               stored.ShadowsocksURL,
		DialDirectProxy:              stored.DialDirectProxy,
		DisableZJUConfig:             stored.DisableZJUConfig,
		DisableRemoteDNS:             stored.DisableRemoteDNS,
		DNSTTL:                       stored.DNSTTL,
		RemoteDNSServer:              stored.RemoteDNSServer,
		SecondaryDNSServer:           stored.SecondaryDNSServer,
		DNSServerBind:                stored.DNSServerBind,
		DisableKeepAlive:             stored.DisableKeepAlive,
		KeepAliveURL:                 stored.KeepAliveURL,
		TCPTunnelMode:                stored.TCPTunnelMode,
		TUNMode:                      stored.TUNMode,
		AddRoute:                     stored.AddRoute,
		DNSHijack:                    stored.DNSHijack,
		FakeIP:                       stored.FakeIP,
		DebugDump:                    stored.DebugDump,
		BindInterface:                stored.BindInterface,
		AutoDetectInterface:          stored.AutoDetectInterface,
		Profile:                      stored.Profile,
		NoSystemDNSMutation:          stored.NoSystemDNSMutation,
		MFAMethod:                    stored.MFAMethod,
		MFAOTPSecret:                 stored.MFAOTPSecret,
		NonInteractive:               stored.NonInteractive,
		RememberSSO:                  stored.RememberSSO,
		RememberMFA:                  stored.RememberMFA,
		DNSRelayBind:                 stored.DNSRelayBind,
		HITSZDNSServer:               stored.HITSZDNSServer,
		Shadowrocket:                 stored.Shadowrocket,
		ShadowrocketUpdateSubs:       stored.ShadowrocketUpdateSubs,
		ShadowrocketDisconnectOnExit: stored.ShadowrocketDisconnectOnExit,
		ShadowrocketConfigFragment:   stored.ShadowrocketConfigFragment,
		TOTPSecret:                   stored.TOTPSecret,
		CertFile:                     stored.CertFile,
		CertPassword:                 stored.CertPassword,
		DisableServerConfig:          stored.DisableServerConfig,
		SkipDomainResource:           stored.SkipDomainResource,
		DisableMultiLine:             stored.DisableMultiLine,
		ProxyAll:                     stored.ProxyAll,
		CustomProxyDomain:            cloneStrings(stored.CustomProxyDomain),
		TwfID:                        stored.TwfID,
		AuthType:                     stored.AuthType,
		Phone:                        stored.Phone,
		LoginDomain:                  stored.LoginDomain,
		UpdateBestNodesInterval:      stored.UpdateBestNodesInterval,
		SkipTCPTunnelWait:            stored.SkipTCPTunnelWait,
	}

	if len(stored.PortForwardingList) > 0 {
		config.PortForwardingList = make([]configs.SinglePortForwarding, len(stored.PortForwardingList))
		for index, forwarding := range stored.PortForwardingList {
			config.PortForwardingList[index] = configs.SinglePortForwarding{
				NetworkType:   forwarding.NetworkType,
				BindAddress:   forwarding.BindAddress,
				RemoteAddress: forwarding.RemoteAddress,
			}
		}
	}
	if len(stored.CustomDNSList) > 0 {
		config.CustomDNSList = make([]configs.SingleCustomDNS, len(stored.CustomDNSList))
		for index, entry := range stored.CustomDNSList {
			config.CustomDNSList[index] = configs.SingleCustomDNS{HostName: entry.HostName, IP: entry.IP}
		}
	}
	return config
}

// NewStoredConnection prepares a connection for Store.Save. Save assigns its
// UUID and timestamps, then encrypts it. ClientData is copied so later caller
// mutations cannot affect the returned value.
func NewStoredConnection(name string, config configs.Config, clientData []byte) StoredConnection {
	return StoredConnection{
		Name:       name,
		Config:     StoredConfigFromConfig(config),
		ClientData: cloneBytes(clientData),
	}
}

// StoredConnectionFromConfig is the explicit Config-to-StoredConnection
// mapping helper. It is equivalent to NewStoredConnection.
func StoredConnectionFromConfig(name string, config configs.Config, clientData []byte) StoredConnection {
	return NewStoredConnection(name, config, clientData)
}

// ToConfig returns a detached runtime config represented by a stored
// connection.
func (connection StoredConnection) ToConfig() configs.Config {
	return connection.Config.ToConfig()
}

// ClientDataCopy returns a detached copy of the persisted aTrust client data.
func (connection StoredConnection) ClientDataCopy() []byte {
	return cloneBytes(connection.ClientData)
}

// AssociatedDataForID returns the exact UTF-8 additional authenticated data
// used for an Envelope. It is exported so the Swift application can use the
// same AES-GCM serialization convention.
func AssociatedDataForID(id string) []byte {
	return []byte("com.heheyizhi.hitsz-connect.config.v1:" + id)
}

// KeyProvider stores per-connection data encryption keys. Implementations must
// make defensive copies of keys. The production provider is macOS Keychain;
// MemoryKeyProvider is available for tests and is intentionally not persisted.
type KeyProvider interface {
	Get(id string) ([]byte, error)
	Set(id string, key []byte) error
	Delete(id string) error
}

// Store manages encrypted .hcenc profiles in one directory.
type Store struct {
	dir    string
	keys   KeyProvider
	random io.Reader
	now    func() time.Time
	mu     sync.Mutex
}

// DefaultDir returns the only default profile location:
// ~/Documents/hitsz-connect. It does not use the current working directory.
func DefaultDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("secureconfig: determine home directory: %w", err)
	}
	return filepath.Join(home, "Documents", "hitsz-connect"), nil
}

// NewDefaultStore opens the default directory with the macOS Keychain key
// provider. On non-macOS platforms it returns ErrUnsupportedPlatform.
func NewDefaultStore() (*Store, error) {
	dir, err := DefaultDir()
	if err != nil {
		return nil, err
	}
	keys, err := NewKeychainProvider()
	if err != nil {
		return nil, err
	}
	return NewStore(dir, keys)
}

// NewStore opens an encrypted profile directory. A custom KeyProvider allows
// tests and controlled integrations to use another secure key backend. The
// directory itself is created with mode 0700 if necessary.
func NewStore(dir string, keys KeyProvider) (*Store, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("secureconfig: profile directory is empty")
	}
	if keys == nil {
		return nil, errors.New("secureconfig: key provider is nil")
	}

	store := &Store{
		dir:    filepath.Clean(dir),
		keys:   keys,
		random: rand.Reader,
		now:    time.Now,
	}
	if err := store.ensureDirectory(); err != nil {
		return nil, err
	}
	return store, nil
}

// Dir returns the profile directory used by this Store.
func (store *Store) Dir() string {
	return store.dir
}

// Create creates a new per-profile random 32-byte DEK, stores it in the key
// provider, and atomically persists an encrypted connection file.
func (store *Store) Create(name string, config configs.Config, clientData []byte) (StoredConnection, error) {
	return store.Save(NewStoredConnection(name, config, clientData))
}

// Save creates a profile when connection.ID is empty, or atomically updates an
// existing profile when it names an existing UUID. Updating never generates a
// replacement key; a missing existing key returns ErrKeyNotFound instead.
func (store *Store) Save(connection StoredConnection) (StoredConnection, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.saveLocked(connection)
}

func (store *Store) saveLocked(connection StoredConnection) (StoredConnection, error) {
	if err := store.ensureDirectory(); err != nil {
		return StoredConnection{}, err
	}
	if err := validateName(connection.Name); err != nil {
		return StoredConnection{}, err
	}
	// Save is an enforcement boundary as callers may construct
	// StoredConnection directly instead of using NewStoredConnection.
	connection.Config = sanitizeStoredConfig(connection.Config)

	if connection.ID == "" {
		id, err := newUUID(store.random)
		if err != nil {
			return StoredConnection{}, err
		}
		connection.ID = id
	} else if err := validateID(connection.ID); err != nil {
		return StoredConnection{}, err
	}

	path := store.pathForID(connection.ID)
	_, statErr := os.Lstat(path)
	exists := statErr == nil
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return StoredConnection{}, fmt.Errorf("secureconfig: inspect profile: %w", statErr)
	}

	var (
		key        []byte
		newKey     bool
		previous   StoredConnection
		previousOK bool
	)
	if exists {
		var err error
		previous, err = store.loadLocked(connection.ID)
		if err != nil {
			return StoredConnection{}, err
		}
		previousOK = true
		key, err = store.keys.Get(connection.ID)
		if err != nil {
			return StoredConnection{}, wrapKeyError("load", err)
		}
		if err := validateKey(key); err != nil {
			return StoredConnection{}, err
		}
	} else {
		var err error
		key, err = randomBytes(store.random, keyLength)
		if err != nil {
			return StoredConnection{}, err
		}
		defer zeroBytes(key)
		if err := store.keys.Set(connection.ID, key); err != nil {
			return StoredConnection{}, wrapKeyError("store", err)
		}
		newKey = true
	}
	if !newKey {
		defer zeroBytes(key)
	}

	now := store.now().UTC()
	if connection.CreatedAt.IsZero() {
		if previousOK && !previous.CreatedAt.IsZero() {
			connection.CreatedAt = previous.CreatedAt
		} else {
			connection.CreatedAt = now
		}
	}
	connection.UpdatedAt = now
	connection.ClientData = cloneBytes(connection.ClientData)

	envelope, err := encryptConnection(connection, key, store.random)
	if err != nil {
		return StoredConnection{}, err
	}
	if err := store.writeEnvelope(path, envelope); err != nil {
		if newKey {
			_ = store.keys.Delete(connection.ID)
		}
		return StoredConnection{}, err
	}
	return cloneConnection(connection), nil
}

// Load decrypts one profile by ID.
func (store *Store) Load(id string) (StoredConnection, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.loadLocked(id)
}

func (store *Store) loadLocked(id string) (StoredConnection, error) {
	if err := validateID(id); err != nil {
		return StoredConnection{}, err
	}
	if err := store.ensureDirectory(); err != nil {
		return StoredConnection{}, err
	}

	path := store.pathForID(id)
	data, err := readSecureFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return StoredConnection{}, fmt.Errorf("%w: %s", ErrNotFound, id)
		}
		return StoredConnection{}, err
	}

	var envelope Envelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return StoredConnection{}, fmt.Errorf("%w: parse JSON", ErrInvalidEnvelope)
	}
	if err := validateEnvelope(envelope, id); err != nil {
		return StoredConnection{}, err
	}

	key, err := store.keys.Get(id)
	if err != nil {
		return StoredConnection{}, wrapKeyError("load", err)
	}
	defer zeroBytes(key)
	if err := validateKey(key); err != nil {
		return StoredConnection{}, err
	}

	connection, err := decryptConnection(envelope, key)
	if err != nil {
		return StoredConnection{}, err
	}
	if connection.ID != id {
		return StoredConnection{}, fmt.Errorf("%w: plaintext ID mismatch", ErrInvalidEnvelope)
	}
	if err := validateName(connection.Name); err != nil {
		return StoredConnection{}, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	// Do not surface or later re-persist transient values from an old or
	// externally-written envelope.
	connection.Config = sanitizeStoredConfig(connection.Config)
	return cloneConnection(connection), nil
}

// List loads every encrypted profile in the store. A corrupt profile or missing
// Keychain item is returned as an error rather than being silently skipped.
func (store *Store) List() ([]StoredConnection, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ensureDirectory(); err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(store.dir)
	if err != nil {
		return nil, fmt.Errorf("secureconfig: read profile directory: %w", err)
	}
	connections := make([]StoredConnection, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), configFileExtension) {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), configFileExtension)
		if validateID(id) != nil {
			continue
		}
		connection, err := store.loadLocked(id)
		if err != nil {
			return nil, err
		}
		connections = append(connections, connection)
	}
	sort.Slice(connections, func(left, right int) bool {
		if connections[left].UpdatedAt.Equal(connections[right].UpdatedAt) {
			return connections[left].Name < connections[right].Name
		}
		return connections[left].UpdatedAt.After(connections[right].UpdatedAt)
	})
	return connections, nil
}

// Delete removes the encrypted file and then its Keychain key. A Keychain key
// that was already removed is treated as success because the profile data is no
// longer recoverable from this Store.
func (store *Store) Delete(id string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := validateID(id); err != nil {
		return err
	}
	if err := store.ensureDirectory(); err != nil {
		return err
	}

	path := store.pathForID(id)
	if err := checkRegularSecureFile(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: %s", ErrNotFound, id)
		}
		return err
	}
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: %s", ErrNotFound, id)
		}
		return fmt.Errorf("secureconfig: delete encrypted profile: %w", err)
	}
	if err := syncDirectory(store.dir); err != nil {
		return err
	}
	if err := store.keys.Delete(id); err != nil && !errors.Is(err, ErrKeyNotFound) {
		return wrapKeyError("delete", err)
	}
	return nil
}

func (store *Store) ensureDirectory() error {
	info, err := os.Lstat(store.dir)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(store.dir, 0o700); err != nil {
			return fmt.Errorf("secureconfig: create profile directory: %w", err)
		}
		info, err = os.Lstat(store.dir)
	}
	if err != nil {
		return fmt.Errorf("secureconfig: inspect profile directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("secureconfig: profile directory is not a real directory")
	}
	if err := os.Chmod(store.dir, 0o700); err != nil {
		return fmt.Errorf("secureconfig: set profile directory permissions: %w", err)
	}
	return nil
}

func (store *Store) pathForID(id string) string {
	return filepath.Join(store.dir, id+configFileExtension)
}

func (store *Store) writeEnvelope(path string, envelope Envelope) error {
	data, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("secureconfig: encode encrypted profile: %w", err)
	}

	temporary, err := os.CreateTemp(store.dir, ".secureconfig-*.tmp")
	if err != nil {
		return fmt.Errorf("secureconfig: create temporary profile: %w", err)
	}
	temporaryPath := temporary.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(temporaryPath)
		}
	}()

	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("secureconfig: set temporary profile permissions: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("secureconfig: write encrypted profile: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("secureconfig: sync encrypted profile: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("secureconfig: close encrypted profile: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("secureconfig: atomically replace encrypted profile: %w", err)
	}
	cleanup = false
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("secureconfig: set encrypted profile permissions: %w", err)
	}
	return syncDirectory(store.dir)
}

func encryptConnection(connection StoredConnection, key []byte, random io.Reader) (Envelope, error) {
	plaintext, err := json.Marshal(connection)
	if err != nil {
		return Envelope{}, fmt.Errorf("secureconfig: encode connection: %w", err)
	}
	defer zeroBytes(plaintext)
	block, err := aes.NewCipher(key)
	if err != nil {
		return Envelope{}, fmt.Errorf("secureconfig: initialize AES-256: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Envelope{}, fmt.Errorf("secureconfig: initialize AES-GCM: %w", err)
	}
	if gcm.NonceSize() != nonceLength {
		return Envelope{}, errors.New("secureconfig: unsupported AES-GCM nonce size")
	}
	nonce, err := randomBytes(random, gcm.NonceSize())
	if err != nil {
		return Envelope{}, err
	}
	defer zeroBytes(nonce)
	ciphertext := gcm.Seal(nil, nonce, plaintext, AssociatedDataForID(connection.ID))
	return Envelope{
		Magic:      EnvelopeMagic,
		Version:    EnvelopeVersion,
		ID:         connection.ID,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}

func decryptConnection(envelope Envelope, key []byte) (StoredConnection, error) {
	nonce, err := base64.StdEncoding.DecodeString(envelope.Nonce)
	if err != nil || len(nonce) != nonceLength {
		return StoredConnection{}, fmt.Errorf("%w: nonce", ErrInvalidEnvelope)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil || len(ciphertext) < 16 {
		return StoredConnection{}, fmt.Errorf("%w: ciphertext", ErrInvalidEnvelope)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return StoredConnection{}, fmt.Errorf("secureconfig: initialize AES-256: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return StoredConnection{}, fmt.Errorf("secureconfig: initialize AES-GCM: %w", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, AssociatedDataForID(envelope.ID))
	if err != nil {
		return StoredConnection{}, fmt.Errorf("%w: authentication failed", ErrInvalidEnvelope)
	}
	defer zeroBytes(plaintext)
	var connection StoredConnection
	if err := json.Unmarshal(plaintext, &connection); err != nil {
		return StoredConnection{}, fmt.Errorf("%w: plaintext JSON", ErrInvalidEnvelope)
	}
	return connection, nil
}

func validateEnvelope(envelope Envelope, expectedID string) error {
	if envelope.Magic != EnvelopeMagic || envelope.Version != EnvelopeVersion || envelope.ID != expectedID {
		return ErrInvalidEnvelope
	}
	if err := validateID(envelope.ID); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	return nil
}

func readSecureFile(path string) ([]byte, error) {
	if err := checkRegularSecureFile(path); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("secureconfig: open encrypted profile: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxEnvelopeBytes+1))
	if err != nil {
		return nil, fmt.Errorf("secureconfig: read encrypted profile: %w", err)
	}
	if len(data) > maxEnvelopeBytes {
		return nil, fmt.Errorf("%w: file too large", ErrInvalidEnvelope)
	}
	return data, nil
}

func checkRegularSecureFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("%w: not a regular file", ErrInvalidEnvelope)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return ErrInsecurePermissions
	}
	return nil
}

func syncDirectory(dir string) error {
	directory, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("secureconfig: open profile directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("secureconfig: sync profile directory: %w", err)
	}
	return nil
}

func randomBytes(random io.Reader, length int) ([]byte, error) {
	bytes := make([]byte, length)
	if _, err := io.ReadFull(random, bytes); err != nil {
		zeroBytes(bytes)
		return nil, fmt.Errorf("secureconfig: obtain random bytes: %w", err)
	}
	return bytes, nil
}

func newUUID(random io.Reader) (string, error) {
	bytes, err := randomBytes(random, 16)
	if err != nil {
		return "", err
	}
	defer zeroBytes(bytes)
	bytes[6] = (bytes[6] & 0x0f) | 0x40
	bytes[8] = (bytes[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		bytes[0:4], bytes[4:6], bytes[6:8], bytes[8:10], bytes[10:16]), nil
}

func validateID(id string) error {
	if len(id) != 36 {
		return ErrInvalidID
	}
	for index, character := range id {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if character != '-' {
				return ErrInvalidID
			}
			continue
		}
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return ErrInvalidID
		}
	}
	return nil
}

func validateName(name string) error {
	if strings.TrimSpace(name) == "" || strings.IndexByte(name, 0) >= 0 {
		return ErrInvalidName
	}
	return nil
}

func validateKey(key []byte) error {
	if len(key) != keyLength {
		return errors.New("secureconfig: key provider returned a key with invalid length")
	}
	return nil
}

func wrapKeyError(operation string, err error) error {
	if errors.Is(err, ErrKeyNotFound) {
		return ErrKeyNotFound
	}
	return fmt.Errorf("secureconfig: Keychain %s failed: %w", operation, err)
}

func cloneConnection(connection StoredConnection) StoredConnection {
	connection.ClientData = cloneBytes(connection.ClientData)
	connection.Config.PortForwardingList = append([]StoredPortForwarding(nil), connection.Config.PortForwardingList...)
	connection.Config.CustomDNSList = append([]StoredCustomDNS(nil), connection.Config.CustomDNSList...)
	connection.Config.CustomProxyDomain = cloneStrings(connection.Config.CustomProxyDomain)
	return connection
}

// sanitizeStoredConfig removes values that must be supplied only for the
// current connection attempt. In particular, aTrust client data is embedded in
// StoredConnection.ClientData instead of retaining a plaintext source path.
func sanitizeStoredConfig(config StoredConfig) StoredConfig {
	config.GraphCodeFile = ""
	config.MFACode = ""
	config.MFAOTPSecretFile = ""
	config.ShadowrocketAddNodeFile = ""
	config.ClientDataFile = ""
	config.CasTicket = ""
	config.OAuth2Code = ""
	config.SID = ""
	config.DeviceID = ""
	config.SignKey = ""
	config.ResourceFile = ""
	return config
}

func cloneBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	copyValue := make([]byte, len(value))
	copy(copyValue, value)
	return copyValue
}

func cloneStrings(value []string) []string {
	if value == nil {
		return nil
	}
	return append([]string(nil), value...)
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
