package secureconfig

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/mythologyli/zju-connect/configs"
)

func TestStoredConfigRoundTrip(t *testing.T) {
	t.Parallel()
	source := sampleConfig()
	want := expectedPersistedConfig(source)
	stored := StoredConfigFromConfig(source)
	got := stored.ToConfig()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("config conversion lost data\nwant: %#v\n got: %#v", want, got)
	}
	if stored.MFAOTPSecret != source.MFAOTPSecret {
		t.Fatal("encrypted OTP seed must remain persistent")
	}
	if stored.MFACode != "" || stored.MFAOTPSecretFile != "" || stored.ClientDataFile != "" ||
		stored.CasTicket != "" || stored.OAuth2Code != "" || stored.SID != "" ||
		stored.DeviceID != "" || stored.SignKey != "" || stored.ResourceFile != "" ||
		stored.ShadowrocketAddNodeFile != "" || stored.GraphCodeFile != "" {
		t.Fatalf("transient/source values were retained in StoredConfig: %#v", stored)
	}

	encoded, err := json.Marshal(NewStoredConnection("HITSZ", source, []byte(`{"session":"state"}`)))
	if err != nil {
		t.Fatalf("marshal stored connection: %v", err)
	}
	for _, field := range []string{
		`"clientData"`, `"serverAddress"`, `"mfaOTPSecret"`, `"portForwardingList"`,
	} {
		if !bytes.Contains(encoded, []byte(field)) {
			t.Errorf("stored JSON is missing camelCase field %s: %s", field, encoded)
		}
	}
	if bytes.Contains(encoded, []byte(`"ServerAddress"`)) {
		t.Fatalf("stored JSON must not contain Go field names: %s", encoded)
	}
	for _, field := range []string{
		`"mfaCode"`, `"mfaOTPSecretFile"`, `"clientDataFile"`, `"casTicket"`, `"oauth2Code"`,
		`"sid"`, `"deviceID"`, `"signKey"`, `"resourceFile"`, `"shadowrocketAddNodeFile"`, `"graphCodeFile"`,
	} {
		if bytes.Contains(encoded, []byte(field)) {
			t.Errorf("stored JSON must exclude transient/source field %s: %s", field, encoded)
		}
	}
}

func TestStoreCreateLoadListSaveDelete(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "profiles")
	provider := NewMemoryKeyProvider()
	store, err := NewStore(directory, provider)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	firstNow := time.Date(2026, 7, 27, 9, 0, 0, 0, time.UTC)
	secondNow := firstNow.Add(time.Minute)
	currentNow := firstNow
	store.now = func() time.Time { return currentNow }

	config := sampleConfig()
	clientData := []byte(`{"cookies":["sensitive-session"]}`)
	created, err := store.Create("HITSZ primary", config, clientData)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := validateID(created.ID); err != nil {
		t.Fatalf("new profile did not receive UUID: %q (%v)", created.ID, err)
	}
	if !created.CreatedAt.Equal(firstNow) || !created.UpdatedAt.Equal(firstNow) {
		t.Fatalf("unexpected timestamps after create: %#v", created)
	}

	directoryInfo, err := os.Stat(directory)
	if err != nil {
		t.Fatalf("stat profile directory: %v", err)
	}
	if got := directoryInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("profile directory mode = %o, want 0700", got)
	}

	path := filepath.Join(directory, created.ID+configFileExtension)
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat encrypted file: %v", err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("encrypted file mode = %o, want 0600", got)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read encrypted file: %v", err)
	}
	if bytes.Contains(raw, []byte(config.Password)) || bytes.Contains(raw, clientData) {
		t.Fatalf("encrypted file exposes plaintext credentials or session data: %s", raw)
	}
	var envelope Envelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("decode envelope JSON: %v", err)
	}
	if envelope.Magic != EnvelopeMagic || envelope.Version != EnvelopeVersion || envelope.ID != created.ID {
		t.Fatalf("unexpected envelope metadata: %#v", envelope)
	}
	nonce, err := base64.StdEncoding.DecodeString(envelope.Nonce)
	if err != nil || len(nonce) != nonceLength {
		t.Fatalf("nonce must use standard base64 and be 12 bytes: %q (%v)", envelope.Nonce, err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil || len(ciphertext) <= 16 {
		t.Fatalf("ciphertext must include payload and 16-byte GCM tag: %q (%v)", envelope.Ciphertext, err)
	}

	loaded, err := store.Load(created.ID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !reflect.DeepEqual(loaded, created) {
		t.Fatalf("loaded connection differs\nwant: %#v\n got: %#v", created, loaded)
	}
	loaded.ClientData[0] = 'X'
	loadedAgain, err := store.Load(created.ID)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if !bytes.Equal(loadedAgain.ClientData, clientData) {
		t.Fatalf("load returned aliased client data")
	}

	listed, err := store.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(listed) != 1 || listed[0].ID != created.ID {
		t.Fatalf("unexpected list result: %#v", listed)
	}

	currentNow = secondNow
	created.Config.Password = "new-password"
	// Store.Save must also sanitize callers that construct StoredConnection
	// directly instead of going through StoredConfigFromConfig.
	created.Config.MFACode = "one-time-code"
	created.Config.MFAOTPSecretFile = "/tmp/source-otp"
	created.Config.ClientDataFile = "/tmp/plain-client-data"
	created.Config.CasTicket = "one-time-ticket"
	created.Config.OAuth2Code = "one-time-oauth-code"
	created.Config.SID = "debug-sid"
	created.Config.DeviceID = "debug-device"
	created.Config.SignKey = "debug-sign-key"
	created.Config.ResourceFile = "/tmp/resource.json"
	created.Config.ShadowrocketAddNodeFile = "/tmp/anytls-node"
	created.Config.GraphCodeFile = "/tmp/captcha.png"
	updated, err := store.Save(created)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.ID != created.ID || !updated.CreatedAt.Equal(firstNow) || !updated.UpdatedAt.Equal(secondNow) {
		t.Fatalf("update did not preserve ID/created timestamp: %#v", updated)
	}
	loadedUpdated, err := store.Load(created.ID)
	if err != nil {
		t.Fatalf("load updated: %v", err)
	}
	if loadedUpdated.Config.Password != "new-password" {
		t.Fatalf("updated config not persisted: %#v", loadedUpdated.Config)
	}
	if loadedUpdated.Config.MFACode != "" || loadedUpdated.Config.MFAOTPSecretFile != "" ||
		loadedUpdated.Config.ClientDataFile != "" || loadedUpdated.Config.CasTicket != "" ||
		loadedUpdated.Config.OAuth2Code != "" || loadedUpdated.Config.SID != "" ||
		loadedUpdated.Config.DeviceID != "" || loadedUpdated.Config.SignKey != "" ||
		loadedUpdated.Config.ResourceFile != "" || loadedUpdated.Config.ShadowrocketAddNodeFile != "" ||
		loadedUpdated.Config.GraphCodeFile != "" {
		t.Fatalf("save retained transient/source fields: %#v", loadedUpdated.Config)
	}

	if err := store.Delete(created.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("encrypted file remains after delete: %v", err)
	}
	if _, err := provider.Get(created.ID); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("KeyProvider retains key after delete: %v", err)
	}
	if _, err := store.Load(created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("load after delete = %v, want ErrNotFound", err)
	}
}

func TestEnvelopeAADBindsID(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x41}, keyLength)
	connection := NewStoredConnection("HITSZ", sampleConfig(), []byte("session"))
	connection.ID = "00112233-4455-4677-8899-aabbccddeeff"
	envelope, err := encryptConnection(connection, key, bytes.NewReader(bytes.Repeat([]byte{0x25}, nonceLength)))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	envelope.ID = "11112233-4455-4677-8899-aabbccddeeff"
	if _, err := decryptConnection(envelope, key); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("modified ID must invalidate GCM AAD, got %v", err)
	}
}

func TestCiphertextUsesGoAndCryptoKitGCMConvention(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x18}, keyLength)
	connection := NewStoredConnection("HITSZ", sampleConfig(), []byte("session"))
	connection.ID = "00112233-4455-4677-8899-aabbccddeeff"
	nonce := bytes.Repeat([]byte{0x7e}, nonceLength)
	envelope, err := encryptConnection(connection, key, bytes.NewReader(nonce))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	plaintext, err := json.Marshal(connection)
	if err != nil {
		t.Fatalf("marshal plaintext: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("new GCM: %v", err)
	}
	want := gcm.Seal(nil, nonce, plaintext, AssociatedDataForID(connection.ID))
	got, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		t.Fatalf("decode ciphertext: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("ciphertext is not gcm.Seal output (ciphertext followed by tag)")
	}
}

func TestMissingKeyIsNotReplaced(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "profiles")
	provider := NewMemoryKeyProvider()
	store, err := NewStore(directory, provider)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	connection, err := store.Create("HITSZ", sampleConfig(), []byte("session"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := provider.Delete(connection.ID); err != nil {
		t.Fatalf("remove test key: %v", err)
	}
	connection.Name = "changed"
	if _, err := store.Save(connection); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("save with missing key = %v, want ErrKeyNotFound", err)
	}
	if _, err := provider.Get(connection.ID); !errors.Is(err, ErrKeyNotFound) {
		t.Fatal("save regenerated an existing profile key")
	}
}

func TestRejectsInsecurePermissions(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "profiles")
	store, err := NewStore(directory, NewMemoryKeyProvider())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	connection, err := store.Create("HITSZ", sampleConfig(), []byte("session"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	path := filepath.Join(directory, connection.ID+configFileExtension)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("relax file mode: %v", err)
	}
	if _, err := store.Load(connection.ID); !errors.Is(err, ErrInsecurePermissions) {
		t.Fatalf("load insecure profile = %v, want ErrInsecurePermissions", err)
	}
}

func TestDefaultDir(t *testing.T) {
	t.Parallel()
	directory, err := DefaultDir()
	if err != nil {
		t.Fatalf("default dir: %v", err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("home directory: %v", err)
	}
	want := filepath.Join(home, "Documents", "hitsz-connect")
	if directory != want {
		t.Fatalf("DefaultDir() = %q, want %q", directory, want)
	}
}

func sampleConfig() configs.Config {
	return configs.Config{
		Protocol:            "atrust",
		ServerAddress:       "trust.hitsz.edu.cn",
		ServerPort:          443,
		Username:            "2025310595",
		Password:            "plain-password-that-must-be-encrypted",
		SocksBind:           "127.0.0.1:1080",
		SocksUser:           "socks-user",
		SocksPasswd:         "socks-password",
		HTTPBind:            "127.0.0.1:1081",
		PortForwardingList:  []configs.SinglePortForwarding{{NetworkType: "tcp", BindAddress: "127.0.0.1:8080", RemoteAddress: "10.248.98.2:80"}},
		ShadowsocksURL:      "ss://example",
		DialDirectProxy:     "http://127.0.0.1:7890",
		DisableZJUConfig:    true,
		DisableRemoteDNS:    true,
		DNSTTL:              99,
		RemoteDNSServer:     "10.248.98.30",
		SecondaryDNSServer:  "1.1.1.1",
		DNSServerBind:       "127.0.0.1:5353",
		CustomDNSList:       []configs.SingleCustomDNS{{HostName: "net.hitsz.edu.cn", IP: "10.248.98.2"}},
		DisableKeepAlive:    true,
		KeepAliveURL:        "https://keepalive.example",
		TCPTunnelMode:       true,
		TUNMode:             true,
		AddRoute:            true,
		DNSHijack:           true,
		FakeIP:              true,
		GraphCodeFile:       "/tmp/graph.png",
		DebugDump:           true,
		BindInterface:       "en0",
		AutoDetectInterface: true,
		Profile:             "hitsz",
		NoSystemDNSMutation: true,

		MFAMethod:                    "otp",
		MFACode:                      "123456",
		MFAOTPSecret:                 "JBSWY3DPEHPK3PXP",
		MFAOTPSecretFile:             "/tmp/otp-secret",
		NonInteractive:               true,
		RememberSSO:                  true,
		RememberMFA:                  true,
		DNSRelayBind:                 "127.0.0.1:53535",
		HITSZDNSServer:               "10.248.98.30",
		Shadowrocket:                 "connect",
		ShadowrocketUpdateSubs:       true,
		ShadowrocketAddNodeFile:      "/tmp/node.txt",
		ShadowrocketDisconnectOnExit: true,
		ShadowrocketConfigFragment:   "/tmp/shadowrocket.conf",

		TOTPSecret:          "totp-secret",
		CertFile:            "/tmp/cert.p12",
		CertPassword:        "cert-password",
		DisableServerConfig: true,
		SkipDomainResource:  true,
		DisableMultiLine:    true,
		ProxyAll:            true,
		CustomProxyDomain:   []string{"hitsz.edu.cn", "example.edu.cn"},
		TwfID:               "twf-id",

		AuthType:                "auth/hitsz-sso",
		Phone:                   "86-12345678901",
		LoginDomain:             "hitcas",
		ClientDataFile:          "/tmp/client-data.json",
		CasTicket:               "cas-ticket",
		OAuth2Code:              "oauth-code",
		SID:                     "sid",
		DeviceID:                "device-id",
		SignKey:                 "sign-key",
		ResourceFile:            "/tmp/resource.json",
		UpdateBestNodesInterval: 300,
		SkipTCPTunnelWait:       true,
	}
}

func expectedPersistedConfig(config configs.Config) configs.Config {
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
