//go:build !darwin

package secureconfig

// NewKeychainProvider is explicitly unavailable off macOS. Tests can pass a
// MemoryKeyProvider to NewStore instead.
func NewKeychainProvider() (KeyProvider, error) {
	return nil, ErrUnsupportedPlatform
}
