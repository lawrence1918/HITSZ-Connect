//go:build darwin && !cgo

package secureconfig

// NewKeychainProvider requires cgo because it calls Security.framework rather
// than putting secrets in a security(1) command invocation.
func NewKeychainProvider() (KeyProvider, error) {
	return nil, ErrUnsupportedPlatform
}
