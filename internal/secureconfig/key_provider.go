package secureconfig

import (
	"sync"
)

// MemoryKeyProvider is an in-memory KeyProvider intended for tests. It copies
// all key material at its API boundary and is never used by NewDefaultStore.
type MemoryKeyProvider struct {
	mu   sync.RWMutex
	keys map[string][]byte
}

// NewMemoryKeyProvider returns an empty non-persistent key provider suitable
// for tests on any operating system.
func NewMemoryKeyProvider() *MemoryKeyProvider {
	return &MemoryKeyProvider{keys: make(map[string][]byte)}
}

// Get returns a copy of the key for id.
func (provider *MemoryKeyProvider) Get(id string) ([]byte, error) {
	provider.mu.RLock()
	key, ok := provider.keys[id]
	provider.mu.RUnlock()
	if !ok {
		return nil, ErrKeyNotFound
	}
	return cloneBytes(key), nil
}

// Set stores a copy of key for id.
func (provider *MemoryKeyProvider) Set(id string, key []byte) error {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if provider.keys == nil {
		provider.keys = make(map[string][]byte)
	}
	oldKey := provider.keys[id]
	provider.keys[id] = cloneBytes(key)
	zeroBytes(oldKey)
	return nil
}

// Delete removes key for id. It returns ErrKeyNotFound when no key exists.
func (provider *MemoryKeyProvider) Delete(id string) error {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	key, ok := provider.keys[id]
	if !ok {
		return ErrKeyNotFound
	}
	delete(provider.keys, id)
	zeroBytes(key)
	return nil
}
