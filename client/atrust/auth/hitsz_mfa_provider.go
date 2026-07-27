package auth

import "sync"

// HITSZMFACodeProvider lets non-terminal frontends supply App/SMS codes
// without sharing stdin with their control protocol.
type HITSZMFACodeProvider func(method string) (string, error)

var hitszMFACodeProvider struct {
	sync.RWMutex
	provider HITSZMFACodeProvider
}

// SetHITSZMFACodeProvider installs a process-local provider and returns a
// restore function. A bridge process has a single active login; normal CLI
// behavior is unchanged while no provider is installed.
func SetHITSZMFACodeProvider(provider HITSZMFACodeProvider) (restore func()) {
	hitszMFACodeProvider.Lock()
	previous := hitszMFACodeProvider.provider
	hitszMFACodeProvider.provider = provider
	hitszMFACodeProvider.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			hitszMFACodeProvider.Lock()
			hitszMFACodeProvider.provider = previous
			hitszMFACodeProvider.Unlock()
		})
	}
}

func currentHITSZMFACodeProvider() HITSZMFACodeProvider {
	hitszMFACodeProvider.RLock()
	defer hitszMFACodeProvider.RUnlock()
	return hitszMFACodeProvider.provider
}
