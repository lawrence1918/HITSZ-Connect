package auth

import "testing"

func TestSetHITSZMFACodeProviderRestore(t *testing.T) {
	if currentHITSZMFACodeProvider() != nil {
		t.Fatal("unexpected provider before test")
	}
	restore := SetHITSZMFACodeProvider(func(method string) (string, error) {
		return method, nil
	})
	provider := currentHITSZMFACodeProvider()
	if provider == nil {
		t.Fatal("provider not installed")
	}
	if got, err := provider("sms"); err != nil || got != "sms" {
		t.Fatalf("provider returned %q, %v", got, err)
	}
	restore()
	if currentHITSZMFACodeProvider() != nil {
		t.Fatal("provider not restored")
	}
	// Restore is intentionally idempotent for deferred cleanup paths.
	restore()
}
