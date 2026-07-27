package metrics

import (
	"sync"
	"testing"
)

func TestATrustTrafficConcurrent(t *testing.T) {
	ResetATrust()
	const goroutines = 16
	const iterations = 1000

	var wg sync.WaitGroup
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range iterations {
				AddATrustTX(3)
				AddATrustRX(5)
			}
		}()
	}
	wg.Wait()

	got := ATrustSnapshot()
	if want := uint64(goroutines * iterations * 3); got.TXBytes != want {
		t.Fatalf("TXBytes = %d, want %d", got.TXBytes, want)
	}
	if want := uint64(goroutines * iterations * 5); got.RXBytes != want {
		t.Fatalf("RXBytes = %d, want %d", got.RXBytes, want)
	}

	ResetATrust()
	if got := ATrustSnapshot(); got != (TrafficSnapshot{}) {
		t.Fatalf("snapshot after reset = %+v", got)
	}
}
