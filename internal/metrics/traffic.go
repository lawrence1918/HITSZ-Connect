// Package metrics provides process-local, concurrency-safe runtime counters.
package metrics

import "sync/atomic"

// TrafficSnapshot is a point-in-time view of aTrust application payload
// traffic. Tunnel framing and TLS overhead are intentionally excluded.
type TrafficSnapshot struct {
	TXBytes uint64 `json:"txBytes"`
	RXBytes uint64 `json:"rxBytes"`
}

var atrustTraffic struct {
	tx atomic.Uint64
	rx atomic.Uint64
}

// AddATrustTX records application bytes handed to an aTrust tunnel.
func AddATrustTX(n int) {
	if n > 0 {
		atrustTraffic.tx.Add(uint64(n))
	}
}

// AddATrustRX records application bytes received from an aTrust tunnel.
func AddATrustRX(n int) {
	if n > 0 {
		atrustTraffic.rx.Add(uint64(n))
	}
}

// ATrustSnapshot returns a lock-free, race-safe traffic snapshot.
func ATrustSnapshot() TrafficSnapshot {
	return TrafficSnapshot{
		TXBytes: atrustTraffic.tx.Load(),
		RXBytes: atrustTraffic.rx.Load(),
	}
}

// ResetATrust clears the process-local counters. A bridge process has exactly
// one active connection, so reset is performed before that connection starts.
func ResetATrust() {
	atrustTraffic.tx.Store(0)
	atrustTraffic.rx.Store(0)
}
