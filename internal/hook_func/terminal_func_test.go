package hook_func

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestTerminalRegistryConcurrentExecWaitsForFirstCleanup(t *testing.T) {
	registry := newTerminalRegistry()
	hookStarted := make(chan struct{})
	releaseHook := make(chan struct{})
	var calls atomic.Int32
	wantErr := errors.New("synthetic cleanup error")
	registry.register("blocking cleanup", func(context.Context) error {
		calls.Add(1)
		close(hookStarted)
		<-releaseHook
		return wantErr
	})

	firstDone := make(chan []error, 1)
	go func() { firstDone <- registry.exec(context.Background()) }()
	<-hookStarted

	secondDone := make(chan []error, 1)
	go func() { secondDone <- registry.exec(context.Background()) }()
	select {
	case <-secondDone:
		t.Fatal("second cleanup caller returned before the first cleanup finished")
	case <-time.After(50 * time.Millisecond):
	}

	close(releaseHook)
	first := <-firstDone
	second := <-secondDone
	if calls.Load() != 1 {
		t.Fatalf("cleanup hook calls = %d, want 1", calls.Load())
	}
	for index, result := range [][]error{first, second} {
		if len(result) != 1 || !errors.Is(result[0], wantErr) {
			t.Fatalf("cleanup result %d = %v, want %v", index, result, wantErr)
		}
	}
}

func TestTerminalRegistryConcurrentWaitRespectsContext(t *testing.T) {
	registry := newTerminalRegistry()
	hookStarted := make(chan struct{})
	releaseHook := make(chan struct{})
	registry.register("blocking cleanup", func(context.Context) error {
		close(hookStarted)
		<-releaseHook
		return nil
	})

	firstDone := make(chan []error, 1)
	go func() { firstDone <- registry.exec(context.Background()) }()
	<-hookStarted

	waitCtx, cancel := context.WithCancel(context.Background())
	cancel()
	result := registry.exec(waitCtx)
	if len(result) != 1 || !errors.Is(result[0], context.Canceled) {
		t.Fatalf("cancelled cleanup wait = %v, want context.Canceled", result)
	}

	close(releaseHook)
	if result := <-firstDone; result != nil {
		t.Fatalf("first cleanup result = %v, want nil", result)
	}
}

func TestTerminalRegistryReturnsIndependentResultCopies(t *testing.T) {
	registry := newTerminalRegistry()
	wantErr := errors.New("synthetic cleanup error")
	registry.register("failing cleanup", func(context.Context) error { return wantErr })

	first := registry.exec(context.Background())
	if len(first) != 1 || !errors.Is(first[0], wantErr) {
		t.Fatalf("first cleanup result = %v, want %v", first, wantErr)
	}
	first[0] = nil

	second := registry.exec(context.Background())
	if len(second) != 1 || !errors.Is(second[0], wantErr) {
		t.Fatalf("stored cleanup result was mutated through caller slice: %v", second)
	}
	second[0] = nil

	third := registry.exec(context.Background())
	if len(third) != 1 || !errors.Is(third[0], wantErr) {
		t.Fatalf("stored cleanup result was mutated through waiter slice: %v", third)
	}
}
