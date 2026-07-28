package hook_func

import (
	"context"
	"sync"

	"github.com/mythologyli/zju-connect/log"
)

type TerminalFunc func(ctx context.Context) error
type TerminalItem struct {
	f    TerminalFunc
	name string
}

type terminalRegistry struct {
	mu      sync.Mutex
	items   []TerminalItem
	started bool
	done    chan struct{}
	errs    []error
}

func newTerminalRegistry() *terminalRegistry {
	return &terminalRegistry{}
}

var defaultTerminalRegistry = newTerminalRegistry()

func RegisterTerminalFunc(execName string, fun TerminalFunc) {
	defaultTerminalRegistry.register(execName, fun)
}

func (registry *terminalRegistry) register(execName string, fun TerminalFunc) {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	if registry.started {
		log.Println("Terminal already started, skip registering func:", execName)
		return
	}

	registry.items = append(registry.items, TerminalItem{
		f:    fun,
		name: execName,
	})
	log.Println("Register func on terminal:", execName)
}

func ExecTerminalFunc(ctx context.Context) []error {
	return defaultTerminalRegistry.exec(ctx)
}

func (registry *terminalRegistry) exec(ctx context.Context) []error {
	registry.mu.Lock()
	if registry.started {
		done := registry.done
		registry.mu.Unlock()

		// Prefer an already-published cleanup result over a concurrently cancelled
		// context. This keeps every completed caller's view deterministic.
		select {
		case <-done:
			return registry.resultCopy()
		default:
		}
		select {
		case <-done:
			return registry.resultCopy()
		case <-ctx.Done():
			return []error{ctx.Err()}
		}
	}
	registry.started = true
	registry.done = make(chan struct{})
	funcList := append([]TerminalItem(nil), registry.items...)
	registry.mu.Unlock()

	var errList []error
	for _, item := range funcList {
		log.Println("Exec func on terminal:", item.name)
		if err := item.f(ctx); err != nil {
			errList = append(errList, err)
			log.Println("Exec func on terminal ", item.name, "failed:", err)
		} else {
			log.Println("Exec func on terminal ", item.name, "success")
		}
	}

	registry.mu.Lock()
	registry.errs = append([]error(nil), errList...)
	close(registry.done)
	result := append([]error(nil), registry.errs...)
	registry.mu.Unlock()
	return result
}

func (registry *terminalRegistry) resultCopy() []error {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	return append([]error(nil), registry.errs...)
}

func IsTerminal() bool {
	return defaultTerminalRegistry.isStarted()
}

func (registry *terminalRegistry) isStarted() bool {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	return registry.started
}
