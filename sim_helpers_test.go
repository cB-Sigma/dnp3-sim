package dnp3_test

import (
	"testing"
	"time"

	dnp3sim "github.com/cB-Sigma/dnp3-sim/sim"
)

func startSim(t *testing.T) *dnp3sim.Sim {
	t.Helper()
	s := dnp3sim.New(10, 1)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
	return s
}

// eventually polls f every 20 ms until it holds or timeout passes.
func eventually(t *testing.T, timeout time.Duration, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", timeout, what)
}
