// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package dnp3_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/dnp3"
)

// Covers: SIG-IPE-6495, SIG-IPE-6496
// TestSessionAgainstSimulator: the master's polling session clears the
// simulator's restart indication, synchronises its clock when it asks,
// answers a buffer overflow with an integrity poll and runs the start-up
// again after a restart.
func TestSessionAgainstSimulator(t *testing.T) {
	sim := startSim(t)
	sim.SetRestart(true)
	sim.SetNeedTime(true)
	m := dial(t, sim, nil, nil)
	var mu sync.Mutex
	tasks := map[string]int{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = m.RunSession(ctx, dnp3.SessionConfig{TimeSync: dnp3.TimeSyncNonLAN, RetryDelay: 200 * time.Millisecond,
			OnTask: func(n string, err error) {
				if err == nil {
					mu.Lock()
					tasks[n]++
					mu.Unlock()
				}
			}})
	}()
	count := func(n string) int { mu.Lock(); defer mu.Unlock(); return tasks[n] }
	eventually(t, 5*time.Second, "start-up", func() bool { return count("time sync") == 1 })
	if sim.Restarting() {
		t.Error("restart indication not cleared")
	}
	if at, ok := sim.Clock(); !ok || time.Since(at).Abs() > 5*time.Second {
		t.Errorf("simulator clock %s (set %v)", at, ok)
	}
	before := count("integrity")
	sim.SetOverflow(true)
	_, _ = m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(1)) // brings the overflow IIN in
	eventually(t, 3*time.Second, "integrity poll after the overflow", func() bool { return count("integrity") > before })
	sim.SetOverflow(false)
	sim.SetRestart(true)
	_, _ = m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(1))
	eventually(t, 3*time.Second, "second start-up", func() bool { return count("clear restart") == 2 })
}
