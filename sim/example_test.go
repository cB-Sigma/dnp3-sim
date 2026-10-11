// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package sim_test

import (
	"context"
	"fmt"
	"time"

	"github.com/cB-Sigma/dnp3"
	"github.com/cB-Sigma/dnp3-sim/sim"
)

// A simulated outstation with one analog input and a buffered event,
// polled by the library's master.
func Example() {
	s := sim.New(10, 1)
	s.Set(30, 0, 49.5, 0x01) // frequency, Hz (g30v5: a 32-bit float)
	s.AddEvent(sim.Event{Group: 2, Var: 1, Index: 0, Value: 1, Flags: 0x01, Class: 1})
	if err := s.Start(); err != nil {
		panic(err)
	}
	defer s.Stop()

	ctx := context.Background()
	m, err := dnp3.Dial(ctx, dnp3.MasterConfig{URL: s.URL(), MasterAddress: 1, OutstationAddress: 10, Timeout: 2 * time.Second})
	if err != nil {
		panic(err)
	}
	defer m.Close()
	frags, err := m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(1, 0))
	if err != nil {
		panic(err)
	}
	for _, f := range frags {
		blocks, _ := dnp3.ParseObjects(f.Objects, true)
		for _, b := range blocks {
			for _, p := range b.Points {
				fmt.Printf("g%dv%d %d: %v\n", p.Group, p.Var, p.Index, p.Value)
			}
		}
	}
	fmt.Println("requests:", s.Requests())
	// Output:
	// g2v1 0: true
	// g30v5 0: 49.5
	// requests: [READ g60v2 g60v1]
}
