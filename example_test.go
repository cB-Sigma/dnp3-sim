// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package dnp3_test

import (
	"context"
	"fmt"
	"time"

	"github.com/cB-Sigma/dnp3"
	"github.com/cB-Sigma/dnp3-sim/sim"
)

// A master of the dnp3 module polls the simulated outstation for its
// class 0 data and latches a relay with select-before-operate.
func Example() {
	rtu := sim.New(10, 1) // outstation 10, master 1
	rtu.Set(30, 0, 230.5, 0x01)
	rtu.Set(10, 0, 0, 0x01)
	if err := rtu.Start(); err != nil {
		panic(err)
	}
	defer rtu.Stop()

	ctx := context.Background()
	m, err := dnp3.Dial(ctx, dnp3.MasterConfig{URL: rtu.URL(), MasterAddress: 1, OutstationAddress: 10, Timeout: 2 * time.Second})
	if err != nil {
		panic(err)
	}
	defer m.Close()

	frags, err := m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(0))
	if err != nil {
		panic(err)
	}
	for _, f := range frags {
		blocks, _ := dnp3.ParseObjects(f.Objects, true)
		for _, b := range blocks {
			for _, p := range b.Points {
				if p.Group == 30 {
					fmt.Printf("g%dv%d index %d: %v\n", p.Group, p.Var, p.Index, p.Value)
				}
			}
		}
	}

	latch, _ := dnp3.EncodeBlock(12, 1, dnp3.Q8Index8, []dnp3.Point{{Index: 0, CROB: dnp3.CROB{Code: dnp3.OpLatchOn, Count: 1}}})
	if err := m.SelectOperate(ctx, latch, 5*time.Second, nil); err != nil {
		panic(err)
	}
	fmt.Println("relay 0:", rtu.Get(10, 0).V)
	// Output:
	// g30v5 index 0: 230.5
	// relay 0: 1
}
