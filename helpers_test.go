// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package dnp3_test

import (
	"encoding/hex"
	"testing"

	"github.com/cB-Sigma/dnp3"
	dnp3sim "github.com/cB-Sigma/dnp3-sim/sim"
)

const updateKeyHex = "00112233445566778899aabbccddeeff"

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// hexKey decodes a hex key of the tests.
func hexKey(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return b
}

// pointsOf indexes the points of response fragments by group and index.
func pointsOf(t *testing.T, frags []dnp3.Fragment) map[[2]uint32]dnp3.Point {
	t.Helper()
	out := map[[2]uint32]dnp3.Point{}
	for _, f := range frags {
		bl, err := dnp3.ParseObjects(f.Objects, true)
		if err != nil {
			t.Fatalf("% X: %v", f.Objects, err)
		}
		for _, b := range bl {
			for _, p := range b.Points {
				out[[2]uint32{uint32(p.Group), p.Index}] = p
			}
		}
	}
	return out
}

// readHeader builds a READ header for index 0 (or all, or a count of 1).
func readHeader(g, v, q uint8) []byte {
	switch q {
	case dnp3.Q8StartStop, dnp3.Q16StartStop, dnp3.QAll:
		return dnp3.AppendHeader(nil, g, v, q, 0, 0)
	case dnp3.Q8Count, dnp3.Q16Count:
		return dnp3.AppendHeader(nil, g, v, q, 1, 0)
	case dnp3.Q8Index8:
		return append(dnp3.AppendHeader(nil, g, v, q, 1, 0), 0)
	case dnp3.Q16Index16:
		return append(dnp3.AppendHeader(nil, g, v, q, 1, 0), 0, 0)
	}
	return nil
}

// authSim starts the simulator with Secure Authentication for user 1.
func authSim(t *testing.T, key string) *dnp3sim.Sim {
	t.Helper()
	sim := startSim(t)
	sim.EnableAuth(1, mustHex(t, key), dnp3.MACSHA256Trunc16)
	return sim
}
