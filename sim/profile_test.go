// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package sim_test

import (
	"bytes"
	"testing"

	"github.com/cB-Sigma/dnp3"
	"github.com/cB-Sigma/dnp3-sim/sim"
	"github.com/cB-Sigma/dnp3/profile"
)

// The simulator's device profile, read back with dnp3's profile package,
// lists its points and configures an equal outstation database.
// Covers: SIG-IPE-6902
func TestSimProfile(t *testing.T) {
	s := sim.New(10, 1)
	s.Set(1, 0, 1, 0x01)
	s.Set(1, 1, 0, 0x01)
	s.Set(30, 5, 230.5, 0x01)
	s.Set(20, 2, 42, 0x01)
	var b bytes.Buffer
	if err := s.Profile(&b, "Example", "dnp3sim"); err != nil {
		t.Fatal(err)
	}
	doc, err := profile.Read(&b)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Device.Configuration.Link.Address != 10 || doc.Device.Configuration.Device.Name != "dnp3sim" {
		t.Errorf("configuration %+v", doc.Device.Configuration)
	}
	if n := len(doc.Points("binary")); n != 2 {
		t.Errorf("%d binaries", n)
	}
	a := doc.Points("analog")
	if len(a) != 1 || a[0].Index != 5 || a[0].StaticVar != 5 || !a[0].Class0 || a[0].Class != "none" {
		t.Errorf("analogs %+v", a)
	}
	db := dnp3.NewPointDB()
	if _, err := doc.Define(db); err != nil {
		t.Fatal(err)
	}
	if _, ok := db.Point("counter", 2); !ok {
		t.Error("the counter was not defined from the profile")
	}
}
