// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package sim

import (
	"io"

	"github.com/cB-Sigma/dnp3"
	"github.com/cB-Sigma/dnp3/profile"
)

// Profile writes the simulated outstation's device profile document (XML)
// with dnp3's profile package: its address, master, fragment size and
// select timeout, and every static point set so far with the static
// variation the simulator answers class 0 with. The simulator's events
// are added by hand (AddEvent), so its points carry no event class.
func (s *Sim) Profile(w io.Writer, vendor, name string) error {
	db := dnp3.NewPointDB()
	s.mu.Lock()
	for g, pts := range s.static {
		typ := dnp3.PointTypeOf(g)
		for i := range pts {
			_ = db.Define(dnp3.DBPoint{Type: typ, Index: uint32(i), Class0: true, StaticVar: s.StaticVar[g]})
		}
	}
	dev := profile.Device{Vendor: vendor, Name: name, Address: s.Address, Masters: []uint16{s.Master}, SelfAddress: s.selfAddress,
		Outstation: dnp3.OutstationConfig{MaxFragment: s.MaxFragment, SelectTimeout: s.SelectTimeout, Unsolicited: true}}
	s.mu.Unlock()
	return profile.New(dev, db).Write(w)
}
