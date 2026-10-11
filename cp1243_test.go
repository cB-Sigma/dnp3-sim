package dnp3_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cB-Sigma/dnp3"
	dnp3sim "github.com/cB-Sigma/dnp3-sim/sim"
)

// The cp1243-1 preset reproduces what the Siemens CP 1243-1 device profile
// (v1.1) declares: outstation address 4, master 1; only the objects,
// qualifiers and function codes of its implementation table; binary and
// analog output status outside class 0; latch-only CROBs; unsolicited
// responses with no retries; Secure Authentication v5 with one user,
// HMAC-SHA-256/16 and AES-128 key wrap; 2048-octet fragments.

// Covers: SIG-IPE-1628
func TestCP1243PresetDeclaredProfile(t *testing.T) {
	ctx := context.Background()
	o, err := dnp3sim.StartCP1243(ctx, dnp3sim.CP1243Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	if o.Address != 4 || o.Master != 1 {
		t.Fatalf("addresses %d/%d", o.Address, o.Master)
	}
	m, err := dnp3.Dial(ctx, dnp3.MasterConfig{URL: o.URL(), MasterAddress: 1, OutstationAddress: 4, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	rejected := func(fc byte, objs []byte, want dnp3.IIN) {
		t.Helper()
		frags, err := m.Request(ctx, fc, objs)
		var rej *dnp3.RejectedError
		if !errors.As(err, &rej) || len(frags) != 1 || frags[0].IIN&want == 0 {
			t.Errorf("%s % X: %v %+v (want IIN %04X)", dnp3.FuncName(fc), objs, err, frags, uint16(want))
		}
	}
	// Class 0 carries inputs and counters but not output status (3.3.3,
	// 3.6.2: never), and the static variations of part 3.
	frags, err := m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(0))
	if err != nil {
		t.Fatal(err)
	}
	groups := map[[2]uint8]bool{}
	for _, f := range frags {
		bl, _ := dnp3.ParseObjects(f.Objects, true)
		for _, b := range bl {
			groups[[2]uint8{b.Header.Group, b.Header.Var}] = true
		}
	}
	if !groups[[2]uint8{1, 2}] || !groups[[2]uint8{20, 1}] || !groups[[2]uint8{30, 1}] || groups[[2]uint8{10, 2}] || groups[[2]uint8{40, 1}] {
		t.Fatalf("class 0 objects %v", groups)
	}
	// Output status is read explicitly (00, 01, 06 per the table).
	frags, err = m.Request(ctx, dnp3.FCRead, dnp3.AppendHeader(nil, 10, 0, dnp3.QAll, 0, 0))
	if err != nil || len(pointsOf(t, frags)) == 0 {
		t.Fatalf("g10 read: %v", err)
	}
	// Device attributes of the table, including the fragment sizes.
	frags, err = m.Request(ctx, dnp3.FCRead, dnp3.AppendHeader(nil, 0, 240, dnp3.Q8StartStop, 0, 0))
	if err != nil || pointsOf(t, frags)[[2]uint32{0, 0}].Value != 2048.0 {
		t.Fatalf("g0v240: %v %+v", err, pointsOf(t, frags))
	}
	// Outside the table: double-bit inputs, 16-bit analog input events by
	// index, cold restart, assign class and a g0 attribute it does not list.
	rejected(dnp3.FCRead, dnp3.AppendHeader(nil, 3, 0, dnp3.QAll, 0, 0), dnp3.IINObjectUnknown)
	rejected(dnp3.FCRead, dnp3.AppendHeader(nil, 32, 2, dnp3.Q8StartStop, 0, 0), dnp3.IINObjectUnknown|dnp3.IINParameterError)
	rejected(dnp3.FCColdRestart, nil, dnp3.IINNoFuncCodeSupport)
	rejected(dnp3.FCAssignClass, dnp3.AppendHeader(nil, 30, 0, dnp3.QAll, 0, 0), dnp3.IINNoFuncCodeSupport)
	rejected(dnp3.FCRead, dnp3.AppendHeader(nil, 0, 245, dnp3.Q8StartStop, 0, 0), dnp3.IINObjectUnknown)
	// CROBs: latch on and off only (3.3.1, table g12v1).
	pulse, _ := dnp3.EncodeBlock(12, 1, dnp3.Q8Index8, []dnp3.Point{{Index: 0, CROB: dnp3.CROB{Code: dnp3.OpPulseOn, Count: 1, OnTime: 100}}})
	frags, _ = m.Request(ctx, dnp3.FCDirectOperate, pulse)
	if p := pointsOf(t, frags)[[2]uint32{12, 0}]; p.Status != 4 {
		t.Errorf("pulse: status %d", p.Status)
	}
	latch, _ := dnp3.EncodeBlock(12, 1, dnp3.Q8Index8, []dnp3.Point{{Index: 0, CROB: dnp3.CROB{Code: dnp3.OpLatchOn, Count: 1}}})
	frags, err = m.Request(ctx, dnp3.FCDirectOperate, latch)
	if p := pointsOf(t, frags)[[2]uint32{12, 0}]; err != nil || p.Status != 0 {
		t.Errorf("latch: %v status %d", err, p.Status)
	}
	// The declared profile is exposed for the report.
	if d := o.Declared(); len(d.Objects) < 60 || d.MaxFragment != 2048 || d.UnsolRetries != 0 || d.KeyChangeCount != 1000 {
		t.Errorf("declared %+v", d)
	}
}
