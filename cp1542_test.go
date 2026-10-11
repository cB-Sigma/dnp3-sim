package dnp3_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/cB-Sigma/dnp3"
	dnp3sim "github.com/cB-Sigma/dnp3-sim/sim"
)

// The cp1542sp-1-irc preset reproduces what the Siemens CP 1542SP-1 IRC
// device profile (v2.2, 2016 template) declares: outstation address 4,
// master 1; only the objects, qualifiers and function codes of its
// implementation table (with the rows other items imply, F-1450);
// double-bit inputs; every data type in class 0; latch-only CROBs and
// analog output blocks, ten of each, mixed in one request; unsolicited
// responses with three retries; three class buffers of 255 events;
// Secure Authentication v5 with one user, HMAC-SHA-256/16 or
// HMAC-SHA-1/10 and AES-128 or AES-256 key wrap; TCP, UDP and TLS.

func startCP1542(t *testing.T, opt dnp3sim.CP1542Options) *dnp3sim.CP1542 {
	t.Helper()
	o, err := dnp3sim.StartCP1542(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(o.Close)
	return o
}

// Covers: SIG-IPE-2650
func TestCP1542PresetDeclaredProfile(t *testing.T) {
	ctx := context.Background()
	o := startCP1542(t, dnp3sim.CP1542Options{})
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
	// Class 0 carries every data type, outputs included (3.1.4, 3.2.4,
	// 3.3.3, 3.4.3, 3.4.7, 3.5.4, 3.6.2, 3.8.2), in the part 3 variations.
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
	for _, gv := range [][2]uint8{{1, 2}, {3, 2}, {10, 2}, {20, 1}, {21, 1}, {30, 1}, {40, 1}} {
		if !groups[gv] {
			t.Errorf("class 0 lacks g%dv%d: %v", gv[0], gv[1], groups)
		}
	}
	// Device attributes of the table.
	frags, err = m.Request(ctx, dnp3.FCRead, dnp3.AppendHeader(nil, 0, 241, dnp3.Q8StartStop, 0, 0))
	if err != nil || pointsOf(t, frags)[[2]uint32{0, 0}].Value != 2048.0 {
		t.Fatalf("g0v241: %v %+v", err, pointsOf(t, frags))
	}
	// Double-bit input events and octet string events are read by class
	// and qualifier 06 (g4, g111 rows).
	if _, err := m.Request(ctx, dnp3.FCRead, dnp3.AppendHeader(nil, 4, 0, dnp3.QAll, 0, 0)); err != nil {
		t.Errorf("g4 read: %v", err)
	}
	if _, err := m.Request(ctx, dnp3.FCRead, dnp3.AppendHeader(nil, 111, 0, dnp3.QAll, 0, 0)); err != nil {
		t.Errorf("g111 read: %v", err)
	}
	// Outside the table: frozen analog inputs (3.5.7 blank), the
	// double-precision variations part 3 ticks but the table leaves out
	// (F-1455), deadbands (group 34 excluded in 1.1.7), assign class,
	// warm restart, delay measurement, file transfer (1.1.8 unticked) and
	// a g0 attribute it does not list.
	rejected(dnp3.FCRead, dnp3.AppendHeader(nil, 31, 0, dnp3.QAll, 0, 0), dnp3.IINObjectUnknown)
	rejected(dnp3.FCRead, dnp3.AppendHeader(nil, 30, 6, dnp3.QAll, 0, 0), dnp3.IINObjectUnknown)
	rejected(dnp3.FCRead, dnp3.AppendHeader(nil, 40, 4, dnp3.QAll, 0, 0), dnp3.IINObjectUnknown)
	rejected(dnp3.FCRead, dnp3.AppendHeader(nil, 34, 0, dnp3.QAll, 0, 0), dnp3.IINObjectUnknown)
	rejected(dnp3.FCAssignClass, dnp3.AppendHeader(nil, 30, 0, dnp3.QAll, 0, 0), dnp3.IINNoFuncCodeSupport)
	rejected(dnp3.FCWarmRestart, nil, dnp3.IINNoFuncCodeSupport)
	rejected(dnp3.FCDelayMeasure, nil, dnp3.IINNoFuncCodeSupport)
	rejected(dnp3.FCOpenFile, dnp3.AppendHeader(nil, 70, 3, dnp3.QFreeFormat, 1, 0), dnp3.IINNoFuncCodeSupport|dnp3.IINParameterError)
	rejected(dnp3.FCRead, dnp3.AppendHeader(nil, 0, 245, dnp3.Q8StartStop, 0, 0), dnp3.IINObjectUnknown)
	// Static objects by index are not in the table (00, 01, 06 only).
	rejected(dnp3.FCRead, append(dnp3.AppendHeader(nil, 30, 1, dnp3.Q8Index8, 1, 0), 0), dnp3.IINParameterError)

	// CROBs: latch on and off only (table g12v1), status NOT_SUPPORTED (4)
	// for a pulse although 3.3.1 gives pulse times (F-1451).
	pulse, _ := dnp3.EncodeBlock(12, 1, dnp3.Q8Index8, []dnp3.Point{{Index: 0, CROB: dnp3.CROB{Code: dnp3.OpPulseOn, Count: 1, OnTime: 1000}}})
	frags, _ = m.Request(ctx, dnp3.FCDirectOperate, pulse)
	if p := pointsOf(t, frags)[[2]uint32{12, 0}]; p.Status != 4 {
		t.Errorf("pulse: status %d", p.Status)
	}
	// A CROB and an analog output block in one request (1.5.8), the
	// single-precision block of g41v3.
	mixed, _ := dnp3.EncodeBlock(12, 1, dnp3.Q8Index8, []dnp3.Point{{Index: 0, CROB: dnp3.CROB{Code: dnp3.OpLatchOn, Count: 1}}})
	aob, _ := dnp3.EncodeBlock(41, 3, dnp3.Q8Index8, []dnp3.Point{{Index: 0, Value: 7.5}})
	frags, err = m.Request(ctx, dnp3.FCDirectOperate, append(mixed, aob...))
	pts := pointsOf(t, frags)
	if err != nil || pts[[2]uint32{12, 0}].Status != 0 || pts[[2]uint32{41, 0}].Status != 0 {
		t.Errorf("mixed controls: %v %+v", err, pts)
	}
	if n := len(o.Controls()); n != 3 {
		t.Errorf("%d controls reached the device", n)
	}
	// More than ten CROBs in one request (1.5.5) are refused.
	var many []dnp3.Point
	for i := range 11 {
		many = append(many, dnp3.Point{Index: uint32(i), CROB: dnp3.CROB{Code: dnp3.OpLatchOn, Count: 1}})
	}
	eleven, _ := dnp3.EncodeBlock(12, 1, dnp3.Q8Index8, many)
	frags, _ = m.Request(ctx, dnp3.FCDirectOperate, eleven)
	if p := pointsOf(t, frags)[[2]uint32{12, 0}]; p.Status == 0 && (len(frags) == 0 || frags[0].IIN&dnp3.IINParameterError == 0) {
		t.Errorf("eleven CROBs accepted: %+v", frags)
	}
	// The declared profile is exposed for the report.
	d := o.Declared()
	if d.MaxFragment != 2048 || d.UnsolRetries != 3 || d.EventsPerClass != 255 || !d.OutputsInClass0 || !d.DoubleBit ||
		!slices.Contains(d.MACs, dnp3.MACSHA1Trunc10) || len(d.TLSSuites) != 6 || !slices.Contains(d.ControlStatuses, 127) {
		t.Errorf("declared %+v", d)
	}
}

// Every READ row of the preset's table is served: no IIN2.0 or IIN2.1.
//
// Covers: SIG-IPE-2656
func TestCP1542PresetServesDeclaredReads(t *testing.T) {
	ctx := context.Background()
	o := startCP1542(t, dnp3sim.CP1542Options{})
	m, err := dnp3.Dial(ctx, dnp3.MasterConfig{URL: o.URL(), MasterAddress: 1, OutstationAddress: 4, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	sent := 0
	for _, r := range o.Declared().Objects {
		if !slices.Contains(r.Funcs, dnp3.FCRead) {
			continue
		}
		for _, q := range r.Quals {
			req := readHeader(r.Group, r.Var, q)
			if r.Group == 110 || r.Group == 111 {
				req = readHeader(r.Group, 0, q)
			}
			frags, err := m.Request(ctx, dnp3.FCRead, req)
			var rej *dnp3.RejectedError
			if err != nil && !errors.As(err, &rej) {
				t.Fatalf("g%dv%d q%02X: %v", r.Group, r.Var, q, err)
			}
			for _, f := range frags {
				if f.IIN&(dnp3.IINNoFuncCodeSupport|dnp3.IINObjectUnknown|dnp3.IINParameterError) != 0 {
					t.Errorf("g%dv%d qualifier %02X declared but answered IIN %04X", r.Group, r.Var, q, uint16(f.IIN))
				}
			}
			sent++
		}
	}
	if sent < 100 {
		t.Errorf("only %d declared reads exercised", sent)
	}
}

// What the CP 1542SP-1 IRC declares beyond the CP 1243-1: its table
// adds double-bit inputs (g3, g4), relative-time binary input events
// (g2v3), octet string events (g111), reads of the internal indications
// (g80v1) and the attributes 246 and 247; it drops every
// double-precision row (g30v6, g32v6, g32v8, g40v4, g41v4, g42v6, g42v8),
// the g40v0 row and the attributes 235 and 236. Part 1 adds UDP, TLS,
// multiple masters, AES-256 key wrap, HMAC-SHA-1/10, unsolicited
// retries, outputs in class 0, mixed control requests and broadcast.
//
// Covers: SIG-IPE-2657
func TestCP1542DiffersFromCP1243(t *testing.T) {
	a, b := dnp3sim.CP1243Declared(), dnp3sim.CP1542Declared()
	rows := func(d dnp3sim.Declared) map[[2]uint8]bool {
		m := map[[2]uint8]bool{}
		for _, r := range d.Objects {
			if slices.Contains(r.Funcs, dnp3.FCRead) || r.Group == 12 || r.Group == 41 {
				m[[2]uint8{r.Group, r.Var}] = true
			}
		}
		return m
	}
	ra, rb := rows(a), rows(b)
	var added, dropped [][2]uint8
	for k := range rb {
		if !ra[k] {
			added = append(added, k)
		}
	}
	for k := range ra {
		if !rb[k] {
			dropped = append(dropped, k)
		}
	}
	cmp := func(x, y [2]uint8) int { return int(x[0])<<8 | int(x[1]) - (int(y[0])<<8 | int(y[1])) }
	slices.SortFunc(added, cmp)
	slices.SortFunc(dropped, cmp)
	wantAdded := [][2]uint8{{0, 246}, {0, 247}, {2, 3}, {3, 1}, {3, 2}, {4, 1}, {4, 2}, {4, 3}, {80, 1}, {111, 0}}
	wantDropped := [][2]uint8{{0, 235}, {0, 236}, {30, 6}, {32, 6}, {32, 8}, {40, 0}, {40, 4}, {41, 4}, {42, 6}, {42, 8}}
	if !slices.Equal(added, wantAdded) {
		t.Errorf("added rows %v, want %v", added, wantAdded)
	}
	if !slices.Equal(dropped, wantDropped) {
		t.Errorf("dropped rows %v, want %v", dropped, wantDropped)
	}
	if a.OutputsInClass0 || !b.OutputsInClass0 || a.UnsolRetries != 0 || b.UnsolRetries != 3 || a.UDP || !b.UDP ||
		len(a.TLSSuites) != 0 || len(b.TLSSuites) == 0 || a.Broadcast || !b.Broadcast || !b.MixedControls ||
		a.KeyChangeInterval != 900*time.Second || b.KeyChangeInterval != 15*time.Minute {
		t.Errorf("part 1 differences: %+v / %+v", a, b)
	}
}

// The preset's broadcast (1.13): with Secure Authentication on, a cold
// restart it enables for broadcast is still refused (critical, not
// authenticated), an immediate freeze it enables is carried out, and a
// warm restart it disables is discarded; without it, a direct operate no
// ack it enables is carried out.
//
// Covers: SIG-IPE-2675, SIG-IPE-2676
func TestCP1542PresetBroadcast(t *testing.T) {
	o := startCP1542(t, dnp3sim.CP1542Options{UpdateKey: mustHex(t, updateKeyHex)})
	d := o.Declared()
	if !slices.Contains(d.BroadcastFuncs, dnp3.FCColdRestart) || slices.Contains(d.BroadcastFuncs, dnp3.FCWarmRestart) {
		t.Fatalf("broadcast functions %v", d.BroadcastFuncs)
	}
	before := o.Security()[dnp3.StatDiscarded]
	o.Broadcast(dnp3.Fragment{Control: dnp3.AppFIR | dnp3.AppFIN | 1, Func: dnp3.FCColdRestart}.Encode())
	o.Broadcast(dnp3.Fragment{Control: dnp3.AppFIR | dnp3.AppFIN | 2, Func: dnp3.FCDirectOperateNR, Objects: latch(t)}.Encode())
	deadline := time.Now().Add(3 * time.Second)
	for o.Security()[dnp3.StatDiscarded] < before+2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := o.Security()[dnp3.StatDiscarded] - before; n != 2 || len(o.Controls()) != 0 {
		t.Fatalf("under SA: %d discarded, %d controls", n, len(o.Controls()))
	}
	plain := startCP1542(t, dnp3sim.CP1542Options{})
	plain.Broadcast(dnp3.Fragment{Control: dnp3.AppFIR | dnp3.AppFIN | 3, Func: dnp3.FCWarmRestart}.Encode())
	plain.Broadcast(dnp3.Fragment{Control: dnp3.AppFIR | dnp3.AppFIN | 4, Func: dnp3.FCDirectOperateNR, Objects: latch(t)}.Encode())
	for len(plain.Controls()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(plain.Controls()) != 1 {
		t.Fatalf("without SA: %d controls", len(plain.Controls()))
	}
}

func latch(t *testing.T) []byte {
	t.Helper()
	b, err := dnp3.EncodeBlock(12, 1, dnp3.Q8Index8, []dnp3.Point{{Index: 0, CROB: dnp3.CROB{Code: dnp3.OpLatchOn, Count: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Our outstation answers reads of its time (g50v1, qualifier 07, count
// 1: the host clock corrected by the last synchronisation) and of the
// internal indications (g80v1, start-stop: index n is IIN bit n).
//
// Covers: SIG-IPE-2679
func TestOutstationReadsTimeAndIIN(t *testing.T) {
	ctx := context.Background()
	o := startCP1542(t, dnp3sim.CP1542Options{})
	m, err := dnp3.Dial(ctx, dnp3.MasterConfig{URL: o.URL(), MasterAddress: 1, OutstationAddress: 4, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	// Synchronise to a clock one hour ahead, then read it back.
	ahead := time.Now().Add(time.Hour)
	w, _ := dnp3.EncodeBlock(50, 1, dnp3.Q8Count, []dnp3.Point{{Value: ahead}})
	if _, err := m.Request(ctx, dnp3.FCWrite, w); err != nil {
		t.Fatal(err)
	}
	frags, err := m.Request(ctx, dnp3.FCRead, dnp3.AppendHeader(nil, 50, 1, dnp3.Q8Count, 1, 0))
	if err != nil {
		t.Fatal(err)
	}
	var got time.Time
	for _, f := range frags {
		bl, _ := dnp3.ParseObjects(f.Objects, true)
		for _, b := range bl {
			if b.Header.Group == 50 && len(b.Points) == 1 {
				got, _ = b.Points[0].Value.(time.Time)
			}
		}
	}
	if d := got.Sub(ahead); d < -2*time.Second || d > 2*time.Second {
		t.Fatalf("g50v1 read %v, want about %v", got, ahead)
	}
	// IIN1.7 (restart) is set until cleared; index 4 (need time) is clear
	// after the synchronisation.
	frags, err = m.Request(ctx, dnp3.FCRead, dnp3.AppendHeader(nil, 80, 1, dnp3.Q8StartStop, 0, 15))
	if err != nil {
		t.Fatal(err)
	}
	bits := map[uint32]bool{}
	for _, f := range frags {
		bl, _ := dnp3.ParseObjects(f.Objects, true)
		for _, b := range bl {
			if b.Header.Group == 80 {
				for _, p := range b.Points {
					bits[p.Index], _ = p.Value.(bool)
				}
			}
		}
	}
	if len(bits) != 16 || bits[4] || bits[7] != (m.IIN()&dnp3.IINDeviceRestart != 0) {
		t.Errorf("g80v1 read %v (IIN %04X)", bits, uint16(m.IIN()))
	}
	// A range beyond the 16 bits is refused.
	if _, err := m.Request(ctx, dnp3.FCRead, dnp3.AppendHeader(nil, 80, 1, dnp3.Q8StartStop, 0, 16)); err == nil {
		t.Error("g80v1 index 16 read accepted")
	}
}
