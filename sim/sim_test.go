// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package sim_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/dnp3"
	"github.com/cB-Sigma/dnp3-sim/sim"
	"github.com/cB-Sigma/iotsec"
)

// The simulator on its own, driven by the library's master: these tests
// check the simulator's behaviour, so that the tests that use it as a
// peer rest on something tested.

func start(t *testing.T, tune func(*sim.Sim)) *sim.Sim {
	t.Helper()
	s := sim.New(10, 1)
	if tune != nil {
		tune(s)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
	return s
}

func dial(t *testing.T, s *sim.Sim, tune func(*dnp3.MasterConfig)) *dnp3.Master {
	t.Helper()
	cfg := dnp3.MasterConfig{URL: s.URL(), MasterAddress: 1, OutstationAddress: 10, Timeout: time.Second}
	if tune != nil {
		tune(&cfg)
	}
	m, err := dnp3.Dial(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func points(t *testing.T, frags []dnp3.Fragment) map[[2]uint32]dnp3.Point {
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

func waitFor(t *testing.T, what string, f func() bool) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if f() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

// Class 0 answers the static points with the default variations, the
// restart indication is set until the master clears it, and buffered
// events go out on a class poll and are dropped once confirmed.
func TestSimPollsAndEvents(t *testing.T) {
	s := start(t, nil)
	s.Set(1, 0, 1, 0x01)
	s.Set(30, 0, 230.5, 0x01)
	s.Set(20, 3, 42, 0x01)
	m := dial(t, s, nil)
	ctx := context.Background()
	frags, err := m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(0))
	if err != nil {
		t.Fatal(err)
	}
	p := points(t, frags)
	if p[[2]uint32{1, 0}].Value != true || p[[2]uint32{30, 0}].Value != 230.5 || p[[2]uint32{20, 3}].Value != 42.0 {
		t.Fatalf("class 0 %+v", p)
	}
	if p[[2]uint32{30, 0}].Var != 5 || p[[2]uint32{1, 0}].Var != 2 {
		t.Errorf("default static variations g1v%d g30v%d, want g1v2 g30v5", p[[2]uint32{1, 0}].Var, p[[2]uint32{30, 0}].Var)
	}
	if m.IIN()&dnp3.IINDeviceRestart == 0 || !s.Restarting() {
		t.Fatal("the restart indication is not set after start")
	}
	clr, _ := dnp3.EncodeBlock(80, 1, dnp3.Q8StartStop, []dnp3.Point{{Index: 7, Value: false}})
	if _, err := m.Request(ctx, dnp3.FCWrite, clr); err != nil || s.Restarting() {
		t.Fatalf("clearing the restart indication: %v, restarting %v", err, s.Restarting())
	}
	at := time.Now().Add(-time.Minute).Truncate(time.Millisecond)
	s.AddEvent(sim.Event{Group: 2, Var: 2, Index: 4, Value: 1, Flags: 0x01, Time: at, Class: 1})
	s.AddEvent(sim.Event{Group: 32, Var: 1, Index: 0, Value: 231, Flags: 0x01, Class: 2})
	if s.PendingEvents() != 2 {
		t.Fatalf("pending %d", s.PendingEvents())
	}
	frags, err = m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(1))
	if err != nil {
		t.Fatal(err)
	}
	if e := points(t, frags)[[2]uint32{2, 4}]; e.Value != true || !e.Time.Equal(at) {
		t.Fatalf("class 1 event %+v, want on at %v", e, at)
	}
	waitFor(t, "the class 1 event dropped", func() bool { return s.PendingEvents() == 1 })
	frags, _ = m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(2))
	if e := points(t, frags)[[2]uint32{32, 0}]; e.Value != 231.0 {
		t.Fatalf("class 2 event %+v", e)
	}
	if r := s.Requests(); len(r) < 4 || !strings.HasPrefix(r[0], "READ") || !slices.ContainsFunc(r, func(x string) bool { return strings.Contains(x, "g80v1") }) {
		t.Errorf("requests %q", r)
	}
}

// Select-before-operate latches a binary output and is recorded; a
// refusing control status fails the operate and leaves the output.
func TestSimControls(t *testing.T) {
	s := start(t, nil)
	s.Set(10, 0, 0, 0x01)
	m := dial(t, s, nil)
	ctx := context.Background()
	latch := func(code uint8) []byte {
		b, _ := dnp3.EncodeBlock(12, 1, dnp3.Q8Index8, []dnp3.Point{{Index: 0, CROB: dnp3.CROB{Code: code, Count: 1}}})
		return b
	}
	statusOK := func(fc byte, frags []dnp3.Fragment) error {
		if p := points(t, frags)[[2]uint32{12, 0}]; p.Status != 0 {
			return fmt.Errorf("function %d: control status %d", fc, p.Status)
		}
		return nil
	}
	if err := m.SelectOperate(ctx, latch(dnp3.OpLatchOn), 5*time.Second, statusOK); err != nil {
		t.Fatal(err)
	}
	if s.Get(10, 0).V != 1 {
		t.Fatal("the output did not latch on")
	}
	c := s.Controls()
	if len(c) == 0 || c[len(c)-1].Func != dnp3.FCOperate || c[len(c)-1].CROB.Code != dnp3.OpLatchOn || c[len(c)-1].Status != 0 {
		t.Fatalf("controls %+v", c)
	}
	s.SetControlStatus(0, 4) // NOT_SUPPORTED on operate
	if err := m.SelectOperate(ctx, latch(dnp3.OpLatchOff), 5*time.Second, statusOK); err == nil {
		t.Fatal("a refused operate succeeded")
	}
	if s.Get(10, 0).V != 1 {
		t.Error("a refused operate changed the output")
	}
}

// Unsolicited reporting: once the master enables a class, a new event of
// that class is sent unsolicited and the master's confirmation is counted.
func TestSimUnsolicited(t *testing.T) {
	s := start(t, nil)
	got := make(chan dnp3.Fragment, 4)
	m := dial(t, s, func(c *dnp3.MasterConfig) {
		c.OnUnsolicited = func(f dnp3.Fragment) {
			if len(f.Objects) > 0 {
				got <- f
			}
		}
	})
	ctx := context.Background()
	if _, err := m.Request(ctx, dnp3.FCEnableUnsolicited, dnp3.ClassRequest(1)); err != nil {
		t.Fatal(err)
	}
	if !s.UnsolicitedEnabled(1) || s.UnsolicitedEnabled(2) {
		t.Fatal("class 1 only should be enabled")
	}
	s.AddEvent(sim.Event{Group: 2, Var: 1, Index: 2, Value: 1, Flags: 0x01, Class: 1})
	select {
	case f := <-got:
		if p := points(t, []dnp3.Fragment{f})[[2]uint32{2, 2}]; p.Value != true {
			t.Fatalf("unsolicited %+v", p)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no unsolicited response")
	}
	waitFor(t, "the unsolicited confirmation", func() bool { return s.UnsolicitedConfirms() >= 1 })
}

// The failure knobs: an ignoring outstation times the request out; after
// Stop and Start it is reachable again at the same address.
func TestSimIgnoreStopStart(t *testing.T) {
	s := start(t, nil)
	url := s.URL()
	m := dial(t, s, func(c *dnp3.MasterConfig) { c.Timeout = 300 * time.Millisecond })
	ctx := context.Background()
	s.SetIgnore(true)
	if _, err := m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(0)); err == nil {
		t.Fatal("an ignored request was answered")
	}
	s.SetIgnore(false)
	s.Stop()
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	if s.URL() != url {
		t.Fatalf("restarted at %s, was %s", s.URL(), url)
	}
	m2 := dial(t, s, nil)
	if _, err := m2.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(0)); err != nil {
		t.Fatalf("after restart: %v", err)
	}
}

// The need-time indication is reported until the master writes the time,
// which the simulator keeps as its clock.
func TestSimTimeSync(t *testing.T) {
	s := start(t, func(s *sim.Sim) { s.SetNeedTime(true) })
	m := dial(t, s, nil)
	ctx := context.Background()
	if _, err := m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(0)); err != nil || m.IIN()&dnp3.IINNeedTime == 0 {
		t.Fatalf("need time not reported: %v %v", err, m.IIN())
	}
	when := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	w, _ := dnp3.EncodeBlock(50, 1, dnp3.Q8Count, []dnp3.Point{{Value: when}})
	if _, err := m.Request(ctx, dnp3.FCWrite, w); err != nil {
		t.Fatal(err)
	}
	c, ok := s.Clock()
	if !ok || c.Sub(when) < 0 || c.Sub(when) > 5*time.Second {
		t.Fatalf("clock %v %v, want about %v", c, ok, when)
	}
	if _, err := m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(0)); err != nil || m.IIN()&dnp3.IINNeedTime != 0 {
		t.Fatalf("need time still reported: %v %v", err, m.IIN())
	}
}

// Over UDP with a fixed reply port the simulator answers to that port
// (as many device profiles do); a master listening there (LocalPort, an
// unconnected socket taking every datagram from the outstation's
// address) hears it.
//
// Covers: SIG-CMD-212
func TestSimUDPReplyPort(t *testing.T) {
	port := freeUDPPort(t)
	s := start(t, func(s *sim.Sim) { s.Network, s.ReplyPort = "udp", port })
	s.Set(30, 0, 12.5, 0x01)
	if !strings.HasPrefix(s.URL(), "udp://") {
		t.Fatalf("url %s", s.URL())
	}
	m := dial(t, s, func(c *dnp3.MasterConfig) { c.LocalPort = port })
	frags, err := m.Request(context.Background(), dnp3.FCRead, dnp3.ClassRequest(0))
	if err != nil || points(t, frags)[[2]uint32{30, 0}].Value != 12.5 {
		t.Fatalf("read over UDP with replies to port %d: %v", port, err)
	}
}

// With a TLS server set, the simulator serves TCP under it; the master
// connects with a TLS client (crypto/tls here) and polls.
func TestSimTLS(t *testing.T) {
	cert, pool := selfSigned(t, "rtu.test")
	s := start(t, func(s *sim.Sim) {
		s.TLS = iotsec.StdTLS{Config: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}
	})
	s.Set(30, 0, 7, 0x01)
	m := dial(t, s, func(c *dnp3.MasterConfig) {
		c.TLS = iotsec.StdTLS{Config: &tls.Config{RootCAs: pool, ServerName: "rtu.test", MinVersion: tls.VersionTLS12}}
	})
	frags, err := m.Request(context.Background(), dnp3.FCRead, dnp3.ClassRequest(0))
	if err != nil || points(t, frags)[[2]uint32{30, 0}].Value != 7.0 {
		t.Fatalf("read over TLS: %v", err)
	}
	// A client that does not trust the certificate is refused.
	bad := dnp3.MasterConfig{URL: s.URL(), MasterAddress: 1, OutstationAddress: 10, Timeout: time.Second,
		TLS: iotsec.StdTLS{Config: &tls.Config{RootCAs: x509.NewCertPool(), ServerName: "rtu.test"}}}
	if m2, err := dnp3.Dial(context.Background(), bad); err == nil {
		_ = m2.Close()
		t.Fatal("an untrusted server was accepted")
	}
}

// The presets start and close, and answer a poll.
func TestSimPresets(t *testing.T) {
	ctx := context.Background()
	key := make([]byte, 16)
	c43, err := sim.StartCP1243(ctx, sim.CP1243Options{UpdateKey: key})
	if err != nil {
		t.Fatal(err)
	}
	defer c43.Close()
	c42, err := sim.StartCP1542(ctx, sim.CP1542Options{UpdateKey: key})
	if err != nil {
		t.Fatal(err)
	}
	defer c42.Close()
	if c43.Declared().MaxFragment == 0 || c42.Declared().MaxFragment == 0 {
		t.Error("declared profiles are empty")
	}
	for _, u := range []string{c43.URL(), c42.URL()} {
		if !strings.HasPrefix(u, "tcp://127.0.0.1:") {
			t.Errorf("url %s", u)
		}
	}
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	for range 20 {
		s := sim.New(99, 98)
		s.Network = "udp"
		if err := s.Start(); err != nil {
			continue
		}
		u := s.URL()
		s.Stop()
		var p int
		if i := strings.LastIndexByte(u, ':'); i > 0 {
			for _, r := range u[i+1:] {
				p = p*10 + int(r-'0')
			}
		}
		if p > 0 {
			return p
		}
	}
	t.Fatal("no free UDP port")
	return 0
}

func selfSigned(t *testing.T, name string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(c)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, pool
}
