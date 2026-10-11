// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/dnp3"
)

// syncBuf is a goroutine-safe output buffer.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// start runs the command with args until the test ends and returns where
// it listens.
func start(t *testing.T, args ...string) (running, *syncBuf) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	out := &syncBuf{}
	got := make(chan running, 1)
	done := make(chan error, 1)
	go func() { done <- run(ctx, args, out, func(r running) { got <- r }) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("run: %v", err)
		}
	})
	select {
	case r := <-got:
		return r, out
	case err := <-done:
		t.Fatalf("run ended: %v (%s)", err, out)
	case <-time.After(5 * time.Second):
		t.Fatal("the simulator did not start")
	}
	return running{}, nil
}

func dial(t *testing.T, url string, outstation uint16, auth *dnp3.Auth) *dnp3.Master {
	t.Helper()
	m, err := dnp3.Dial(context.Background(), dnp3.MasterConfig{URL: url, MasterAddress: 1, OutstationAddress: outstation, Timeout: 2 * time.Second, Auth: auth})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func values(t *testing.T, frags []dnp3.Fragment) map[[2]uint32]any {
	t.Helper()
	out := map[[2]uint32]any{}
	for _, f := range frags {
		bl, err := dnp3.ParseObjects(f.Objects, true)
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range bl {
			for _, p := range b.Points {
				out[[2]uint32{uint32(p.Group), p.Index}] = p.Value
			}
		}
	}
	return out
}

// The demo outstation answers an integrity poll with its database, the
// values move and report events, and a latch command reaches the output.
func TestRunnerDemo(t *testing.T) {
	r, out := start(t, "-listen", "127.0.0.1:0", "-report", "50ms")
	if !strings.Contains(out.String(), "outstation 10 (master 1) at tcp://127.0.0.1:") {
		t.Errorf("output %q", out)
	}
	m := dial(t, r.URL, 10, nil)
	ctx := context.Background()
	frags, err := m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(1, 2, 3, 0))
	if err != nil {
		t.Fatal(err)
	}
	v := values(t, frags)
	if v[[2]uint32{30, 1}] != 12.25 || v[[2]uint32{40, 0}] == nil || v[[2]uint32{10, 0}] != false {
		t.Fatalf("integrity poll %v", v)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		frags, err = m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(2))
		if err == nil && values(t, frags)[[2]uint32{32, 0}] != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no analog event reported: %v", err)
		}
		time.Sleep(60 * time.Millisecond)
	}
	op, _ := dnp3.EncodeBlock(12, 1, dnp3.Q8Index8, []dnp3.Point{{Index: 0, CROB: dnp3.CROB{Code: dnp3.OpLatchOn, Count: 1}}})
	if _, err := m.Request(ctx, dnp3.FCDirectOperate, op); err != nil {
		t.Fatal(err)
	}
	if r.Sim.Get(10, 0).V != 1 {
		t.Error("the latch did not reach the breaker output")
	}
}

// With -auth the outstation challenges critical requests; a master with
// the same update key changes the session keys and operates.
func TestRunnerSecureAuthentication(t *testing.T) {
	const key = "00112233445566778899aabbccddeeff"
	r, _ := start(t, "-listen", "127.0.0.1:0", "-report", "0", "-auth", key)
	a, err := dnp3.NewAuth(&dnp3.AuthConfig{UpdateKey: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}})
	if err != nil {
		t.Fatal(err)
	}
	m := dial(t, r.URL, 10, a)
	ctx := context.Background()
	if err := m.ChangeSessionKeys(ctx); err != nil {
		t.Fatal(err)
	}
	op, _ := dnp3.EncodeBlock(12, 1, dnp3.Q8Index8, []dnp3.Point{{Index: 0, CROB: dnp3.CROB{Code: dnp3.OpLatchOn, Count: 1}}})
	if _, err := m.Request(ctx, dnp3.FCDirectOperate, op); err != nil {
		t.Fatal(err)
	}
	if ok, _, _ := r.Sim.AuthStats(); ok == 0 || r.Sim.Get(10, 0).V != 1 {
		t.Errorf("authenticated operate: %d successes, output %v", ok, r.Sim.Get(10, 0).V)
	}
}

// A preset runs at its own addresses (cp1243-1: outstation 4).
func TestRunnerPreset(t *testing.T) {
	r, out := start(t, "-preset", "cp1243-1", "-listen", "127.0.0.1:0")
	if !strings.Contains(out.String(), "outstation 4 (master 1)") {
		t.Errorf("output %q", out)
	}
	m := dial(t, r.URL, 4, nil)
	if _, err := m.Request(context.Background(), dnp3.FCRead, dnp3.ClassRequest(0)); err != nil {
		t.Fatal(err)
	}
}

func TestRunnerFlags(t *testing.T) {
	for _, args := range [][]string{
		{"-auth", "00"},
		{"-preset", "nope"},
		{"-udp", "-cert", "x.pem", "-key", "x.key"},
		{"-address", "70000"},
		{"extra"},
	} {
		if err := run(context.Background(), args, &syncBuf{}, nil); err == nil {
			t.Errorf("%q accepted", args)
		}
	}
	if err := run(context.Background(), []string{"-h"}, &syncBuf{}, nil); !errors.Is(err, flag.ErrHelp) {
		t.Errorf("-h: %v", err)
	}
}
