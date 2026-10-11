// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package dnp3_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cB-Sigma/dnp3"
	"github.com/cB-Sigma/iotsec"
)

// The seams the library takes from iotsec, each with a stand-in here:
// the dialer, the TLS client and its keepalive, and the role authority.

// A configured Dialer opens the master's TCP connection.
func TestMasterUsesDialer(t *testing.T) {
	s := startSim(t)
	var calls atomic.Int32
	d := iotsec.DialerFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		calls.Add(1)
		var nd net.Dialer
		return nd.DialContext(ctx, network, addr)
	})
	m, err := dnp3.Dial(context.Background(), dnp3.MasterConfig{URL: s.URL(), MasterAddress: 1, OutstationAddress: 10, Timeout: time.Second, Dialer: d})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if _, err := m.Request(context.Background(), dnp3.FCRead, dnp3.ClassRequest(0)); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Errorf("dialer called %d times", calls.Load())
	}
	refuse := iotsec.DialerFunc(func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("egress refused") })
	if _, err := dnp3.Dial(context.Background(), dnp3.MasterConfig{URL: s.URL(), MasterAddress: 1, OutstationAddress: 10, Timeout: time.Second, Dialer: refuse}); err == nil {
		t.Error("a refusing dialer did not fail the connection")
	}
}

// kaConn is a "secured" connection that takes the protocol's keepalive,
// as a TLS profile with timed key updates does.
type kaConn struct {
	net.Conn
	mu sync.Mutex
	ka iotsec.Keepalive
}

func (c *kaConn) SetKeepalive(f iotsec.Keepalive) { c.mu.Lock(); c.ka = f; c.mu.Unlock() }

type kaTLS struct{ conns chan *kaConn }

func (k kaTLS) Client(_ context.Context, raw net.Conn, _ string) (net.Conn, error) {
	c := &kaConn{Conn: raw}
	k.conns <- c
	return c, nil
}

// The master hands the TLS client the dialled connection, registers
// REQUEST_LINK_STATUS as the keepalive, and the outstation receives it.
func TestMasterTLSKeepalive(t *testing.T) {
	s := startSim(t)
	tc := kaTLS{conns: make(chan *kaConn, 1)}
	m, err := dnp3.Dial(context.Background(), dnp3.MasterConfig{URL: s.URL(), MasterAddress: 1, OutstationAddress: 10, Timeout: time.Second, TLS: tc})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	c := <-tc.conns
	c.mu.Lock()
	ka := c.ka
	c.mu.Unlock()
	if ka == nil {
		t.Fatal("no keepalive registered")
	}
	if err := ka(); err != nil {
		t.Fatal(err)
	}
	eventually(t, 2*time.Second, "REQUEST_LINK_STATUS at the outstation", func() bool {
		return bytes.IndexByte(s.LinkFunctions(), dnp3.LinkRequestLinkStatus) >= 0
	})
	if _, err := dnp3.Dial(context.Background(), dnp3.MasterConfig{URL: "udp://127.0.0.1:20000", MasterAddress: 1, OutstationAddress: 10, TLS: tc}); err == nil {
		t.Error("TLS over UDP was accepted")
	}
}

// Without a role authority, g120v8 user certificates are refused.
func TestUserCertificateNeedsRoleAuthority(t *testing.T) {
	_, err := dnp3.VerifyUserCertificate(dnp3.UserCertificate{Method: 68, Type: dnp3.CertID, Cert: []byte{0x30, 0x00}}, nil, nil)
	if !errors.Is(err, dnp3.ErrNoRoleAuthority) {
		t.Fatalf("err %v", err)
	}
}
