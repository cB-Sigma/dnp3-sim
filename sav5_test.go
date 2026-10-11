package dnp3_test

import (
	"bytes"
	"context"
	"crypto/dsa" //nolint:staticcheck // update key change methods 67 to 69
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/dnp3"
	dnp3sim "github.com/cB-Sigma/dnp3-sim/sim"
)

// dial connects a master to the simulator with Secure Authentication
// settings c (nil: none) and extra master settings.
func dial(t *testing.T, sim *dnp3sim.Sim, c *dnp3.AuthConfig, extra func(*dnp3.MasterConfig)) *dnp3.Master {
	t.Helper()
	var a *dnp3.Auth
	if c != nil {
		var err error
		if a, err = dnp3.NewAuth(c); err != nil {
			t.Fatal(err)
		}
	}
	cfg := dnp3.MasterConfig{URL: sim.URL(), MasterAddress: 1, OutstationAddress: 10, Timeout: 500 * time.Millisecond, Auth: a}
	if extra != nil {
		extra(&cfg)
	}
	m, err := dnp3.Dial(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func crobObjs(t *testing.T, idx uint32) []byte {
	t.Helper()
	b, err := dnp3.EncodeBlock(12, 1, dnp3.Q16Index16, []dnp3.Point{{Index: idx, CROB: dnp3.CROB{Code: dnp3.OpLatchOn, Count: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Covers: SIG-IPE-1599
func TestSAv5SessionKeyChangeLayout(t *testing.T) {
	// Table A-7: 128-bit keys and a key status with 4 octets of challenge
	// data (15 octets) wrap to 2 + 16 + 16 + 15 + 7 padding + 8 = 64.
	ks := dnp3.AppendKeyStatus(nil, dnp3.KeyStatus{KSQ: 1, User: 1, KeyWrap: 1, Status: dnp3.KeyStatusNotInit, Challenge: []byte{1, 2, 3, 4}})
	if len(ks) != 15 {
		t.Fatalf("key status is %d octets", len(ks))
	}
	plain := dnp3.SessionKeyData(make([]byte, 16), make([]byte, 16), ks)
	w, err := dnp3.WrapKey(mustHex(t, updateKeyHex), plain)
	if err != nil || len(plain) != 56 || len(w) != 64 {
		t.Fatalf("plain %d, wrapped %d: %v", len(plain), len(w), err)
	}
	// The key wrap data carries the key status without its MAC (Table A-5).
	withMAC := dnp3.AppendKeyStatus(nil, dnp3.KeyStatus{KSQ: 2, User: 1, KeyWrap: 1, Status: dnp3.KeyStatusOK, MAL: 4, Challenge: []byte{9, 9, 9, 9}, MAC: bytes.Repeat([]byte{7}, 16)})
	k, err := dnp3.ParseKeyStatus(withMAC)
	if err != nil || !bytes.Equal(k.Unauthenticated(withMAC), withMAC[:15]) {
		t.Fatalf("%+v %v", k, err)
	}
	// Table A-6: keys go lowest index first.
	aesKey := mustHex(t, "2b7e151628aed2a6abf7158809cf4f3c")
	d := dnp3.SessionKeyData(aesKey, aesKey, nil)
	if d[2] != 0x2b || d[17] != 0x3c || binary.LittleEndian.Uint16(d) != 16 {
		t.Fatalf("% X", d)
	}

	// Against the outstation: the first KSQ sent is 1, it advances for
	// the status request and the change; the key status after the change
	// carries a MAC over the whole key change fragment, which the master
	// checks, and a later status request's MAC is checked with the last
	// monitoring key (7.5.4.2).
	sim := authSim(t, updateKeyHex)
	m := dial(t, sim, &dnp3.AuthConfig{UpdateKey: hexKey(updateKeyHex)}, nil)
	ctx := context.Background()
	if err := m.ChangeSessionKeys(ctx); err != nil {
		t.Fatal(err)
	}
	if sim.KSQ() != 2 {
		t.Errorf("KSQ after one change is %d, want 2", sim.KSQ())
	}
	if err := m.ChangeSessionKeys(ctx); err != nil {
		t.Fatalf("second change (key status with MAC): %v", err)
	}
	if _, _, ch := sim.AuthStats(); ch != 2 || sim.KSQ() != 4 {
		t.Errorf("changes %d, KSQ %d", ch, sim.KSQ())
	}
	if st := m.Auth().Statistics(); st["session-key-changes"] != 2 || st["failed-session-key-changes"] != 0 {
		t.Errorf("master statistics %v", st)
	}
}

// Covers: SIG-IPE-1600
func TestSAv5AggressiveMode(t *testing.T) {
	sim := authSim(t, updateKeyHex)
	m := dial(t, sim, &dnp3.AuthConfig{UpdateKey: hexKey(updateKeyHex), AggressiveMode: true}, nil)
	ctx := context.Background()
	if err := m.ChangeSessionKeys(ctx); err != nil {
		t.Fatal(err)
	}
	// The first critical request after a key change is challenged
	// (7.5.3.3); the next ones go in aggressive mode with CSQ 2 and 3.
	for i := range 3 {
		if _, err := m.Request(ctx, dnp3.FCDirectOperate, crobObjs(t, 0)); err != nil {
			t.Fatalf("operate %d: %v", i, err)
		}
	}
	reqs, _ := sim.AggressiveStats()
	ok, failed, _ := sim.AuthStats()
	if reqs != 2 || ok != 3 || failed != 0 {
		t.Fatalf("aggressive requests %d, verified %d, failed %d", reqs, ok, failed)
	}
	if n := len(sim.Controls()); n != 3 {
		t.Fatalf("%d controls ran", n)
	}
	if !slices.Contains(sim.Requests(), "DIRECT_OPERATE g120v3 g12v1 g120v9") {
		t.Errorf("requests %q", sim.Requests())
	}
	// A new key change: challenge-reply first again.
	if err := m.ChangeSessionKeys(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Request(ctx, dnp3.FCDirectOperate, crobObjs(t, 0)); err != nil {
		t.Fatal(err)
	}
	if r, _ := sim.AggressiveStats(); r != 2 {
		t.Errorf("aggressive mode used right after a key change (%d)", r)
	}
	// The outstation refuses aggressive mode (error 4): the request fails
	// with the reason and the master stops using it; the next request is
	// challenged normally.
	sim.SetAggressive(false)
	_, err := m.Request(ctx, dnp3.FCDirectOperate, crobObjs(t, 0))
	var ae *dnp3.AuthError
	if !errors.As(err, &ae) || ae.Code != dnp3.AuthErrAggressiveNotSupp || !strings.Contains(err.Error(), "aggressive mode not supported") {
		t.Fatalf("refused aggressive request: %v", err)
	}
	if _, err := m.Request(ctx, dnp3.FCDirectOperate, crobObjs(t, 0)); err != nil {
		t.Fatalf("after the refusal: %v", err)
	}
	if n := len(sim.Controls()); n != 5 {
		t.Errorf("%d controls ran, want 5", n)
	}
	// A request without response (DIRECT_OPERATE_NR) with SA: the master
	// waits for a possible challenge and answers it.
	if _, err := m.Request(ctx, dnp3.FCDirectOperateNR, crobObjs(t, 1)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 2*time.Second, "the no-ack control", func() bool { return len(sim.Controls()) == 6 })
}

// Covers: SIG-IPE-1601
func TestSAv5AggressiveConfirmAndResponseChallenges(t *testing.T) {
	sim := authSim(t, updateKeyHex)
	sim.AskAggressiveConfirms(true)
	m := dial(t, sim, &dnp3.AuthConfig{UpdateKey: hexKey(updateKeyHex)}, nil)
	ctx := context.Background()
	if err := m.ChangeSessionKeys(ctx); err != nil {
		t.Fatal(err)
	}
	// An event response ending with a challenge (CON set): the master
	// confirms in aggressive mode even though aggressive mode is off
	// (7.6.1.4.7), the events are confirmed and the challenge is not data.
	sim.AddEvent(dnp3sim.Event{Group: 32, Var: 5, Index: 0, Value: 7, Flags: 1, Class: 1})
	frags, err := m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(1, 2, 3))
	if err != nil {
		t.Fatal(err)
	}
	eventually(t, 2*time.Second, "the aggressive-mode confirmation", func() bool { _, c := sim.AggressiveStats(); return c == 1 })
	if sim.PendingEvents() != 0 {
		t.Error("the events were not confirmed")
	}
	blocks, _ := dnp3.ParseObjects(frags[0].Objects, true)
	for _, b := range blocks {
		if b.Header.Group == 120 {
			t.Errorf("the challenge was left in the response data: %v", b.Header)
		}
	}
	sim.AskAggressiveConfirms(false)

	// The master challenges responses: each response with objects is
	// authenticated by the outstation's reply before it is used.
	m2 := dial(t, sim, &dnp3.AuthConfig{UpdateKey: hexKey(updateKeyHex), ChallengeResponses: true}, nil)
	if err := m2.ChangeSessionKeys(ctx); err != nil {
		t.Fatal(err)
	}
	sim.Set(30, 0, 42, 1)
	frags, err = m2.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(0))
	if err != nil || len(frags) == 0 {
		t.Fatalf("challenged read: %v", err)
	}
	if st := m2.Auth().Statistics(); st["successful-authentications"] == 0 {
		t.Errorf("no response authenticated: %v", st)
	}
	// The outstation now answers in aggressive mode: its MAC is checked
	// against the master's last challenge.
	sim.AggressiveResponses(true)
	frags, err = m2.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(0))
	if err != nil || len(frags) == 0 {
		t.Fatalf("aggressive-mode response: %v", err)
	}
	blocks, _ = dnp3.ParseObjects(frags[0].Objects, true)
	if len(blocks) == 0 || blocks[0].Header.Group == 120 {
		t.Fatalf("aggressive-mode objects left in the data: %+v", blocks)
	}
	if !strings.Contains(strings.Join(sim.Requests(), ";"), "AUTH_REQUEST g120v1") {
		t.Errorf("the master never challenged: %q", sim.Requests())
	}
}

func updateKeyTest(t *testing.T, method uint8) {
	sim := authSim(t, updateKeyHex)
	ctx := context.Background()
	m := dial(t, sim, &dnp3.AuthConfig{UpdateKey: hexKey(updateKeyHex)}, nil)
	if err := m.ChangeSessionKeys(ctx); err != nil {
		t.Fatal(err)
	}
	c := dnp3.UpdateKeyChange{UserName: "alice", Role: dnp3.RoleOperator, Expiry: 30, SCS: 1, Outstation: "rtu-9"}
	switch method {
	case dnp3.KeyChangeAES128SHA1, dnp3.KeyChangeAES256SHA256:
		key := make([]byte, 16)
		if method == dnp3.KeyChangeAES256SHA256 {
			key = make([]byte, 32)
		}
		_, _ = rand.Read(key)
		sim.SetAuthority("rtu-9", key, nil, nil)
		c.Authority = dnp3.SymmetricAuthority{KeyChangeMethod: method, Key: key}
		// A wrong authority key: invalid certification data (error 10).
		bad := c
		bad.Authority = dnp3.SymmetricAuthority{KeyChangeMethod: method, Key: make([]byte, len(key))}
		var ae *dnp3.AuthError
		if err := m.ChangeUpdateKey(ctx, bad); !errors.As(err, &ae) || ae.Code != dnp3.AuthErrInvalidCertData {
			t.Fatalf("wrong authority key: %v", err)
		}
	default:
		var params dsa.Parameters
		if err := dsa.GenerateParameters(&params, rand.Reader, dsa.L1024N160); err != nil {
			t.Fatal(err)
		}
		authKey, userKey := &dsa.PrivateKey{PublicKey: dsa.PublicKey{Parameters: params}}, &dsa.PrivateKey{PublicKey: dsa.PublicKey{Parameters: params}}
		_ = dsa.GenerateKey(authKey, rand.Reader)
		_ = dsa.GenerateKey(userKey, rand.Reader)
		pub, err := dnp3.MarshalDSAPublicKey(&userKey.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if back, err := x509.ParsePKIXPublicKey(pub); err != nil || back.(*dsa.PublicKey).Y.Cmp(userKey.Y) != 0 {
			t.Fatalf("the SubjectPublicKeyInfo does not parse back: %v", err)
		}
		ostn, _ := rsa.GenerateKey(rand.Reader, 1024)
		sim.SetAuthority("rtu-9", nil, &authKey.PublicKey, ostn)
		c.Authority = dnp3.AsymmetricAuthority{KeyChangeMethod: method, Key: authKey}
		c.UserKey, c.UserPublicKey, c.OutstationKey = userKey, pub, &ostn.PublicKey
	}
	// An update key change for a user never added: unknown user (11).
	var ae *dnp3.AuthError
	if err := m.ChangeUpdateKey(ctx, dnp3.UpdateKeyChange{Authority: c.Authority, Operation: dnp3.UserChange, SCS: 0, UserName: "", Outstation: "rtu-9"}); err == nil {
		t.Fatal("an update key change without a user name was sent")
	}
	if err := m.ChangeUpdateKey(ctx, c); err != nil {
		t.Fatalf("update key change: %v", err)
	}
	usr, role, ok := sim.User("alice")
	if !ok || role != dnp3.RoleOperator || usr < 2 {
		t.Fatalf("user alice: %d %d %v", usr, role, ok)
	}
	// The new key and user number are in use: the session keys were
	// changed with them and a control is authenticated.
	if _, err := m.Request(ctx, dnp3.FCDirectOperate, crobObjs(t, 0)); err != nil {
		t.Fatalf("control as alice: %v", err)
	}
	// A viewer may not operate (Table 7-12): error 7.
	c.SCS, c.Role, c.UserName = 2, dnp3.RoleViewer, "bob"
	if err := m.ChangeUpdateKey(ctx, c); err != nil {
		t.Fatalf("second user: %v", err)
	}
	_, err := m.Request(ctx, dnp3.FCDirectOperate, crobObjs(t, 0))
	if !errors.As(err, &ae) || ae.Code != dnp3.AuthErrAuthorization {
		t.Fatalf("viewer control: %v", err)
	}
	if st := m.Auth().Statistics(); st["update-key-changes"] != 2 {
		t.Errorf("statistics %v", st)
	}
}

// Covers: SIG-IPE-1602
func TestSAv5UpdateKeyChangeSymmetric(t *testing.T) {
	for _, method := range []uint8{dnp3.KeyChangeAES256SHA256, dnp3.KeyChangeAES128SHA1} {
		t.Run(string(rune('0'+method)), func(t *testing.T) { updateKeyTest(t, method) })
	}
}

// Covers: SIG-IPE-1603
func TestSAv5UpdateKeyChangeAsymmetric(t *testing.T) {
	updateKeyTest(t, dnp3.KeyChangeRSA1024SHA1)
}

// Covers: SIG-IPE-1583
func TestIEEE1815LinkConfirmedUserData(t *testing.T) {
	sim := startSim(t)
	sim.Set(30, 0, 5, 1)
	m := dial(t, sim, nil, func(c *dnp3.MasterConfig) { c.LinkConfirm, c.LinkRetries = true, 1 })
	ctx := context.Background()
	for range 3 {
		if _, err := m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(0)); err != nil {
			t.Fatal(err)
		}
	}
	fcs := sim.LinkFunctions()
	if len(fcs) < 4 || fcs[0] != dnp3.LinkResetLinkStates || fcs[1] != dnp3.LinkConfirmedUserData {
		t.Fatalf("link functions %v", fcs)
	}
	if slices.Contains(fcs[1:], byte(dnp3.LinkResetLinkStates)) {
		t.Errorf("the link was reset more than once: %v", fcs)
	}
}

// Covers: SIG-IPE-1584
func TestIEEE1815KeepAlive(t *testing.T) {
	sim := startSim(t)
	m := dial(t, sim, nil, func(c *dnp3.MasterConfig) { c.KeepAlive = 150 * time.Millisecond })
	eventually(t, 3*time.Second, "a keep-alive REQUEST_LINK_STATUS", func() bool {
		return slices.Contains(sim.LinkFunctions(), byte(dnp3.LinkRequestLinkStatus))
	})
	select {
	case <-m.Done():
		t.Fatalf("the association ended although the link status was answered: %v", m.Err())
	case <-time.After(400 * time.Millisecond):
	}
	// A peer that accepts the connection and never answers: the
	// keep-alive ends it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			defer c.Close()
			_, _ = c.Read(make([]byte, 1024))
			time.Sleep(3 * time.Second)
		}
	}()
	m2, err := dnp3.Dial(context.Background(), dnp3.MasterConfig{URL: "tcp://" + ln.Addr().String(), MasterAddress: 1, OutstationAddress: 10, Timeout: 200 * time.Millisecond, KeepAlive: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer m2.Close()
	select {
	case <-m2.Done():
		if !strings.Contains(m2.Err().Error(), "keep-alive") {
			t.Errorf("ended with %v", m2.Err())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a silent peer was not detected")
	}
}

// Covers: SIG-IPE-1586
func TestIEEE1815MaxRequestFragment(t *testing.T) {
	sim := startSim(t)
	m := dial(t, sim, nil, func(c *dnp3.MasterConfig) { c.MaxRequest = 249 })
	var pts []dnp3.Point
	for i := range 30 {
		pts = append(pts, dnp3.Point{Index: uint32(i), CROB: dnp3.CROB{Code: 3, Count: 1}})
	}
	objs, _ := dnp3.EncodeBlock(12, 1, dnp3.Q16Index16, pts)
	if _, err := m.Request(context.Background(), dnp3.FCDirectOperate, objs); err == nil || !strings.Contains(err.Error(), "at most 249") {
		t.Fatalf("oversized request: %v", err)
	}
	if len(sim.Requests()) != 0 {
		t.Error("the oversized request was sent")
	}
}
