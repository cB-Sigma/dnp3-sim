package sim

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/cB-Sigma/dnp3"
	"github.com/cB-Sigma/iotsec"
)

// Preset cp1542sp-1-irc: an outstation that behaves as the Siemens CP
// 1542SP-1 IRC (ET 200SP / S7-1500 DNP3 communication processor) device
// profile, document version 2.2 (2022-11-28, on the 2016 template, XML
// schema 2.11.00), declares. Like cp1243-1 it runs the dnp3 package's
// outstation with the declared settings and a filter built from the
// implementation table (part 4). The profile gives no point list (part
// 5), so the database is a small one of our own over every declared data
// type. Where the profile is silent or contradicts itself or IEEE
// 1815-2012 the choice is recorded in the findings register (F-1450 on).

// CP1542TLSSuites are the TLS 1.2 cipher suites of 1.12.11 that the IEC
// 62351-3 profile (as the iec62351 tlsprofile implements it) also offers; the preset narrows its
// TLS 1.2 offer to them. The profile's CCM and ChaCha20 suites are not in
// ours, and TLS_RSA_WITH_AES_128_CBC_SHA256 of ours is not in the
// profile's (F-1454).
var CP1542TLSSuites = []string{
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
}

// CP1542TLS13Suites are the TLS 1.3 suites of 1.12.11 (AES-GCM); the
// preset narrows the profile's TLS 1.3 offer to them, leaving out its
// AES-128-CCM and ChaCha20-Poly1305, which the device does not list
// (F-1454).
var CP1542TLS13Suites = []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"}

// CP1542Declared is the CP 1542SP-1 IRC device profile v2.2.
func CP1542Declared() Declared {
	var o []DeclaredObject
	// g0: the attributes of the table, read with start-stop; 254 and 255
	// also with "all".
	for _, v := range []uint8{212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229,
		231, 232, 233, 237, 238, 239, 240, 241, 242, 243, 246, 247, 248, 249, 250, 252} {
		o = append(o, DeclaredObject{Group: 0, Var: v, Funcs: rd, Quals: []byte{dnp3.Q8StartStop}})
	}
	o = append(o, objs(0, []uint8{254, 255}, rd, []byte{dnp3.Q8StartStop, dnp3.QAll})...)
	o = append(o, objs(1, []uint8{1, 2}, rd, q0016)...)
	o = append(o, objs(2, []uint8{1, 2, 3}, rd, qEvent)...) // v3 without g51 (F-1452)
	o = append(o, objs(3, []uint8{1, 2}, rd, q0016)...)
	o = append(o, objs(4, []uint8{1, 2, 3}, rd, qEvent)...)
	o = append(o, objs(10, []uint8{1, 2}, rd, q0016)...)
	o = append(o, objs(11, []uint8{1, 2}, rd, q0016)...) // static qualifiers as printed (F-608 again)
	o = append(o, objs(12, []uint8{1}, ctl, qIndex)...)  // latch on/off only (F-1451)
	o = append(o, objs(20, []uint8{1, 2}, rd, q0016)...)
	o = append(o, objs(21, []uint8{1, 2, 5, 6}, rd, q0016)...)
	o = append(o, objs(22, []uint8{1, 2, 5, 6}, rd, qEvent)...)
	o = append(o, objs(23, []uint8{1, 2, 5, 6}, rd, qEvent)...)
	o = append(o, objs(30, []uint8{1, 2, 5}, rd, q0016)...)
	o = append(o, objs(32, []uint8{1, 2, 3, 4, 5, 7}, rd, qEvent)...)
	o = append(o, objs(40, []uint8{1, 2, 3}, rd, q0016)...)
	o = append(o, objs(41, []uint8{1, 2, 3}, ctl, qIndex)...)
	o = append(o, objs(42, []uint8{1, 2, 3, 4, 5, 7}, rd, q0016)...) // as printed (F-608 again)
	o = append(o, DeclaredObject{Group: 50, Var: 1, Funcs: []byte{dnp3.FCRead, dnp3.FCWrite}, Quals: []byte{dnp3.Q8Count}})
	o = append(o, DeclaredObject{Group: 60, Var: 1, Funcs: rd, Quals: []byte{dnp3.QAll}})
	for _, v := range []uint8{2, 3, 4} {
		o = append(o, DeclaredObject{Group: 60, Var: v, Funcs: rd, Quals: qEvent},
			DeclaredObject{Group: 60, Var: v, Funcs: []byte{dnp3.FCEnableUnsolicited, dnp3.FCDisableUnsolicited}, Quals: []byte{dnp3.QAll}})
	}
	o = append(o, DeclaredObject{Group: 80, Var: 1, Funcs: rd, Quals: []byte{dnp3.Q8StartStop, dnp3.Q16StartStop}})
	o = append(o, DeclaredObject{Group: 110, Var: 0, Funcs: rd, Quals: q0016},
		DeclaredObject{Group: 110, Var: 0, Funcs: []byte{dnp3.FCWrite}, Quals: []byte{dnp3.Q8StartStop, dnp3.Q16StartStop, dnp3.Q8Index8, dnp3.Q16Index16}},
		DeclaredObject{Group: 111, Var: 0, Funcs: rd, Quals: qEvent})
	// Implied by other items (F-1450).
	o = append(o,
		DeclaredObject{Group: 20, Var: 0, Funcs: []byte{dnp3.FCImmedFreeze, dnp3.FCImmedFreezeNR, dnp3.FCFreezeClear, dnp3.FCFreezeClearNR}, Quals: q0016, Implied: "3.4.10 counters frozen by master request; 1.13.5 to 1.13.8 broadcast freezes enabled"},
		DeclaredObject{Group: 50, Var: 3, Funcs: []byte{dnp3.FCWrite}, Quals: []byte{dnp3.Q8Count}, Implied: "1.3.17 DNP3 LAN procedure; 1.13.2 g50v3 broadcast write enabled"},
		DeclaredObject{Group: 80, Var: 1, Funcs: []byte{dnp3.FCWrite}, Quals: []byte{dnp3.Q8StartStop}, Implied: "1.1.7 Level 3 (clearing IIN1.7); 1.13.2 clear restart broadcast enabled"},
	)
	return Declared{
		Name: "cp1542sp-1-irc", Level: 3, LinkAddress: 4, MasterAddr: 1, Objects: o,
		// Record current time (1.3.17) and cold restart (1.13.11) are
		// implied; the table lists neither (F-1450).
		FunctionOnly:   []byte{dnp3.FCConfirm, dnp3.FCRecordCurrentTime, dnp3.FCColdRestart},
		MaxFragment:    2048,
		ConfirmTimeout: 5 * time.Second, UnsolConfirmTimeout: 5 * time.Second, UnsolRetries: 3,
		KeepAlive: 180 * time.Second, LinkConfirmTimeout: 2 * time.Second, SelectTimeout: time.Second,
		NeedTime: 6000 * time.Second, MaxCROB: 10, MaxAOB: 10, LatchOnly: true, OutputsInClass0: true,
		Users: 1, MAC: dnp3.MACSHA256Trunc16, KeyWrap: "AES-128", KeyChangeInterval: 15 * time.Minute, KeyChangeCount: 1000,
		AggressiveReceive: true,
		Attributes: map[uint8]any{252: "SIEMENS AG", 250: "CP 1542SP-1 IRC", 243: "2", 242: "V2.2",
			249: "DNP3-L3", 240: 2048.0, 241: 2048.0, 216: 10.0,
			// 1.11.2 to 1.11.4: supported, values not given; ours.
			246: "00-00-00-00-00-00", 247: "cp1542sp-1-irc preset", 248: "preset",
			// The other attributes of the table, from the preset's database
			// (StartCP1542): no data sets, one point of each output,
			// counter and analog type, two binary inputs, events for all;
			// 217 is the typical time-tag error of 1.10.7, 218 is not
			// given (0).
			212: 0.0, 213: 0.0, 214: 0.0, 215: 0.0, 217: 200.0, 218: 0.0, 219: 1.0, 220: 0.0, 221: 1.0, 222: 1.0,
			223: 0.0, 224: 1.0, 225: 1.0, 226: 1.0, 227: 1.0, 228: 0.0, 229: 1.0, 231: 1.0, 232: 0.0, 233: 1.0,
			237: 1.0, 238: 1.0, 239: 2.0},
		StaticVars: map[string]uint8{"binary": 2, "double": 2, "binary-output": 2, "counter": 1, "frozen-counter": 1,
			"analog": 1, "analog-output": 1},
		EventVars: map[string]uint8{"binary": 2, "double": 2, "binary-output": 2, "counter": 1, "frozen-counter": 1,
			"analog": 3, "analog-output": 3},
		LastFragmentConfirmations: "when the fragment carries events (1.7.11; F-1453)",
		// Items with no counterpart in the cp1243-1 profile.
		DoubleBit: true, MixedControls: true, MACs: []uint8{dnp3.MACSHA1Trunc10, dnp3.MACSHA256Trunc16},
		KeyWraps: []string{"AES-128", "AES-256"}, MaxErrors: 2, ChallengeLength: 4, EventsPerClass: 255,
		UnsolCount: 1, Broadcast: true, UDP: true, TLSSuites: CP1542TLSSuites,
		// 1.13.2 to 1.13.22: the function codes enabled for broadcast.
		BroadcastFuncs: []byte{dnp3.FCWrite, dnp3.FCDirectOperate, dnp3.FCDirectOperateNR, dnp3.FCImmedFreeze, dnp3.FCImmedFreezeNR,
			dnp3.FCFreezeClear, dnp3.FCFreezeClearNR, dnp3.FCColdRestart, dnp3.FCEnableUnsolicited, dnp3.FCDisableUnsolicited,
			dnp3.FCRecordCurrentTime},
		// 1.12.21 and 1.12.3.
		MaxAuthFailures: 5, MaxReplyTimeouts: 3, MaxAuthRekeys: 3, SecurityResponseTimeout: 5 * time.Second,
		ControlStatuses: []uint8{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 127},
	}
}

// CP1542Options tunes the preset.
type CP1542Options struct {
	// UpdateKey enables Secure Authentication v5 for user 1: 16 octets
	// (AES-128 key wrap, the current value of 1.12.10) or 32 (AES-256).
	UpdateKey []byte
	// MAC is the MAC algorithm of the outstation's challenges (1.12.9:
	// HMAC-SHA-256/16, the default, or HMAC-SHA-1/10).
	MAC uint8
	// UDP serves datagrams (1.3.2) instead of TCP.
	UDP bool
	// TLS serves TCP under a TLS server profile (the IEC 62351-3 profile),
	// built with its TLS 1.2 and 1.3 offers narrowed to CP1542TLSSuites
	// and CP1542TLS13Suites (1.12.11).
	TLS iotsec.TLSServerProfile
	// Listen is the address (default 127.0.0.1:0).
	Listen string
}

// CP1542 is a running cp1542sp-1-irc preset.
type CP1542 struct {
	Address, Master uint16
	declared        Declared
	db              *dnp3.PointDB
	assoc           *dnp3.Association
	auth            *dnp3.OutstationAuth
	h               *cpHandler
	ln              net.Listener
	pc              net.PacketConn
	scheme          string
	cancel          context.CancelFunc
	done            sync.WaitGroup
}

// StartCP1542 starts the preset with a small database: binary inputs 0
// and 1 (class 1), double-bit input 0 (class 1), analog input 0 (12,
// class 2), counter 0 (100, class 3), frozen counter 0, binary output 0,
// analog output 0 (5) and octet string 0, all in class 0 as the profile
// declares (3.1.4 to 3.8.2).
func StartCP1542(ctx context.Context, opt CP1542Options) (*CP1542, error) {
	d := CP1542Declared()
	if opt.UDP && opt.TLS != nil {
		return nil, errors.New("TLS needs TCP")
	}
	db := dnp3.NewPointDB()
	for _, p := range []struct {
		typ   string
		idx   uint32
		class int
		v     float64
	}{{"binary", 0, 1, 0}, {"binary", 1, 1, 0}, {"double", 0, 1, 1}, {"analog", 0, 2, 12}, {"counter", 0, 3, 100},
		{"frozen-counter", 0, 0, 0}, {"binary-output", 0, 1, 0}, {"analog-output", 0, 2, 5}} {
		if err := db.Define(dnp3.DBPoint{Type: p.typ, Index: p.idx, Class0: true, Class: p.class,
			StaticVar: d.StaticVars[p.typ], EventVar: d.EventVars[p.typ]}); err != nil {
			return nil, err
		}
		if _, err := db.Update(ctx, p.typ, p.idx, p.v, nil, 0x01, time.Now()); err != nil {
			return nil, err
		}
	}
	if err := db.Define(dnp3.DBPoint{Type: "octet-string", Index: 0, Class0: true, Class: 3}); err != nil {
		return nil, err
	}
	if _, err := db.Update(ctx, "octet-string", 0, 0, []byte("ET 200SP"), 0x01, time.Now()); err != nil {
		return nil, err
	}
	h := &cpHandler{db: db, latch: d.LatchOnly}
	cfg := dnp3.OutstationConfig{Address: d.LinkAddress, Master: d.MasterAddr, DB: db, Handler: h, MaxFragment: d.MaxFragment,
		ConfirmTimeout: d.ConfirmTimeout, SelectTimeout: d.SelectTimeout, MaxControls: d.MaxCROB, Unsolicited: true,
		UnsolRetries: d.UnsolRetries, UnsolCount: d.UnsolCount, NeedTime: d.NeedTime, Attributes: d.Attributes,
		Writable: map[uint8]bool{}, Filter: d.Filter, Broadcast: d.Broadcast, BroadcastFuncs: map[byte]bool{},
		Events: dnp3.NewEventBuffer(map[int]int{1: d.EventsPerClass, 2: d.EventsPerClass, 3: d.EventsPerClass}, nil)}
	for _, fc := range d.BroadcastFuncs {
		cfg.BroadcastFuncs[fc] = true
	}
	c := &CP1542{Address: d.LinkAddress, Master: d.MasterAddr, declared: d, db: db, h: h}
	if opt.UpdateKey != nil {
		if len(opt.UpdateKey) != 16 && len(opt.UpdateKey) != 32 {
			return nil, errors.New("the cp1542sp-1-irc preset wraps keys with AES-128 or AES-256: the update key is 16 or 32 octets")
		}
		mal := opt.MAC
		if mal == 0 {
			mal = d.MAC
		}
		if mal != dnp3.MACSHA256Trunc16 && mal != dnp3.MACSHA1Trunc10 {
			return nil, errors.New("the cp1542sp-1-irc preset declares HMAC-SHA-256/16 and HMAC-SHA-1/10 only (1.12.9)")
		}
		agg := d.AggressiveReceive
		a, err := dnp3.NewOutstationAuth(dnp3.OutstationAuthConfig{
			Users: []dnp3.OutstationUser{{Number: 1, Name: "Common", UpdateKey: opt.UpdateKey, Role: dnp3.RoleSingleUser}},
			MAL:   mal, Aggressive: &agg, KeyInterval: d.KeyChangeInterval, KeyCount: d.KeyChangeCount, MaxErrors: d.MaxErrors,
			MaxAuthFailures: d.MaxAuthFailures, MaxReplyTimeouts: d.MaxReplyTimeouts, ReplyTimeout: d.SecurityResponseTimeout,
			Subject: "dnp3sim cp1542sp-1-irc",
		})
		if err != nil {
			return nil, err
		}
		c.auth, cfg.Auth = a, a
	}
	c.assoc = dnp3.NewAssociation(cfg)
	listen := opt.Listen
	if listen == "" {
		listen = "127.0.0.1:0"
	}
	rctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	n := &dnp3.OutstationNet{KeepAlive: d.KeepAlive, Timeout: d.LinkConfirmTimeout}
	n.Add(c.assoc)
	if opt.UDP {
		pc, err := net.ListenPacket("udp", listen)
		if err != nil {
			cancel()
			return nil, err
		}
		c.pc, c.scheme = pc, "udp"
		c.done.Add(2)
		go func() { defer c.done.Done(); c.assoc.Run(rctx) }()
		go func() { defer c.done.Done(); n.ServeUDP(rctx, pc, nil) }()
		return c, nil
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		cancel()
		return nil, err
	}
	if opt.TLS != nil {
		p, err := opt.TLS(iotsec.TLSSelection{CipherSuites: CP1542TLSSuites, CipherSuites13: CP1542TLS13Suites})
		if err != nil {
			cancel()
			_ = ln.Close()
			return nil, err
		}
		ln = iotsec.TLSListener(ln, p)
	}
	c.ln, c.scheme = ln, "tcp"
	c.done.Add(2)
	go func() { defer c.done.Done(); c.assoc.Run(rctx) }()
	go func() {
		defer c.done.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go n.ServeStream(rctx, conn)
		}
	}()
	return c, nil
}

// URL is the preset's tcp:// or udp:// address.
func (c *CP1542) URL() string {
	if c.pc != nil {
		return "udp://" + c.pc.LocalAddr().String()
	}
	return "tcp://" + c.ln.Addr().String()
}

// Close stops the preset.
func (c *CP1542) Close() {
	c.cancel()
	if c.ln != nil {
		_ = c.ln.Close()
	}
	if c.pc != nil {
		_ = c.pc.Close()
	}
	c.done.Wait()
}

// Declared is the profile the preset reproduces.
func (c *CP1542) Declared() Declared { return c.declared }

// SetBinary changes binary input idx (a class 1 event).
func (c *CP1542) SetBinary(ctx context.Context, idx uint32, on bool) {
	v := 0.0
	if on {
		v = 1
	}
	_, _ = c.db.Update(ctx, "binary", idx, v, nil, 0x01, time.Now())
}

// SetDouble changes double-bit input idx (0 to 3; a class 1 event).
func (c *CP1542) SetDouble(ctx context.Context, idx uint32, state float64) {
	_, _ = c.db.Update(ctx, "double", idx, state, nil, 0x01, time.Now())
}

// SetAnalog changes analog input idx (a class 2 event).
func (c *CP1542) SetAnalog(ctx context.Context, idx uint32, v float64) {
	_, _ = c.db.Update(ctx, "analog", idx, v, nil, 0x01, time.Now())
}

// Clock is the master's time from the last synchronisation.
func (c *CP1542) Clock() (time.Time, bool) {
	c.h.mu.Lock()
	defer c.h.mu.Unlock()
	return c.h.clock, !c.h.clock.IsZero()
}

// Controls are the controls received.
func (c *CP1542) Controls() []dnp3.ControlRequest {
	c.h.mu.Lock()
	defer c.h.mu.Unlock()
	return append([]dnp3.ControlRequest(nil), c.h.controls...)
}

// SessionKeyChanges counts successful session key changes.
func (c *CP1542) SessionKeyChanges() uint32 {
	if c.auth == nil {
		return 0
	}
	return c.auth.Statistics()[dnp3.StatSessionKeyChanges]
}

// Broadcast hands the preset a request as if the master sent it to the
// broadcast address 0xFFFD (never answered).
func (c *CP1542) Broadcast(apdu []byte) {
	var seq uint8
	for _, s := range dnp3.Segment(apdu, &seq) {
		c.assoc.Deliver(dnp3.Frame{Ctrl: dnp3.CtrlDIR | dnp3.CtrlPRM | dnp3.LinkUnconfirmedUserData, Dest: dnp3.AddrBroadcastNoConfirm,
			Src: c.Master, Data: s})
	}
}

// Security is the Secure Authentication statistics (zero without it).
func (c *CP1542) Security() [dnp3.NumSecurityStatistics]uint32 {
	if c.auth == nil {
		return [dnp3.NumSecurityStatistics]uint32{}
	}
	return c.auth.Statistics()
}
