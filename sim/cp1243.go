package sim

import (
	"context"
	"errors"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/cB-Sigma/dnp3"
)

// Preset cp1243-1: an outstation that behaves as the Siemens CP 1243-1
// (S7-1200 DNP3 communication processor) device profile v1.1 (2016-11-11)
// declares. It runs the dnp3 package's outstation (Association) with the
// declared settings and a filter that serves only the objects, qualifiers
// and function codes of the profile's implementation table (part 4). The
// values are facts read from that profile; where it is silent or
// inconsistent the choice is recorded in the findings register (F-605 on).

// DeclaredObject is one implementation table row: the function codes and
// qualifiers an outstation parses with the object.
type DeclaredObject struct {
	Group, Var uint8
	Funcs      []byte
	Quals      []byte
	// Implied rows are not in the table but follow from other items of
	// the profile (the note names the item).
	Implied string
}

// Declared is what a device profile declares about an outstation.
type Declared struct {
	Name                      string
	Level                     int
	LinkAddress, MasterAddr   uint16
	Objects                   []DeclaredObject
	FunctionOnly              []byte // function codes accepted without objects
	MaxFragment               int
	ConfirmTimeout            time.Duration // 1.7.1
	UnsolConfirmTimeout       time.Duration // 1.8.3
	UnsolRetries              int           // 1.8.4
	KeepAlive                 time.Duration // 1.3.10
	LinkConfirmTimeout        time.Duration // 1.4.6
	SelectTimeout             time.Duration // 3.3.10 (read as milliseconds, F-607)
	NeedTime                  time.Duration // 1.10.2
	MaxCROB, MaxAOB           int           // 1.5.5, 1.5.6
	LatchOnly                 bool          // 3.3.1
	OutputsInClass0           bool          // 3.3.3, 3.6.2
	Users                     int           // 1.12.2
	MAC                       uint8         // 1.12.9
	KeyWrap                   string        // 1.12.10
	KeyChangeInterval         time.Duration // 1.12.6
	KeyChangeCount            int           // 1.12.7
	AggressiveReceive         bool          // 1.12.4
	Attributes                map[uint8]any
	StaticVars, EventVars     map[string]uint8 // part 3 current values
	LastFragmentConfirmations string           // 1.7.8 (F-606)
	// Items the cp1243-1 profile does not declare (zero there).
	DoubleBit       bool     // 3.2
	MixedControls   bool     // 1.5.8
	MACs            []uint8  // 1.12.9 capabilities
	KeyWraps        []string // 1.12.10 capabilities
	MaxErrors       int      // 1.12.21 max error messages sent
	ChallengeLength int      // 1.12.20
	EventsPerClass  int      // 1.7.6
	UnsolCount      int      // 1.9.1 to 1.9.3
	Broadcast       bool     // 1.13.1
	UDP             bool     // 1.3.2
	TLSSuites       []string // 1.12.11, those our TLS profile also offers
	ControlStatuses []uint8  // 1.5.9
	BroadcastFuncs  []byte   // 1.13.2 to 1.13.22: enabled for broadcast
	// 1.12.21 statistic limits and 1.12.3 security response timeout.
	MaxAuthFailures, MaxReplyTimeouts, MaxAuthRekeys int
	SecurityResponseTimeout                          time.Duration
}

func objs(g uint8, vars []uint8, funcs, quals []byte) []DeclaredObject {
	var out []DeclaredObject
	for _, v := range vars {
		out = append(out, DeclaredObject{Group: g, Var: v, Funcs: funcs, Quals: quals})
	}
	return out
}

var (
	rd     = []byte{dnp3.FCRead}
	ctl    = []byte{dnp3.FCSelect, dnp3.FCOperate, dnp3.FCDirectOperate, dnp3.FCDirectOperateNR}
	q0016  = []byte{dnp3.Q8StartStop, dnp3.Q16StartStop, dnp3.QAll}
	qEvent = []byte{dnp3.QAll, dnp3.Q8Count, dnp3.Q16Count}
	qIndex = []byte{dnp3.Q8Index8, dnp3.Q16Index16}
)

// CP1243Declared is the CP 1243-1 device profile v1.1.
func CP1243Declared() Declared {
	var o []DeclaredObject
	// g0: the attributes of the table, read with start-stop; 254 and 255
	// also with "all".
	for _, v := range []uint8{212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229,
		231, 232, 233, 235, 236, 237, 238, 239, 240, 241, 242, 243, 248, 249, 250, 252} {
		o = append(o, DeclaredObject{Group: 0, Var: v, Funcs: rd, Quals: []byte{dnp3.Q8StartStop}})
	}
	o = append(o, objs(0, []uint8{254, 255}, rd, []byte{dnp3.Q8StartStop, dnp3.QAll})...)
	o = append(o, objs(1, []uint8{1, 2}, rd, q0016)...)
	o = append(o, objs(2, []uint8{1, 2}, rd, qEvent)...)
	o = append(o, objs(10, []uint8{1, 2}, rd, q0016)...)
	o = append(o, objs(11, []uint8{1, 2}, rd, q0016)...) // as printed (F-608)
	o = append(o, objs(12, []uint8{1}, ctl, qIndex)...)
	o = append(o, objs(20, []uint8{1, 2}, rd, q0016)...)
	o = append(o, objs(21, []uint8{1, 2, 5, 6}, rd, q0016)...)
	o = append(o, objs(22, []uint8{1, 2, 5, 6}, rd, qEvent)...)
	o = append(o, objs(23, []uint8{1, 2, 5, 6}, rd, qEvent)...)
	o = append(o, objs(30, []uint8{1, 2, 5, 6}, rd, q0016)...)
	o = append(o, objs(32, []uint8{1, 2, 3, 4, 5, 6, 7, 8}, rd, qEvent)...)
	o = append(o, objs(40, []uint8{0, 1, 2, 3, 4}, rd, q0016)...)
	o = append(o, objs(41, []uint8{1, 2, 3, 4}, ctl, qIndex)...)
	o = append(o, objs(42, []uint8{1, 2, 3, 4, 5, 6, 7, 8}, rd, q0016)...) // as printed (F-608)
	o = append(o, DeclaredObject{Group: 50, Var: 1, Funcs: []byte{dnp3.FCRead, dnp3.FCWrite}, Quals: []byte{dnp3.Q8Count}})
	o = append(o, DeclaredObject{Group: 60, Var: 1, Funcs: rd, Quals: []byte{dnp3.QAll}})
	for _, v := range []uint8{2, 3, 4} {
		o = append(o, DeclaredObject{Group: 60, Var: v, Funcs: rd, Quals: qEvent},
			DeclaredObject{Group: 60, Var: v, Funcs: []byte{dnp3.FCEnableUnsolicited, dnp3.FCDisableUnsolicited}, Quals: []byte{dnp3.QAll}})
	}
	o = append(o, DeclaredObject{Group: 110, Var: 0, Funcs: rd, Quals: q0016},
		DeclaredObject{Group: 110, Var: 0, Funcs: []byte{dnp3.FCWrite}, Quals: []byte{dnp3.Q8StartStop, dnp3.Q16StartStop, dnp3.Q8Index8, dnp3.Q16Index16}})
	// Implied by other items (F-605).
	o = append(o,
		DeclaredObject{Group: 20, Var: 0, Funcs: []byte{dnp3.FCImmedFreeze, dnp3.FCImmedFreezeNR, dnp3.FCFreezeClear, dnp3.FCFreezeClearNR}, Quals: q0016, Implied: "3.4.10 counters frozen by master request"},
		DeclaredObject{Group: 50, Var: 3, Funcs: []byte{dnp3.FCWrite}, Quals: []byte{dnp3.Q8Count}, Implied: "1.3.17 DNP3 LAN procedure"},
		DeclaredObject{Group: 80, Var: 1, Funcs: []byte{dnp3.FCWrite}, Quals: []byte{dnp3.Q8StartStop}, Implied: "1.1.7 Level 3 (clearing IIN1.7)"},
	)
	return Declared{
		Name: "cp1243-1", Level: 3, LinkAddress: 4, MasterAddr: 1, Objects: o,
		FunctionOnly:   []byte{dnp3.FCConfirm, dnp3.FCRecordCurrentTime},
		MaxFragment:    2048,
		ConfirmTimeout: 10 * time.Second, UnsolConfirmTimeout: 5 * time.Second, UnsolRetries: 0,
		KeepAlive: 180 * time.Second, LinkConfirmTimeout: 2 * time.Second, SelectTimeout: time.Second,
		NeedTime: 6000 * time.Second, MaxCROB: 10, MaxAOB: 10, LatchOnly: true, OutputsInClass0: false,
		Users: 1, MAC: dnp3.MACSHA256Trunc16, KeyWrap: "AES-128", KeyChangeInterval: 900 * time.Second, KeyChangeCount: 1000,
		AggressiveReceive: true,
		Attributes: map[uint8]any{252: "SIEMENS AG", 250: "CP1243-1 DNP3", 243: "6GK7 243-1JX30-0XE0", 242: "1.2.18",
			249: "DNP3-L3", 240: 2048.0, 241: 2048.0, 216: 10.0},
		StaticVars:                map[string]uint8{"binary": 2, "binary-output": 2, "counter": 1, "frozen-counter": 1, "analog": 1, "analog-output": 1},
		EventVars:                 map[string]uint8{"binary": 2, "binary-output": 2, "counter": 1, "analog": 3, "analog-output": 3},
		LastFragmentConfirmations: "when the fragment carries events",
	}
}

// Filter serves only the declared requests: a function code the profile
// never lists answers IIN2.0, an object it does not list IIN2.1, a
// qualifier not listed for the object IIN2.2. A variation 0 request is
// served when some variation of the group is (F-608).
func (d Declared) Filter(req dnp3.Fragment) dnp3.IIN {
	fc := req.Func
	if len(req.Objects) == 0 {
		if slices.Contains(d.FunctionOnly, fc) {
			return 0
		}
		return dnp3.IINNoFuncCodeSupport
	}
	listed := false
	for _, r := range d.Objects {
		listed = listed || slices.Contains(r.Funcs, fc)
	}
	if !listed {
		return dnp3.IINNoFuncCodeSupport
	}
	blocks, err := dnp3.ParseRequest(fc, req.Objects)
	if err != nil {
		return dnp3.IINParameterError
	}
	for _, b := range blocks {
		h := b.Header
		known, qual := false, false
		for _, r := range d.Objects {
			if r.Group != h.Group || !slices.Contains(r.Funcs, fc) || (r.Var != h.Var && h.Var != 0 && !((h.Group == 110 || h.Group == 111) && r.Var == 0)) {
				continue
			}
			known = true
			qual = qual || slices.Contains(r.Quals, h.Qual)
		}
		switch {
		case !known:
			return dnp3.IINObjectUnknown
		case !qual:
			return dnp3.IINParameterError
		}
	}
	return 0
}

// CP1243Options tunes the preset.
type CP1243Options struct {
	// UpdateKey enables Secure Authentication v5 for user 1 (16 octets:
	// the profile's AES-128 key wrap).
	UpdateKey []byte
	// Listen is the TCP address (default 127.0.0.1:0).
	Listen string
}

// CP1243 is a running cp1243-1 preset.
type CP1243 struct {
	Address, Master uint16
	declared        Declared
	db              *dnp3.PointDB
	assoc           *dnp3.Association
	auth            *dnp3.OutstationAuth
	h               *cpHandler
	ln              net.Listener
	cancel          context.CancelFunc
	done            sync.WaitGroup
}

type cpHandler struct {
	db       *dnp3.PointDB
	latch    bool
	mu       sync.Mutex
	clock    time.Time
	controls []dnp3.ControlRequest
}

func (h *cpHandler) Control(ctx context.Context, c dnp3.ControlRequest) uint8 {
	h.mu.Lock()
	h.controls = append(h.controls, c)
	h.mu.Unlock()
	if c.Group == 12 {
		op := c.CROB.Code & 0x0F
		if h.latch && (c.CROB.Code&0xF0 != 0 || (op != dnp3.OpLatchOn && op != dnp3.OpLatchOff)) {
			return 4 // NOT_SUPPORTED: latch on and off only (3.3.1)
		}
		if !c.Select {
			v := 0.0
			if op == dnp3.OpLatchOn {
				v = 1
			}
			_, _ = h.db.Update(ctx, "binary-output", c.Index, v, nil, 0x01, time.Now())
		}
		return 0
	}
	if !c.Select {
		_, _ = h.db.Update(ctx, "analog-output", c.Index, c.Value, nil, 0x01, time.Now())
	}
	return 0
}
func (h *cpHandler) DataSetControl(context.Context, dnp3.DataSetControl) uint8 { return 4 }
func (h *cpHandler) Restart(context.Context, bool) time.Duration               { return 0 }
func (h *cpHandler) Activate(context.Context, [][]byte) dnp3.ActivateStatus {
	return dnp3.ActivateStatus{}
}
func (h *cpHandler) Application(context.Context, byte, [][]byte) dnp3.IIN {
	return dnp3.IINNoFuncCodeSupport
}
func (h *cpHandler) TimeSet(t time.Time)                          { h.mu.Lock(); h.clock = t; h.mu.Unlock() }
func (h *cpHandler) DataSetWritten(context.Context, dnp3.DataSet) {}

// StartCP1243 starts the preset on a TCP listener with a small database:
// binary inputs 0 and 1 (class 1), analog input 0 (12, class 2), counter
// 0 (100, class 3), frozen counter 0, binary output 0 and analog output 0
// (5), the outputs outside class 0 as the profile declares.
func StartCP1243(ctx context.Context, opt CP1243Options) (*CP1243, error) {
	d := CP1243Declared()
	db := dnp3.NewPointDB()
	def := func(typ string, idx uint32, class int, v float64) error {
		class0 := d.OutputsInClass0 || (typ != "binary-output" && typ != "analog-output")
		if err := db.Define(dnp3.DBPoint{Type: typ, Index: idx, Class0: class0, Class: class, StaticVar: d.StaticVars[typ], EventVar: d.EventVars[typ]}); err != nil {
			return err
		}
		_, err := db.Update(ctx, typ, idx, v, nil, 0x01, time.Now())
		return err
	}
	for _, p := range []struct {
		typ   string
		idx   uint32
		class int
		v     float64
	}{{"binary", 0, 1, 0}, {"binary", 1, 1, 0}, {"analog", 0, 2, 12}, {"counter", 0, 3, 100}, {"frozen-counter", 0, 0, 0},
		{"binary-output", 0, 1, 0}, {"analog-output", 0, 2, 5}} {
		if err := def(p.typ, p.idx, p.class, p.v); err != nil {
			return nil, err
		}
	}
	h := &cpHandler{db: db, latch: d.LatchOnly}
	cfg := dnp3.OutstationConfig{Address: d.LinkAddress, Master: d.MasterAddr, DB: db, Handler: h, MaxFragment: d.MaxFragment,
		ConfirmTimeout: d.ConfirmTimeout, SelectTimeout: d.SelectTimeout, MaxControls: d.MaxCROB, Unsolicited: true,
		UnsolRetries: d.UnsolRetries, NeedTime: d.NeedTime, Attributes: d.Attributes, Writable: map[uint8]bool{}, Filter: d.Filter}
	c := &CP1243{Address: d.LinkAddress, Master: d.MasterAddr, declared: d, db: db, h: h}
	if opt.UpdateKey != nil {
		if len(opt.UpdateKey) != 16 {
			return nil, errors.New("the cp1243-1 preset wraps keys with AES-128: the update key is 16 octets")
		}
		agg := d.AggressiveReceive
		a, err := dnp3.NewOutstationAuth(dnp3.OutstationAuthConfig{
			Users: []dnp3.OutstationUser{{Number: 1, Name: "Common", UpdateKey: opt.UpdateKey, Role: dnp3.RoleSingleUser}},
			MAL:   d.MAC, Aggressive: &agg, KeyInterval: d.KeyChangeInterval, KeyCount: d.KeyChangeCount,
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
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	c.ln = ln
	rctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	n := &dnp3.OutstationNet{KeepAlive: d.KeepAlive, Timeout: d.LinkConfirmTimeout}
	n.Add(c.assoc)
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

// URL is the preset's tcp:// address.
func (c *CP1243) URL() string { return "tcp://" + c.ln.Addr().String() }

// Close stops the preset.
func (c *CP1243) Close() {
	c.cancel()
	_ = c.ln.Close()
	c.done.Wait()
}

// Declared is the profile the preset reproduces.
func (c *CP1243) Declared() Declared { return c.declared }

// SetBinary changes binary input idx (a class 1 event).
func (c *CP1243) SetBinary(ctx context.Context, idx uint32, on bool) {
	v := 0.0
	if on {
		v = 1
	}
	_, _ = c.db.Update(ctx, "binary", idx, v, nil, 0x01, time.Now())
}

// Clock is the master's time from the last synchronisation.
func (c *CP1243) Clock() (time.Time, bool) {
	c.h.mu.Lock()
	defer c.h.mu.Unlock()
	return c.h.clock, !c.h.clock.IsZero()
}

// Controls are the controls received.
func (c *CP1243) Controls() []dnp3.ControlRequest {
	c.h.mu.Lock()
	defer c.h.mu.Unlock()
	return append([]dnp3.ControlRequest(nil), c.h.controls...)
}

// SessionKeyChanges counts successful session key changes.
func (c *CP1243) SessionKeyChanges() uint32 {
	if c.auth == nil {
		return 0
	}
	return c.auth.Statistics()[dnp3.StatSessionKeyChanges]
}
