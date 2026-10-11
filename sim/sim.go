// Package sim is a DNP3 outstation simulator for tests, run in-process
// or from cmd/dnp3sim: a point database answered to class polls, buffered
// events (with and without time), unsolicited responses, IIN bits, time
// synchronisation and controls, with knobs for failures (control status,
// ignored requests, stop and restart), over TCP (optionally TLS) or UDP.
// It reuses the dnp3 package's codec. The presets cp1243-1 (cp1243.go)
// and cp1542sp-1-irc (cp1542.go) instead run the dnp3 package's
// outstation limited to a vendor device profile's declared capabilities.
package sim

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cB-Sigma/dnp3"
	"github.com/cB-Sigma/iotsec"
)

// Value is a static point's value and flags (0x01 is online). Binary
// states are 0 or 1; double-bit states 0–3.
type Value struct {
	V     float64
	Flags uint8
}

// Event is a buffered event. Group and Var select the event object (for
// example 2/2 binary with time, 2/3 binary with relative time, 32/7 float
// with time); Class is 1, 2 or 3.
type Event struct {
	Group, Var uint8
	Index      uint16
	Value      float64
	Flags      uint8
	Time       time.Time
	Class      int
}

// Control is a control the outstation executed (or refused).
type Control struct {
	Func   byte
	Group  uint8
	Index  uint32
	CROB   dnp3.CROB
	Value  float64
	Status uint8
}

// Sim is the outstation.
type Sim struct {
	Address, Master uint16
	// MaxFragment is the largest response fragment (octets); smaller
	// values force multi-fragment responses.
	MaxFragment int
	// SelectTimeout is how long a select stays valid.
	SelectTimeout time.Duration
	// StaticVar is the variation used for class 0 data per group (default
	// g1v2, g3v2, g10v2, g20v1, g21v1, g30v5, g40v3).
	StaticVar map[uint8]uint8
	// Network is "tcp" (default) or "udp"; set before the first Start.
	Network string
	// ReplyPort, over UDP, sends every response to this port of the
	// master's address instead of the port the request came from (the
	// device profile's fixed "destination UDP port for responses", often
	// 20000); 0 answers the source port. Set before Start.
	ReplyPort int
	// Listen is the address the first Start listens on (default
	// 127.0.0.1:0, a free port); a later Start reuses the address.
	Listen string
	// TLS, when set before Start, serves TCP under a TLS server profile
	// (the IEC 62351-3 profile, say, or iotsec.StdTLS).
	TLS iotsec.TLSServer

	mu            sync.Mutex
	addr          string
	ln            io.Closer
	cur           *conn
	stuck         dnp3.IIN
	auth          *simAuth
	attrs         map[uint8]any
	freezes       []string
	static        map[uint8]map[uint16]Value // by static group
	events        []Event
	restart       bool
	needTime      bool
	overflow      bool
	unsol         map[int]bool
	ignore        bool
	selStatus     uint8
	opStatus      uint8
	sel           *selection
	recorded      time.Time
	clock         time.Time // time written by the master
	clockAt       time.Time // when it was written
	delayMs       uint16
	controls      []Control
	requests      []string
	unsolConfirms int
	selfAddress   bool
	linkFrames    []byte // primary link function codes received
	restartDelay  time.Duration
	assigned      []string
	fs            *fileState
}

// SetSelfAddress makes the outstation accept frames sent to 0xFFFC
// (9.2.5.2.2).
func (s *Sim) SetSelfAddress(on bool) { s.mu.Lock(); s.selfAddress = on; s.mu.Unlock() }

// LinkFunctions lists the primary link function codes received.
func (s *Sim) LinkFunctions() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.linkFrames...)
}

type selection struct {
	objs []byte
	seq  uint8
	at   time.Time
}

// New creates a stopped outstation with the device-restart indication set.
func New(address, master uint16) *Sim {
	return &Sim{
		Address: address, Master: master, MaxFragment: 2048, SelectTimeout: 2 * time.Second,
		StaticVar: map[uint8]uint8{1: 2, 3: 2, 10: 2, 20: 1, 21: 1, 30: 5, 40: 3},
		static:    map[uint8]map[uint16]Value{}, unsol: map[int]bool{}, restart: true, attrs: map[uint8]any{},
	}
}

// Start listens (on Listen, by default 127.0.0.1:0, the first time; on
// the same address after a Stop).
func (s *Sim) Start() error {
	s.mu.Lock()
	addr := s.addr
	s.mu.Unlock()
	if addr == "" {
		addr = s.Listen
	}
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	if s.Network == "udp" {
		var pc net.PacketConn
		var err error
		for range 50 {
			if pc, err = net.ListenPacket("udp", addr); err == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err != nil {
			return err
		}
		c := s.newConn(&udpConn{pc: pc, replyPort: s.ReplyPort})
		s.mu.Lock()
		s.ln, s.addr, s.cur = pc, pc.LocalAddr().String(), c
		s.mu.Unlock()
		go c.read()
		go c.serve()
		return nil
	}
	var ln net.Listener
	var err error
	for range 50 { // the port can take a moment to free after Stop
		if ln, err = net.Listen("tcp", addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		return err
	}
	if s.TLS != nil {
		ln = iotsec.TLSListener(ln, s.TLS)
	}
	s.mu.Lock()
	s.ln, s.addr = ln, ln.Addr().String()
	s.mu.Unlock()
	go s.accept(ln)
	return nil
}

// Stop closes the listener and the connection.
func (s *Sim) Stop() {
	s.mu.Lock()
	ln, c := s.ln, s.cur
	s.ln, s.cur = nil, nil
	s.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	if c != nil {
		c.close()
	}
}

// URL is the outstation's tcp:// or udp:// URL.
func (s *Sim) URL() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Network == "udp" {
		return "udp://" + s.addr
	}
	return "tcp://" + s.addr
}

// udpConn serves one master over a UDP socket: it answers the address the
// latest datagram came from, and every write is one datagram.
type udpConn struct {
	pc        net.PacketConn
	replyPort int
	mu        sync.Mutex
	peer      net.Addr
}

func (u *udpConn) Read(b []byte) (int, error) {
	n, a, err := u.pc.ReadFrom(b)
	if err == nil {
		if ua, ok := a.(*net.UDPAddr); ok && u.replyPort != 0 {
			a = &net.UDPAddr{IP: ua.IP, Port: u.replyPort, Zone: ua.Zone}
		}
		u.mu.Lock()
		u.peer = a
		u.mu.Unlock()
	}
	return n, err
}

func (u *udpConn) Write(b []byte) (int, error) {
	u.mu.Lock()
	a := u.peer
	u.mu.Unlock()
	if a == nil {
		return len(b), nil // no master yet: nowhere to send
	}
	return u.pc.WriteTo(b, a)
}

func (u *udpConn) Close() error { return u.pc.Close() }

// SetStuckIIN sets indications reported in every response whatever the
// master does (a misbehaving outstation); 0 clears them.
func (s *Sim) SetStuckIIN(i dnp3.IIN) { s.mu.Lock(); s.stuck = i; s.mu.Unlock() }

// SetAttribute sets a device attribute (group 0 variation, standard set
// 0): a string, float64 or []byte.
func (s *Sim) SetAttribute(variation uint8, v any) {
	s.mu.Lock()
	s.attrs[variation] = v
	s.mu.Unlock()
}

// Freezes lists the freeze requests received ("IMMED_FREEZE all",
// "FREEZE_CLEAR 2-2").
func (s *Sim) Freezes() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.freezes...)
}

// Set stores a static value for a static group (1, 3, 10, 20, 21, 30, 40).
func (s *Sim) Set(group uint8, index uint16, v float64, flags uint8) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.static[group] == nil {
		s.static[group] = map[uint16]Value{}
	}
	s.static[group][index] = Value{v, flags}
}

// Get reads a static value.
func (s *Sim) Get(group uint8, index uint16) Value {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.static[group][index]
}

// AddEvent buffers an event and, when unsolicited responses are enabled
// for its class, reports it unsolicited.
func (s *Sim) AddEvent(e Event) {
	s.mu.Lock()
	s.events = append(s.events, e)
	c := s.cur
	push := s.unsol[e.Class]
	s.mu.Unlock()
	if push && c != nil {
		go c.unsolicited()
	}
}

// SetRestart, SetNeedTime and SetOverflow set internal indications.
func (s *Sim) SetRestart(v bool) { s.mu.Lock(); s.restart = v; s.mu.Unlock() }

// SetNeedTime sets the need-time indication.
func (s *Sim) SetNeedTime(v bool) { s.mu.Lock(); s.needTime = v; s.mu.Unlock() }

// SetOverflow sets the event-buffer-overflow indication.
func (s *Sim) SetOverflow(v bool) { s.mu.Lock(); s.overflow = v; s.mu.Unlock() }

// Restarting reports the device-restart indication.
func (s *Sim) Restarting() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.restart }

// SetIgnore makes the outstation drop (true) or answer (false) requests.
func (s *Sim) SetIgnore(v bool) { s.mu.Lock(); s.ignore = v; s.mu.Unlock() }

// SetControlStatus sets the status answered to SELECT and to OPERATE /
// DIRECT_OPERATE (0 succeeds).
func (s *Sim) SetControlStatus(selectStatus, operateStatus uint8) {
	s.mu.Lock()
	s.selStatus, s.opStatus = selectStatus, operateStatus
	s.mu.Unlock()
}

// SetDelay sets the processing delay reported to DELAY_MEASURE (ms).
func (s *Sim) SetDelay(ms uint16) { s.mu.Lock(); s.delayMs = ms; s.mu.Unlock() }

// Clock is the outstation's clock as set by the master, and whether it
// was set.
func (s *Sim) Clock() (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.clockAt.IsZero() {
		return time.Time{}, false
	}
	return s.clock.Add(time.Since(s.clockAt)), true
}

// Controls lists executed and refused controls.
func (s *Sim) Controls() []Control {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Control(nil), s.controls...)
}

// Requests lists the requests received, as "READ g60v2 g60v3", "WRITE
// g80v1" and so on.
func (s *Sim) Requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.requests...)
}

// UnsolicitedConfirms counts confirmed unsolicited responses.
func (s *Sim) UnsolicitedConfirms() int { s.mu.Lock(); defer s.mu.Unlock(); return s.unsolConfirms }

// UnsolicitedEnabled reports whether a class is enabled for unsolicited
// reporting.
func (s *Sim) UnsolicitedEnabled(class int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unsol[class]
}

// PendingEvents counts buffered events.
func (s *Sim) PendingEvents() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.events) }

// NullUnsolicited sends an unsolicited response without objects, which
// reports the current internal indications.
func (s *Sim) NullUnsolicited() {
	s.mu.Lock()
	c := s.cur
	s.mu.Unlock()
	if c != nil {
		go func() {
			c.amu.Lock()
			defer c.amu.Unlock()
			c.sendUnsolicited(nil, nil)
		}()
	}
}

func (s *Sim) newConn(nc io.ReadWriteCloser) *conn {
	return &conn{s: s, nc: nc, reqs: make(chan dnp3.Fragment, 16), confirms: make(chan dnp3.Fragment, 16), done: make(chan struct{})}
}

func (s *Sim) accept(ln net.Listener) {
	for {
		nc, err := ln.Accept()
		if err != nil {
			return
		}
		c := s.newConn(nc)
		// Under a TLS profile that needs traffic before a timed key
		// update on an idle connection (IEC 62351-3), the keepalive is
		// REQUEST_LINK_STATUS (IEEE 1815 13.2.3.3.1), as the library's
		// outstation does.
		iotsec.SetKeepalive(nc, func() error {
			c.link(dnp3.CtrlPRM | dnp3.LinkRequestLinkStatus)
			return nil
		})
		s.mu.Lock()
		old := s.cur
		s.cur = c
		s.mu.Unlock()
		if old != nil {
			old.close()
		}
		go c.read()
		go c.serve()
	}
}

// iin is the current internal indications (s.mu held); events about to
// be reported (skip) do not count for the class bits.
func (s *Sim) iin(skip ...int) dnp3.IIN {
	i := s.stuck
	if s.restart {
		i |= dnp3.IINDeviceRestart
	}
	if s.needTime {
		i |= dnp3.IINNeedTime
	}
	if s.overflow {
		i |= dnp3.IINEventBufferOverflow
	}
	for n, e := range s.events {
		if !slices.Contains(skip, n) {
			i |= dnp3.IIN(1) << e.Class
		}
	}
	return i
}

type conn struct {
	s        *Sim
	nc       io.ReadWriteCloser
	wmu      sync.Mutex
	tseq     uint8
	amu      sync.Mutex // one response or unsolicited exchange at a time
	useq     uint8
	reqs     chan dnp3.Fragment
	confirms chan dnp3.Fragment
	once     sync.Once
	done     chan struct{}
	sec      dnp3.Secondary
}

func (c *conn) close() {
	c.once.Do(func() {
		_ = c.nc.Close()
		close(c.done)
	})
}

func (c *conn) read() {
	defer c.close()
	var lp dnp3.LinkParser
	var ra dnp3.Reassembler
	buf := make([]byte, 4096)
	for {
		n, err := c.nc.Read(buf)
		if err != nil {
			return
		}
		for _, f := range lp.Feed(buf[:n]) {
			c.s.mu.Lock()
			self := c.s.selfAddress
			c.s.mu.Unlock()
			if (f.Dest != c.s.Address && !dnp3.IsBroadcast(f.Dest) && !(self && f.Dest == dnp3.AddrSelf)) || !f.Primary() {
				continue
			}
			c.s.mu.Lock()
			c.s.linkFrames = append(c.s.linkFrames, f.Func())
			c.s.mu.Unlock()
			act := c.sec.Handle(f)
			if act.Respond {
				c.link(act.Func)
			}
			if !act.Deliver {
				continue
			}
			apdu, err := ra.Add(f.Data)
			if err != nil || apdu == nil {
				continue
			}
			frag, err := dnp3.ParseFragment(apdu)
			if err != nil {
				continue
			}
			ch := c.reqs
			if frag.Func == dnp3.FCConfirm {
				ch = c.confirms
			}
			select {
			case ch <- frag:
			case <-c.done:
				return
			}
		}
	}
}

func (c *conn) link(fc byte) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	b, _ := dnp3.Frame{Ctrl: fc, Dest: c.s.Master, Src: c.s.Address}.Encode()
	_, _ = c.nc.Write(b)
}

func (c *conn) send(f dnp3.Fragment) {
	if f.Func == dnp3.FCResponse || f.Func == dnp3.FCUnsolicited {
		c.s.mu.Lock()
		if a := c.s.auth; a != nil {
			f = a.wrapResponse(f)
			a.lastResp = f.Encode()
		}
		c.s.mu.Unlock()
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	for _, seg := range dnp3.Segment(f.Encode(), &c.tseq) {
		b, _ := dnp3.Frame{Ctrl: dnp3.CtrlPRM | dnp3.LinkUnconfirmedUserData, Dest: c.s.Master, Src: c.s.Address, Data: seg}.Encode()
		if _, err := c.nc.Write(b); err != nil {
			return
		}
	}
}

// awaitConfirm waits for a confirm with the given sequence and UNS bit.
func (c *conn) awaitConfirm(seq uint8, uns bool) bool {
	t := time.NewTimer(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case f := <-c.confirms:
			if f.Seq() == seq && (f.Control&dnp3.AppUNS != 0) == uns {
				c.s.mu.Lock()
				ok := c.s.auth.checkConfirm(f)
				c.s.mu.Unlock()
				return ok
			}
		case <-t.C:
			return false
		case <-c.done:
			return false
		}
	}
}

func (c *conn) drainConfirms() {
	for {
		select {
		case <-c.confirms:
		default:
			return
		}
	}
}

func (c *conn) serve() {
	for {
		select {
		case <-c.done:
			return
		case req := <-c.reqs:
			c.handle(req)
		}
	}
}

func describe(req dnp3.Fragment) string {
	parts := []string{dnp3.FuncName(req.Func)}
	if req.Func == dnp3.FCAuthRequest && len(req.Objects) > 1 {
		return fmt.Sprintf("AUTH_REQUEST g120v%d", req.Objects[1])
	}
	blocks, _ := dnp3.ParseObjects(req.Objects, req.Func != dnp3.FCRead && req.Func != dnp3.FCEnableUnsolicited && req.Func != dnp3.FCDisableUnsolicited)
	for _, b := range blocks {
		parts = append(parts, b.Header.String())
	}
	return strings.Join(parts, " ")
}

func (c *conn) handle(req dnp3.Fragment) {
	s := c.s
	s.mu.Lock()
	ignore := s.ignore
	s.requests = append(s.requests, describe(req))
	s.mu.Unlock()
	if ignore {
		return
	}
	c.amu.Lock()
	defer c.amu.Unlock()
	if c.authGate(req) {
		return
	}
	c.process(req)
}

// process executes a request and responds (c.amu held).
func (c *conn) process(req dnp3.Fragment) {
	s := c.s
	var chunks [][]byte
	var sent []int // indices of events in the response
	var iin2 dnp3.IIN
	if ch, iin, handled, respond := c.extra(req); handled {
		if respond {
			c.respond(req.Seq(), ch, nil, iin)
		}
		return
	}
	switch req.Func {
	case dnp3.FCRead:
		blocks, err := dnp3.ParseObjects(req.Objects, false)
		if err != nil {
			iin2 |= dnp3.IINParameterError
		}
		for _, b := range blocks {
			switch {
			case b.Header.Group == 60 && b.Header.Var == 1:
				chunks = append(chunks, s.staticChunks()...)
			case b.Header.Group == 60 && b.Header.Var >= 2 && b.Header.Var <= 4:
				ch, idx := s.eventChunks(func(e Event) bool { return e.Class == int(b.Header.Var)-1 })
				chunks = append(chunks, ch...)
				sent = append(sent, idx...)
				if b.Header.Var == 4 {
					s.mu.Lock()
					if s.fs != nil {
						chunks = append(chunks, s.fs.pending...)
						s.fs.pending = nil
					}
					s.mu.Unlock()
				}
			case b.Header.Group == 0:
				ch := s.attributeChunks(b.Header.Var)
				if len(ch) == 0 {
					iin2 |= dnp3.IINObjectUnknown
				}
				chunks = append(chunks, ch...)
			case b.Header.Group == 121:
				s.mu.Lock()
				ch := s.securityStatistics()
				s.mu.Unlock()
				if ch == nil {
					iin2 |= dnp3.IINObjectUnknown
				}
				chunks = append(chunks, ch)
			case b.Header.Var == 0 && s.StaticVar[b.Header.Group] != 0:
				chunks = append(chunks, s.staticChunks(b.Header.Group)...)
			default:
				iin2 |= dnp3.IINObjectUnknown
			}
		}
	case dnp3.FCWrite:
		blocks, err := dnp3.ParseObjects(req.Objects, true)
		if err != nil {
			iin2 |= dnp3.IINObjectUnknown
		}
		s.mu.Lock()
		for _, b := range blocks {
			for _, p := range b.Points {
				switch {
				case p.Group == 80 && p.Index == 7 && p.Value == false:
					s.restart = false
				case p.Group == 50 && p.Var == 1:
					s.clock, s.clockAt, s.needTime = p.Value.(time.Time), time.Now(), false
				case p.Group == 50 && p.Var == 3 && !s.recorded.IsZero():
					s.clock, s.clockAt, s.needTime = p.Value.(time.Time), s.recorded, false
				default:
					iin2 |= dnp3.IINParameterError
				}
			}
		}
		s.mu.Unlock()
	case dnp3.FCRecordCurrentTime:
		s.mu.Lock()
		s.recorded = time.Now()
		s.mu.Unlock()
	case dnp3.FCDelayMeasure:
		s.mu.Lock()
		d := s.delayMs
		s.mu.Unlock()
		b, _ := dnp3.EncodeBlock(52, 2, dnp3.Q8Count, []dnp3.Point{{Value: float64(d)}})
		chunks = append(chunks, b)
	case dnp3.FCEnableUnsolicited, dnp3.FCDisableUnsolicited:
		blocks, _ := dnp3.ParseObjects(req.Objects, false)
		s.mu.Lock()
		for _, b := range blocks {
			if b.Header.Group == 60 && b.Header.Var >= 2 && b.Header.Var <= 4 {
				s.unsol[int(b.Header.Var)-1] = req.Func == dnp3.FCEnableUnsolicited
			} else {
				iin2 |= dnp3.IINParameterError
			}
		}
		s.mu.Unlock()
	case dnp3.FCImmedFreeze, dnp3.FCFreezeClear:
		if err := s.freeze(req); err != nil {
			iin2 |= dnp3.IINParameterError
		}
	case dnp3.FCSelect, dnp3.FCOperate, dnp3.FCDirectOperate:
		echo, err := s.control(req)
		if err != nil {
			iin2 |= dnp3.IINParameterError
		} else {
			chunks = append(chunks, echo)
		}
	default:
		iin2 |= dnp3.IINNoFuncCodeSupport
	}
	c.respond(req.Seq(), chunks, sent, iin2)
	if req.Func == dnp3.FCEnableUnsolicited {
		go c.unsolicited()
	}
}

// respond sends the chunks in as many fragments as MaxFragment needs,
// waiting for confirms, and drops the reported events once confirmed.
func (c *conn) respond(seq uint8, chunks [][]byte, sent []int, iin2 dnp3.IIN) {
	s := c.s
	s.mu.Lock()
	limit := s.MaxFragment - 4
	s.mu.Unlock()
	var frags [][]byte
	var cur []byte
	for _, ch := range chunks {
		if len(cur) > 0 && len(cur)+len(ch) > limit {
			frags = append(frags, cur)
			cur = nil
		}
		cur = append(cur, ch...)
	}
	frags = append(frags, cur)
	for i, objs := range frags {
		ctl := seq & 0x0F
		if i == 0 {
			ctl |= dnp3.AppFIR
		}
		last := i == len(frags)-1
		if last {
			ctl |= dnp3.AppFIN
		}
		if !last || len(sent) > 0 {
			ctl |= dnp3.AppCON
		}
		s.mu.Lock()
		iin := s.iin(sent...) | iin2
		s.mu.Unlock()
		c.drainConfirms()
		c.send(dnp3.Fragment{Control: ctl, Func: dnp3.FCResponse, IIN: iin, Objects: objs})
		if ctl&dnp3.AppCON != 0 && !c.awaitConfirm(seq, false) {
			return
		}
		seq = (seq + 1) & 0x0F
	}
	if len(sent) > 0 {
		s.dropEvents(sent)
	}
}

// unsolicited reports buffered events of enabled classes.
func (c *conn) unsolicited() {
	s := c.s
	c.amu.Lock()
	defer c.amu.Unlock()
	s.mu.Lock()
	unsol := map[int]bool{}
	for k, v := range s.unsol {
		unsol[k] = v
	}
	s.mu.Unlock()
	chunks, idx := s.eventChunks(func(e Event) bool { return unsol[e.Class] })
	if len(idx) == 0 {
		return
	}
	c.sendUnsolicited(chunks, idx)
}

// sendUnsolicited sends one unsolicited response (c.amu held) and waits
// for its confirm.
func (c *conn) sendUnsolicited(chunks [][]byte, idx []int) {
	s := c.s
	seq := c.useq
	c.useq = (c.useq + 1) & 0x0F
	s.mu.Lock()
	iin := s.iin(idx...)
	s.mu.Unlock()
	c.drainConfirms()
	c.send(dnp3.Fragment{Control: dnp3.AppFIR | dnp3.AppFIN | dnp3.AppCON | dnp3.AppUNS | seq, Func: dnp3.FCUnsolicited, IIN: iin, Objects: bytes.Join(chunks, nil)})
	if c.awaitConfirm(seq, true) {
		s.mu.Lock()
		s.unsolConfirms++
		s.mu.Unlock()
		s.dropEvents(idx)
	}
}

func (s *Sim) dropEvents(idx []int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	drop := map[int]bool{}
	for _, i := range idx {
		drop[i] = true
	}
	var keep []Event
	for i, e := range s.events {
		if !drop[i] {
			keep = append(keep, e)
		}
	}
	s.events = keep
}

// attributeChunks encodes device attributes: every one for variation
// 254, else the one asked for.
func (s *Sim) attributeChunks(variation uint8) [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	var vars []int
	for v := range s.attrs {
		if variation == dnp3.AttrAll || v == variation {
			vars = append(vars, int(v))
		}
	}
	sort.Ints(vars)
	var out [][]byte
	for _, v := range vars {
		out = append(out, dnp3.AppendAttribute(nil, uint8(v), 0, s.attrs[uint8(v)]))
	}
	return out
}

// freeze copies running counters (g20) to frozen counters (g21), for
// every counter (qualifier all) or a start-stop range, and with
// FREEZE_CLEAR zeroes the running counters.
func (s *Sim) freeze(req dnp3.Fragment) error {
	blocks, err := dnp3.ParseObjects(req.Objects, false)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, b := range blocks {
		if b.Header.Group != 20 {
			return errors.New("freeze needs group 20")
		}
		what := "all"
		if b.Header.Qual != dnp3.QAll {
			what = fmt.Sprintf("%d-%d", b.Header.Start, b.Header.Stop)
		}
		s.freezes = append(s.freezes, dnp3.FuncName(req.Func)+" "+what)
		for i, v := range s.static[20] {
			if b.Header.Qual != dnp3.QAll && (uint32(i) < b.Header.Start || uint32(i) > b.Header.Stop) {
				continue
			}
			s.setLocked(21, i, v.V)
			if req.Func == dnp3.FCFreezeClear {
				s.setLocked(20, i, 0)
			}
		}
	}
	return nil
}

// staticChunks encodes class 0 data (or only the given groups): one chunk
// per run of consecutive indices of each group.
func (s *Sim) staticChunks(only ...uint8) [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	var groups []int
	for g := range s.static {
		if len(only) == 0 || slices.Contains(only, g) {
			groups = append(groups, int(g))
		}
	}
	sort.Ints(groups)
	var out [][]byte
	for _, gi := range groups {
		g := uint8(gi)
		v := s.StaticVar[g]
		var idx []int
		for i := range s.static[g] {
			idx = append(idx, int(i))
		}
		sort.Ints(idx)
		var run []dnp3.Point
		flush := func() {
			if len(run) == 0 {
				return
			}
			q := uint8(dnp3.Q8StartStop)
			if run[len(run)-1].Index > 255 {
				q = dnp3.Q16StartStop
			}
			b, err := dnp3.EncodeBlock(g, v, q, run)
			if err == nil {
				out = append(out, b)
			}
			run = nil
		}
		for _, i := range idx {
			if len(run) > 0 && run[len(run)-1].Index+1 != uint32(i) {
				flush()
			}
			val := s.static[g][uint16(i)]
			run = append(run, dnp3.Point{Index: uint32(i), Value: val.V, Flags: val.Flags, HasFlags: true})
		}
		flush()
	}
	return out
}

// eventChunks encodes the buffered events that match, each with its own
// header (and a CTO before relative-time events).
func (s *Sim) eventChunks(match func(Event) bool) ([][]byte, []int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out [][]byte
	var idx []int
	for i, e := range s.events {
		if !match(e) {
			continue
		}
		p := dnp3.Point{Index: uint32(e.Index), Value: e.Value, Flags: e.Flags, HasFlags: true, Time: e.Time}
		var b []byte
		var err error
		if (e.Group == 2 || e.Group == 4) && e.Var == 3 {
			cto := e.Time.Truncate(time.Second)
			b, _ = dnp3.EncodeBlock(51, 1, dnp3.Q8Count, []dnp3.Point{{Value: cto}})
			var ev []byte
			ev, err = dnp3.EncodeBlock(e.Group, e.Var, dnp3.Q16Index16, []dnp3.Point{p}, cto)
			b = append(b, ev...)
		} else {
			b, err = dnp3.EncodeBlock(e.Group, e.Var, dnp3.Q16Index16, []dnp3.Point{p})
		}
		if err != nil {
			continue
		}
		out = append(out, b)
		idx = append(idx, i)
	}
	return out, idx
}

// control handles SELECT, OPERATE and DIRECT_OPERATE for g12v1 and g41,
// returning the echoed objects.
func (s *Sim) control(req dnp3.Fragment) ([]byte, error) {
	blocks, err := dnp3.ParseObjects(req.Objects, true)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var status uint8
	switch req.Func {
	case dnp3.FCSelect:
		status = s.selStatus
		if status == 0 {
			s.sel = &selection{objs: append([]byte(nil), req.Objects...), seq: req.Seq(), at: time.Now()}
		}
	case dnp3.FCOperate:
		switch sel := s.sel; {
		case sel == nil || !bytes.Equal(sel.objs, req.Objects) || req.Seq() != (sel.seq+1)&0x0F:
			status = 2 // no select
		case time.Since(sel.at) > s.SelectTimeout:
			status = 1 // timeout
		default:
			status = s.opStatus
		}
		s.sel = nil
	default:
		status = s.opStatus
	}
	var echo []byte
	for _, b := range blocks {
		if b.Header.Group != 12 && b.Header.Group != 41 {
			return nil, errors.New("not a control object")
		}
		pts := make([]dnp3.Point, len(b.Points))
		for i, p := range b.Points {
			p.Status = status
			pts[i] = p
			v, _ := p.Value.(float64)
			s.controls = append(s.controls, Control{Func: req.Func, Group: p.Group, Index: p.Index, CROB: p.CROB, Value: v, Status: status})
			if status != 0 || req.Func == dnp3.FCSelect {
				continue
			}
			if p.Group == 12 {
				on := 0.0
				switch {
				case p.CROB.Code&0xC0 == dnp3.TCCClose, p.CROB.Code&0x0F == dnp3.OpLatchOn, p.CROB.Code == dnp3.OpPulseOn:
					on = 1
				}
				s.setLocked(10, uint16(p.Index), on)
			} else {
				s.setLocked(40, uint16(p.Index), v)
			}
		}
		e, err := dnp3.EncodeBlock(b.Header.Group, b.Header.Var, b.Header.Qual, pts)
		if err != nil {
			return nil, err
		}
		echo = append(echo, e...)
	}
	return echo, nil
}

func (s *Sim) setLocked(group uint8, index uint16, v float64) {
	if s.static[group] == nil {
		s.static[group] = map[uint16]Value{}
	}
	old, ok := s.static[group][index]
	if !ok {
		old.Flags = 0x01
	}
	s.static[group][index] = Value{v, old.Flags}
}

// String summarises the outstation for test failure messages.
func (s *Sim) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fmt.Sprintf("outstation %d at %s: %d events, requests %q", s.Address, s.addr, len(s.events), s.requests)
}
