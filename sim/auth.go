package sim

import (
	"bytes"
	"crypto/dsa" //nolint:staticcheck // update key change methods 67 to 69
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"time"

	"github.com/cB-Sigma/dnp3"
)

// Secure Authentication (outstation side, IEEE 1815-2012 clause 7): key
// status and session key change, challenges of critical requests and
// verification of the master's reply, aggressive-mode requests,
// aggressive-mode confirmations it asks for, replies to the master's
// challenges, user status and update key changes, user roles, errors
// (g120v7) and security statistics (g121).

type simUser struct {
	name      string
	usr       uint16
	role      uint16
	updateKey []byte
	pubKey    *dsa.PublicKey
	pending   *dnp3.UserStatus
}

type simAuth struct {
	user      uint16
	updateKey []byte
	mal       uint8
	critical  map[byte]bool
	ksq       uint32
	status    uint8
	ctrl, mon []byte
	lastKS    []byte // key status data last sent, without its MAC
	lastChg   []byte // the last session key change fragment received
	macMon    []byte // last valid monitoring key (for key status MACs)
	csq       uint32
	pending   *pendingAuth
	ok, fail  int
	changes   int
	replyMAC  func(mac []byte) []byte // test hook: tampers with a received MAC
	stats     [dnp3.NumSecurityStatistics]uint32

	aggressive   bool   // aggressive-mode requests accepted
	lastChal     []byte // the last challenge fragment sent (for aggressive mode)
	aggrCount    int
	askConfirm   bool   // ask for aggressive-mode confirmations of event responses
	confirmChal  []byte // the response fragment carrying that challenge
	aggrConfirms int
	aggrResp     bool   // answer in aggressive mode after the master challenged
	masterChal   []byte // the master's last challenge received
	masterCSQ    uint32
	masterMAL    uint8
	lastResp     []byte // the last response fragment sent

	// Update key change.
	authorityKey []byte          // symmetric methods
	authorityPub *dsa.PublicKey  // asymmetric methods
	rsaKey       *rsa.PrivateKey // outstation key for asymmetric methods
	name         string          // outstation name
	users        map[string]*simUser
	nextUSR      uint16
	ukc          *pendingUKC
	ukChanges    int
}

type pendingUKC struct {
	user   *simUser
	method uint8
	mchal  []byte
	ochal  []byte
	ksq    uint32
}

type pendingAuth struct {
	req       dnp3.Fragment
	challenge []byte // the challenge fragment as sent
	csq       uint32
}

// EnableAuth turns on Secure Authentication for user with the update key
// (16 or 32 octets) and MAC algorithm mal. Every request except READ is
// critical until SetCritical says otherwise.
func (s *Sim) EnableAuth(user uint16, updateKey []byte, mal uint8) {
	s.mu.Lock()
	defer s.mu.Unlock()
	crit := map[byte]bool{}
	for fc := range 256 {
		if byte(fc) != dnp3.FCRead && byte(fc) != dnp3.FCConfirm && byte(fc) != dnp3.FCAuthRequest {
			crit[byte(fc)] = true
		}
	}
	s.auth = &simAuth{user: user, updateKey: updateKey, mal: mal, critical: crit, status: dnp3.KeyStatusNotInit,
		aggressive: true, users: map[string]*simUser{}, nextUSR: 10, name: "outstation"}
}

// SetCritical lists the function codes that are challenged.
func (s *Sim) SetCritical(fcs ...byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auth.critical = map[byte]bool{}
	for _, fc := range fcs {
		s.auth.critical[fc] = true
	}
}

// SetAggressive accepts (true, the default) or refuses aggressive-mode
// requests (error 4).
func (s *Sim) SetAggressive(on bool) { s.mu.Lock(); s.auth.aggressive = on; s.mu.Unlock() }

// AskAggressiveConfirms makes event responses end with a challenge, so
// the master must confirm them in aggressive mode (7.5.2.3.2 d).
func (s *Sim) AskAggressiveConfirms(on bool) { s.mu.Lock(); s.auth.askConfirm = on; s.mu.Unlock() }

// AggressiveResponses makes the outstation answer in aggressive mode once
// the master has challenged it.
func (s *Sim) AggressiveResponses(on bool) { s.mu.Lock(); s.auth.aggrResp = on; s.mu.Unlock() }

// AuthStats counts verified and failed challenge replies and completed
// session key changes.
func (s *Sim) AuthStats() (ok, failed, keyChanges int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.auth.ok, s.auth.fail, s.auth.changes
}

// AggressiveStats counts accepted aggressive-mode requests and
// aggressive-mode confirmations.
func (s *Sim) AggressiveStats() (requests, confirms int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.auth.aggrCount, s.auth.aggrConfirms
}

// KSQ is the key change sequence number last sent.
func (s *Sim) KSQ() uint32 { s.mu.Lock(); defer s.mu.Unlock(); return s.auth.ksq }

// ForgetSessionKeys drops the session keys (as after a restart).
func (s *Sim) ForgetSessionKeys() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auth.ctrl, s.auth.mon, s.auth.status = nil, nil, dnp3.KeyStatusNotInit
}

// SetUpdateKey replaces the outstation's update key (a mismatch with the
// master's makes key changes fail).
func (s *Sim) SetUpdateKey(k []byte) { s.mu.Lock(); s.auth.updateKey = k; s.mu.Unlock() }

// SetAuthority configures update key changes: the outstation's name, the
// symmetric authority certification key (methods 3 and 4) or the
// authority's DSA public key and the outstation's RSA key (methods 67 to
// 69).
func (s *Sim) SetAuthority(name string, key []byte, authorityPub *dsa.PublicKey, rsaKey *rsa.PrivateKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auth.name, s.auth.authorityKey, s.auth.authorityPub, s.auth.rsaKey = name, key, authorityPub, rsaKey
}

// User reports a user's number, role and whether it has an update key.
func (s *Sim) User(name string) (usr uint16, role uint16, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.auth.users[name]
	if u == nil || u.updateKey == nil {
		return 0, 0, false
	}
	return u.usr, u.role, true
}

func (a *simAuth) keyWrap() uint8 {
	if len(a.updateKey) == 32 {
		return dnp3.KeyWrapAES256
	}
	return dnp3.KeyWrapAES128
}

// keyFor is the update key and role of a user number.
func (a *simAuth) roleOf(usr uint16) (uint16, bool) {
	for _, u := range a.users {
		if u.usr == usr && u.updateKey != nil {
			return u.role, true
		}
	}
	return 0, false
}

// authGate handles AUTH_REQUEST and challenges critical requests. It
// reports whether the request was consumed (c.amu held).
func (c *conn) authGate(req dnp3.Fragment) bool {
	s := c.s
	s.mu.Lock()
	a := s.auth
	s.mu.Unlock()
	if a == nil {
		return false
	}
	if req.Func == dnp3.FCAuthRequest {
		c.authRequest(a, req)
		return true
	}
	if _, inner, _, _, ok := dnp3.SplitAggressive(req.Objects); ok {
		c.aggressiveRequest(a, req, inner)
		return true
	}
	s.mu.Lock()
	crit := a.critical[req.Func]
	keys := a.ctrl != nil
	s.mu.Unlock()
	if !crit {
		return false
	}
	if !keys {
		c.authError(req.Seq(), a, 0, dnp3.AuthErrAuthFailed)
		return true
	}
	s.mu.Lock()
	a.csq++
	cd := make([]byte, 4)
	_, _ = rand.Read(cd)
	ch := dnp3.Challenge{CSQ: a.csq, User: dnp3.UserUnknown, MAL: a.mal, Reason: dnp3.AuthReasonCritical, Data: cd}
	f := dnp3.Fragment{Control: dnp3.AppFIR | dnp3.AppFIN | req.Seq(), Func: dnp3.FCAuthResponse, IIN: s.iin(), Objects: dnp3.AppendAuthObject(nil, dnp3.AuthChallenge, ch.Encode())}
	a.pending = &pendingAuth{req: req, challenge: f.Encode(), csq: a.csq}
	a.lastChal = a.pending.challenge
	a.stats[dnp3.StatCriticalReceived]++
	s.mu.Unlock()
	c.send(f)
	return true
}

// aggressiveRequest checks an aggressive-mode request (Table A-9, rule e
// of 7.5.2.3.3) and executes the request it carries.
func (c *conn) aggressiveRequest(a *simAuth, req dnp3.Fragment, inner []byte) {
	s := c.s
	obj, _, mac, macAt, _ := dnp3.SplitAggressive(req.Objects)
	s.mu.Lock()
	if !a.aggressive {
		s.mu.Unlock()
		c.authError(req.Seq(), a, 0, dnp3.AuthErrAggressiveNotSupp)
		return
	}
	csq := binary.LittleEndian.Uint32(obj)
	usr := binary.LittleEndian.Uint16(obj[4:])
	pre := dnp3.Fragment{Control: req.Control, Func: req.Func, Objects: req.Objects[:macAt]}.Encode()
	good := a.ctrl != nil && a.lastChal != nil && csq > a.csq
	if good {
		want, err := dnp3.MAC(a.mal, a.ctrl, a.lastChal, pre)
		good = err == nil && hmac.Equal(want, mac)
	}
	if good {
		a.csq = csq // rule e: the next challenge carries this CSQ plus one
		a.aggrCount++
		a.ok++
		a.stats[dnp3.StatCriticalReceived]++
		a.stats[dnp3.StatSuccessfulAuth]++
	} else {
		a.fail++
		a.stats[dnp3.StatAuthFailures]++
	}
	role, known := a.roleOf(usr)
	s.mu.Unlock()
	if !good {
		c.authError(req.Seq(), a, csq, dnp3.AuthErrAuthFailed)
		return
	}
	plain := dnp3.Fragment{Control: req.Control, Func: req.Func, Objects: inner}
	if known && !permitted(role, plain.Func) {
		c.authError(req.Seq(), a, csq, dnp3.AuthErrAuthorization)
		return
	}
	c.process(plain)
}

// permitted applies Table 7-12 to a request: controls need OPERATOR or
// SINGLEUSER; other critical requests need a role that may change
// configuration.
func permitted(role uint16, fc byte) bool {
	switch fc {
	case dnp3.FCSelect, dnp3.FCOperate, dnp3.FCDirectOperate, dnp3.FCDirectOperateNR:
		return role == dnp3.RoleOperator || role == dnp3.RoleSingleUser
	case dnp3.FCRead, dnp3.FCConfirm:
		return role != dnp3.RoleSecAdm
	}
	return role != dnp3.RoleViewer
}

func (c *conn) authResponse(seq uint8, variation uint8, data []byte) {
	s := c.s
	s.mu.Lock()
	iin := s.iin()
	s.mu.Unlock()
	c.send(dnp3.Fragment{Control: dnp3.AppFIR | dnp3.AppFIN | seq, Func: dnp3.FCAuthResponse, IIN: iin, Objects: dnp3.AppendAuthObject(nil, variation, data)})
}

func (c *conn) authError(seq uint8, a *simAuth, csq uint32, code uint8) {
	d := binary.LittleEndian.AppendUint32(nil, csq)
	d = binary.LittleEndian.AppendUint16(d, a.user)
	d = binary.LittleEndian.AppendUint16(d, 0) // association id
	d = append(d, code)
	d = dnp3.AppendTime48(d, time.Now())
	c.s.mu.Lock()
	a.stats[dnp3.StatErrorsSent]++
	c.s.mu.Unlock()
	c.authResponse(seq, dnp3.AuthErrorObj, d)
}

// keyStatus builds a key status (s.mu held): the KSQ was already
// advanced; the MAC covers the last session key change fragment with the
// last valid monitoring key (Table A-4), none before any.
func (a *simAuth) keyStatus() []byte {
	cd := make([]byte, 4)
	_, _ = rand.Read(cd)
	k := dnp3.KeyStatus{KSQ: a.ksq, User: a.user, KeyWrap: a.keyWrap(), Status: a.status, Challenge: cd}
	if a.macMon != nil && a.lastChg != nil {
		k.MAL = a.mal
		k.MAC, _ = dnp3.MAC(a.mal, a.macMon, a.lastChg)
	}
	d := dnp3.AppendKeyStatus(nil, k)
	a.lastKS = k.Unauthenticated(d)
	return d
}

func (c *conn) authRequest(a *simAuth, req dnp3.Fragment) {
	s := c.s
	blocks, err := dnp3.ParseObjects(req.Objects, true)
	if err != nil || len(blocks) == 0 || blocks[0].Header.Group != 120 || len(blocks[0].Points) == 0 {
		c.authError(req.Seq(), a, 0, dnp3.AuthErrAuthFailed)
		return
	}
	v := blocks[0].Header.Var
	d := blocks[0].Points[0].Raw
	switch v {
	case dnp3.AuthKeyStatusReq:
		s.mu.Lock()
		a.ksq++
		ks := a.keyStatus()
		s.mu.Unlock()
		c.authResponse(req.Seq(), dnp3.AuthKeyStatus, ks)
	case dnp3.AuthSessionKeyChg:
		s.mu.Lock()
		ok := false
		if len(d) > 6 && binary.LittleEndian.Uint32(d) == a.ksq && a.lastKS != nil {
			if plain, err := dnp3.UnwrapKey(a.updateKey, d[6:]); err == nil {
				ctrl, mon, ks, err := dnp3.ParseSessionKeyData(plain)
				if err == nil && bytes.HasPrefix(ks, a.lastKS) && len(bytes.Trim(ks[len(a.lastKS):], "\x00")) == 0 {
					a.ctrl, a.mon, a.status, ok = ctrl, mon, dnp3.KeyStatusOK, true
					a.macMon, a.lastChg = mon, req.Encode()
					a.changes++
					a.stats[dnp3.StatSessionKeyChanges]++
				}
			}
		}
		if !ok {
			a.ctrl, a.mon, a.status = nil, nil, dnp3.KeyStatusAuthFail
			a.stats[dnp3.StatFailedSessionKeyChanges]++
		}
		a.ksq++
		ks := a.keyStatus()
		s.mu.Unlock()
		c.authResponse(req.Seq(), dnp3.AuthKeyStatus, ks)
	case dnp3.AuthReply:
		s.mu.Lock()
		p := a.pending
		a.pending = nil
		good := false
		var usr uint16
		if p != nil && len(d) > 6 && binary.LittleEndian.Uint32(d) == p.csq && a.ctrl != nil {
			usr = binary.LittleEndian.Uint16(d[4:])
			mac := d[6:]
			if a.replyMAC != nil {
				mac = a.replyMAC(mac)
			}
			want, err := dnp3.MAC(a.mal, a.ctrl, p.challenge, p.req.Encode())
			good = err == nil && hmac.Equal(want, mac)
		}
		if good {
			a.ok++
			a.stats[dnp3.StatSuccessfulAuth]++
		} else {
			a.fail++
			a.stats[dnp3.StatAuthFailures]++
		}
		role, known := a.roleOf(usr)
		s.mu.Unlock()
		if !good {
			var csq uint32
			if p != nil {
				csq = p.csq
			}
			c.authError(req.Seq(), a, csq, dnp3.AuthErrAuthFailed)
			return
		}
		if known && !permitted(role, p.req.Func) {
			c.authError(req.Seq(), a, p.csq, dnp3.AuthErrAuthorization)
			return
		}
		c.process(p.req)
	case dnp3.AuthChallenge:
		// The master challenges our last response: reply with the
		// monitoring direction key over its challenge and that response.
		ch, err := dnp3.ParseChallenge(d)
		s.mu.Lock()
		var mac []byte
		if err == nil && a.mon != nil && a.lastResp != nil {
			mac, err = dnp3.MAC(ch.MAL, a.mon, req.Encode(), a.lastResp)
		}
		if err == nil && mac != nil {
			a.masterChal, a.masterCSQ, a.masterMAL = req.Encode(), ch.CSQ, ch.MAL
		}
		s.mu.Unlock()
		if err != nil || mac == nil {
			c.authError(req.Seq(), a, ch.CSQ, dnp3.AuthErrAuthFailed)
			return
		}
		r := binary.LittleEndian.AppendUint32(nil, ch.CSQ)
		r = binary.LittleEndian.AppendUint16(r, ch.User)
		c.authResponse(req.Seq(), dnp3.AuthReply, append(r, mac...))
	case dnp3.AuthUserStatusChange:
		c.userStatusChange(a, req, d)
	case dnp3.AuthUpdateKeyChgReq:
		c.updateKeyRequest(a, req, d)
	case dnp3.AuthUpdateKeyChg:
		c.updateKeyChange(a, req, blocks)
	default:
		c.authError(req.Seq(), a, 0, dnp3.AuthErrAuthFailed)
	}
}

// userStatusChange validates the certification data (7.5.5.5) and keeps
// the status until the update key has been changed.
func (c *conn) userStatusChange(a *simAuth, req dnp3.Fragment, d []byte) {
	s := c.s
	u, err := dnp3.ParseUserStatus(d)
	if err != nil {
		c.authError(req.Seq(), a, 0, dnp3.AuthErrInvalidCertData)
		return
	}
	s.mu.Lock()
	var code uint8
	switch {
	case dnp3.Symmetric(u.Method) && a.authorityKey == nil, !dnp3.Symmetric(u.Method) && (a.authorityPub == nil || a.rsaKey == nil):
		code = dnp3.AuthErrUpdateMethod
	case dnp3.Symmetric(u.Method):
		want, err := dnp3.SymmetricAuthority{KeyChangeMethod: u.Method, Key: a.authorityKey}.Certify(u)
		if err != nil {
			code = dnp3.AuthErrUpdateMethod
		} else if !hmac.Equal(want, u.CertData) {
			code = dnp3.AuthErrInvalidCertData
		}
	default:
		if !dnp3.DSAVerify(u.Method, a.authorityPub, u.StatusInfo(), u.CertData) {
			code = dnp3.AuthErrInvalidSignature
		}
	}
	if code == 0 {
		usr := a.users[u.Name]
		if prev := usr; prev != nil && prev.pending != nil && u.SCS <= prev.pending.SCS {
			code = dnp3.AuthErrInvalidCertData // the SCS must increase
		}
	}
	if code == 0 {
		usr := a.users[u.Name]
		if u.Operation == dnp3.UserDelete {
			delete(a.users, u.Name)
		} else {
			if usr == nil {
				usr = &simUser{name: u.Name}
				a.users[u.Name] = usr
			}
			uc := u
			usr.pending = &uc
		}
	}
	s.mu.Unlock()
	if code != 0 {
		c.authError(req.Seq(), a, 0, code)
		return
	}
	c.send(dnp3.Fragment{Control: dnp3.AppFIR | dnp3.AppFIN | req.Seq(), Func: dnp3.FCAuthResponse, IIN: s.iin()})
}

func (c *conn) updateKeyRequest(a *simAuth, req dnp3.Fragment, d []byte) {
	s := c.s
	r, err := dnp3.ParseUpdateKeyRequest(d)
	s.mu.Lock()
	u := a.users[r.Name]
	if err != nil || u == nil || u.pending == nil || u.pending.Method != r.Method {
		s.mu.Unlock()
		c.authError(req.Seq(), a, 0, dnp3.AuthErrUnknownUser)
		return
	}
	a.ksq++
	if u.usr == 0 {
		u.usr = a.nextUSR
		a.nextUSR++
	}
	ochal := make([]byte, dnp3.ChallengeLen(r.Method))
	_, _ = rand.Read(ochal)
	a.ukc = &pendingUKC{user: u, method: r.Method, mchal: r.Challenge, ochal: ochal, ksq: a.ksq}
	rep := dnp3.UpdateKeyReply{KSQ: a.ksq, User: u.usr, Data: ochal}
	s.mu.Unlock()
	c.authResponse(req.Seq(), dnp3.AuthUpdateKeyChgReply, rep.Encode())
}

func (c *conn) updateKeyChange(a *simAuth, req dnp3.Fragment, blocks []dnp3.Block) {
	s := c.s
	if len(blocks) != 2 || len(blocks[0].Points) != 1 || len(blocks[1].Points) != 1 {
		c.authError(req.Seq(), a, 0, dnp3.AuthErrAuthFailed)
		return
	}
	chg, err := dnp3.ParseUpdateKeyReply(blocks[0].Points[0].Raw)
	proof, pv := blocks[1].Points[0].Raw, blocks[1].Header.Var
	s.mu.Lock()
	p := a.ukc
	a.ukc = nil
	var key []byte
	code := uint8(dnp3.AuthErrAuthFailed)
	if err == nil && p != nil && chg.KSQ == p.ksq && chg.User == p.user.usr {
		name := p.user.name
		var plain []byte
		if dnp3.Symmetric(p.method) {
			plain, err = dnp3.UnwrapKey(a.authorityKey, chg.Data)
		} else {
			h := sha256.New()
			if p.method == dnp3.KeyChangeRSA1024SHA1 {
				h = sha1.New()
			}
			plain, err = rsa.DecryptOAEP(h, rand.Reader, a.rsaKey, chg.Data, nil)
		}
		kl := 32
		if p.method == dnp3.KeyChangeAES128SHA1 || p.method == dnp3.KeyChangeRSA1024SHA1 {
			kl = 16
		}
		if err == nil && len(plain) >= len(name)+kl+len(p.ochal) && string(plain[:len(name)]) == name &&
			bytes.Equal(plain[len(name)+kl:len(name)+kl+len(p.ochal)], p.ochal) {
			k := plain[len(name) : len(name)+kl]
			switch {
			case dnp3.Symmetric(p.method) && pv == dnp3.AuthUpdateKeyChgConf:
				want, err := dnp3.ConfirmationMAC(p.method, k, a.name, p.mchal, p.ochal, p.ksq, p.user.usr)
				if err == nil && hmac.Equal(want, proof) {
					key = k
				}
			case !dnp3.Symmetric(p.method) && pv == dnp3.AuthUpdateKeyChgSig:
				pub, err := x509.ParsePKIXPublicKey(p.user.pending.PublicKey)
				if dp, ok := pub.(*dsa.PublicKey); err == nil && ok &&
					dnp3.DSAVerify(p.method, dp, dnp3.SignatureData(a.name, p.mchal, p.ochal, p.ksq, p.user.usr, chg.Data), proof) {
					key = k
				} else {
					code = dnp3.AuthErrInvalidSignature
				}
			}
		}
	}
	var reply []byte
	if key != nil {
		u := p.user
		u.updateKey, u.role = key, u.pending.Role
		u.pending = nil
		a.ukChanges++
		a.stats[dnp3.StatUpdateKeyChanges]++
		// The new key replaces the session keys' update key for this user.
		a.updateKey, a.user = key, u.usr
		a.ctrl, a.mon, a.status = nil, nil, dnp3.KeyStatusNotInit
		reply, _ = dnp3.ConfirmationMAC(p.method, key, u.name, p.ochal, p.mchal, p.ksq, u.usr)
	} else {
		a.stats[dnp3.StatFailedUpdateKeyChanges]++
	}
	s.mu.Unlock()
	if key == nil {
		c.authError(req.Seq(), a, chg.KSQ, code)
		return
	}
	c.authResponse(req.Seq(), dnp3.AuthUpdateKeyChgConf, reply)
}

// securityStatistics is the g121v1 chunk of the statistics (READ g121).
func (s *Sim) securityStatistics() []byte {
	if s.auth == nil {
		return nil
	}
	pts := make([]dnp3.Point, dnp3.NumSecurityStatistics)
	for i := range pts {
		pts[i] = dnp3.Point{Index: uint32(i), Value: float64(s.auth.stats[i]), Flags: 0x01, HasFlags: true}
	}
	b, _ := dnp3.EncodeBlock(121, 1, dnp3.Q8StartStop, pts)
	return b
}

// wrapResponse adds what the association's security settings need to a
// response or unsolicited response about to be sent (s.mu held): an
// aggressive-mode MAC after the master has challenged us, or a trailing
// challenge asking for an aggressive-mode confirmation.
func (a *simAuth) wrapResponse(f dnp3.Fragment) dnp3.Fragment {
	if a == nil || a.mon == nil {
		return f
	}
	if a.aggrResp && a.masterChal != nil && len(f.Objects) > 0 {
		n := dnp3.MACLen(a.masterMAL)
		obj := binary.LittleEndian.AppendUint32(nil, a.masterCSQ+1)
		obj = binary.LittleEndian.AppendUint16(obj, dnp3.UserDefault)
		body := append(dnp3.AppendHeader(nil, 120, dnp3.AuthAggressive, dnp3.Q8Count, 1, 0), obj...)
		body = append(body, f.Objects...)
		body = append(body, 120, dnp3.AuthMACObj, 0x5B, 1, byte(n), byte(n>>8))
		pre := dnp3.Fragment{Control: f.Control, Func: f.Func, IIN: f.IIN, Objects: body}
		mac, _ := dnp3.MAC(a.masterMAL, a.mon, a.masterChal, pre.Encode())
		pre.Objects = append(pre.Objects, mac...)
		return pre
	}
	if a.askConfirm && f.Control&dnp3.AppCON != 0 && len(f.Objects) > 0 {
		a.csq++
		cd := make([]byte, 4)
		_, _ = rand.Read(cd)
		ch := dnp3.Challenge{CSQ: a.csq, User: dnp3.UserUnknown, MAL: a.mal, Reason: dnp3.AuthReasonCritical, Data: cd}
		f.Objects = dnp3.AppendAuthObject(append([]byte(nil), f.Objects...), dnp3.AuthChallenge, ch.Encode())
		a.confirmChal = f.Encode()
		a.lastChal = a.confirmChal
	}
	return f
}

// checkConfirm verifies a confirmation the outstation asked to be sent
// in aggressive mode (s.mu held); plain confirmations pass when none was
// asked for.
func (a *simAuth) checkConfirm(f dnp3.Fragment) bool {
	if a == nil || a.confirmChal == nil {
		return true
	}
	chal := a.confirmChal
	_, _, mac, macAt, ok := dnp3.SplitAggressive(f.Objects)
	if !ok {
		a.stats[dnp3.StatAuthFailures]++
		return false
	}
	pre := dnp3.Fragment{Control: f.Control, Func: f.Func, Objects: f.Objects[:macAt]}.Encode()
	want, err := dnp3.MAC(a.mal, a.ctrl, chal, pre)
	if err != nil || !hmac.Equal(want, mac) {
		a.stats[dnp3.StatAuthFailures]++
		return false
	}
	a.confirmChal = nil
	a.aggrConfirms++
	return true
}

// TamperReplies makes the outstation see every challenge reply MAC with
// its first octet flipped (true) or unchanged (false).
func (s *Sim) TamperReplies(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !on {
		s.auth.replyMAC = nil
		return
	}
	s.auth.replyMAC = func(mac []byte) []byte {
		m := bytes.Clone(mac)
		if len(m) > 0 {
			m[0] ^= 0xFF
		}
		return m
	}
}
