package sim

import (
	"fmt"
	"strings"
	"time"

	"github.com/cB-Sigma/dnp3"
)

// Further outstation functions: cold and warm restart (4.4.9), freezes
// without acknowledgement and at a time (4.4.6 to 4.4.8), assign class
// (4.4.14) and sequential file transfer (4.4.17 to 4.4.19, 5.3).

type simFile struct {
	data    []byte
	created time.Time
	dir     bool
}

type openFile struct {
	name    string
	mode    uint16
	block   uint32
	max     uint16
	written []byte
}

type fileState struct {
	files    map[string]*simFile
	open     map[uint32]*openFile
	next     uint32
	delayed  bool     // answer file requests with a null response and report the objects as class 3 events
	pending  [][]byte // file event chunks waiting for a class 3 poll
	password string
	key      uint32
}

// PutFile stores a file (a name ending in "/" is a directory; its content
// is generated from the files below it).
func (s *Sim) PutFile(name string, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fileStore().files[name] = &simFile{data: data, created: time.UnixMilli(1_600_000_000_000).UTC(), dir: strings.HasSuffix(name, "/")}
}

// File returns a stored file.
func (s *Sim) File(name string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.fileStore().files[name]
	if f == nil {
		return nil, false
	}
	return f.data, true
}

// DelayFileAnswers makes file requests answered by a null response, the
// file objects following as class 3 events (5.3.3).
func (s *Sim) DelayFileAnswers(on bool) { s.mu.Lock(); s.fileStore().delayed = on; s.mu.Unlock() }

// RequireFilePassword makes OPEN_FILE and DELETE_FILE need the key of an
// AUTHENTICATE_FILE with this password.
func (s *Sim) RequireFilePassword(pw string) { s.mu.Lock(); s.fileStore().password = pw; s.mu.Unlock() }

// OpenFiles counts open file handles.
func (s *Sim) OpenFiles() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.fileStore().open) }

// SetRestartDelay sets the delay reported to COLD_RESTART and
// WARM_RESTART (g52v1 when whole seconds, else g52v2).
func (s *Sim) SetRestartDelay(d time.Duration) { s.mu.Lock(); s.restartDelay = d; s.mu.Unlock() }

// Assignments lists the ASSIGN_CLASS sets received ("class 2: g30v0 all").
func (s *Sim) Assignments() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.assigned...)
}

func (s *Sim) fileStore() *fileState {
	if s.fs == nil {
		s.fs = &fileState{files: map[string]*simFile{}, open: map[uint32]*openFile{}, next: 0x100}
	}
	return s.fs
}

// extra handles the functions of this file. It returns the response
// chunks and IIN2 bits, and whether it handled the request and whether a
// response is due.
func (c *conn) extra(req dnp3.Fragment) (chunks [][]byte, iin2 dnp3.IIN, handled, respond bool) {
	s := c.s
	switch req.Func {
	case dnp3.FCColdRestart, dnp3.FCWarmRestart:
		s.mu.Lock()
		d := s.restartDelay
		s.freezes = append(s.freezes, dnp3.FuncName(req.Func))
		s.mu.Unlock()
		var b []byte
		if d%time.Second == 0 {
			b, _ = dnp3.EncodeBlock(52, 1, dnp3.Q8Count, []dnp3.Point{{Value: float64(d / time.Second)}})
		} else {
			b, _ = dnp3.EncodeBlock(52, 2, dnp3.Q8Count, []dnp3.Point{{Value: float64(d / time.Millisecond)}})
		}
		s.mu.Lock()
		s.restart = true
		for k := range s.unsol {
			s.unsol[k] = false
		}
		s.mu.Unlock()
		return [][]byte{b}, 0, true, true
	case dnp3.FCDirectOperateNR:
		_, _ = s.control(dnp3.Fragment{Control: req.Control, Func: dnp3.FCDirectOperate, Objects: req.Objects})
		return nil, 0, true, false
	case dnp3.FCImmedFreezeNR, dnp3.FCFreezeClearNR:
		fc := dnp3.FCImmedFreeze
		if req.Func == dnp3.FCFreezeClearNR {
			fc = dnp3.FCFreezeClear
		}
		_ = s.freeze(dnp3.Fragment{Func: byte(fc), Objects: req.Objects})
		s.mu.Lock()
		s.freezes[len(s.freezes)-1] = strings.Replace(s.freezes[len(s.freezes)-1], dnp3.FuncName(byte(fc)), dnp3.FuncName(req.Func), 1)
		s.mu.Unlock()
		return nil, 0, true, false
	case dnp3.FCFreezeAtTime, dnp3.FCFreezeAtTimeNR:
		blocks, err := dnp3.ParseObjects(req.Objects, true)
		if err != nil || len(blocks) < 2 || blocks[0].Header.Group != 50 || blocks[0].Header.Var != 2 {
			return nil, dnp3.IINParameterError, true, req.Func == dnp3.FCFreezeAtTime
		}
		p := blocks[0].Points[0]
		var hs []string
		for _, b := range blocks[1:] {
			hs = append(hs, b.Header.String())
		}
		s.mu.Lock()
		s.freezes = append(s.freezes, fmt.Sprintf("%s %d %d %s", dnp3.FuncName(req.Func), p.Value.(time.Time).UnixMilli(), p.Interval, strings.Join(hs, " ")))
		s.mu.Unlock()
		return nil, 0, true, req.Func == dnp3.FCFreezeAtTime
	case dnp3.FCAssignClass:
		blocks, err := dnp3.ParseObjects(req.Objects, false)
		if err != nil || len(blocks) == 0 || blocks[0].Header.Group != 60 {
			return nil, dnp3.IINParameterError, true, true
		}
		var sets []string
		class := 0
		for _, b := range blocks {
			if b.Header.Group == 60 {
				class = int(b.Header.Var) - 1
				continue
			}
			if b.Header.Group == 120 || b.Header.Group == 122 {
				if class == 0 {
					return nil, dnp3.IINNoFuncCodeSupport, true, true
				}
			}
			r := "all"
			if b.Header.Qual != dnp3.QAll {
				r = fmt.Sprintf("%d-%d", b.Header.Start, b.Header.Stop)
			}
			sets = append(sets, fmt.Sprintf("class %d: %s %s", class, b.Header.String(), r))
		}
		s.mu.Lock()
		s.assigned = append(s.assigned, sets...)
		s.mu.Unlock()
		return nil, 0, true, true
	case dnp3.FCOpenFile, dnp3.FCCloseFile, dnp3.FCDeleteFile, dnp3.FCAbortFile, dnp3.FCGetFileInfo, dnp3.FCAuthenticateFile:
		ch, iin := c.fileRequest(req)
		return ch, iin, true, true
	case dnp3.FCRead, dnp3.FCWrite:
		blocks, err := dnp3.ParseObjects(req.Objects, req.Func == dnp3.FCWrite)
		if err != nil || len(blocks) != 1 || blocks[0].Header.Group != 70 || blocks[0].Header.Var != 5 || (req.Func == dnp3.FCRead && blocks[0].Header.Qual != dnp3.QFreeFormat) {
			return nil, 0, false, false
		}
		// A READ of g70v5 carries its object (handle and block).
		if req.Func == dnp3.FCRead {
			blocks, err = dnp3.ParseObjects(req.Objects, true)
			if err != nil {
				return nil, dnp3.IINParameterError, true, true
			}
		}
		ch, iin := c.fileData(req.Func, blocks[0].Points[0].Raw)
		return ch, iin, true, true
	}
	return nil, 0, false, false
}

func fileObject(v uint8, data []byte) []byte {
	b, _ := dnp3.EncodeBlock(70, v, dnp3.QFreeFormat, []dnp3.Point{{Raw: data}})
	return b
}

// answerFile returns the chunk now, or queues it as a class 3 event.
func (s *Sim) answerFile(chunk []byte) [][]byte {
	fs := s.fileStore()
	if fs.delayed {
		fs.pending = append(fs.pending, chunk)
		return nil
	}
	return [][]byte{chunk}
}

// directory is the content of a directory file: a g70v7 descriptor of each
// file directly below it.
func (fs *fileState) directory(dir string) []byte {
	var out []byte
	for n, f := range fs.files {
		rest, ok := strings.CutPrefix(n, dir)
		if !ok || rest == "" || strings.Contains(strings.TrimSuffix(rest, "/"), "/") {
			continue
		}
		t := uint16(1)
		if f.dir {
			t = 0
		}
		out = append(out, dnp3.FileDescriptor{Type: t, Size: uint32(len(f.data)), Created: f.created, Permissions: 0x01FF, Name: rest}.Encode()...)
	}
	return out
}

func (c *conn) fileRequest(req dnp3.Fragment) ([][]byte, dnp3.IIN) {
	s := c.s
	blocks, err := dnp3.ParseObjects(req.Objects, true)
	if err != nil || len(blocks) != 1 || blocks[0].Header.Group != 70 || len(blocks[0].Points) != 1 {
		return nil, dnp3.IINParameterError
	}
	raw := blocks[0].Points[0].Raw
	s.mu.Lock()
	defer s.mu.Unlock()
	fs := s.fileStore()
	switch req.Func {
	case dnp3.FCAuthenticateFile:
		a, err := dnp3.ParseFileAuth(raw)
		if err != nil {
			return nil, dnp3.IINParameterError
		}
		var key uint32
		if fs.password != "" && a.Password == fs.password {
			fs.key = uint32(time.Now().UnixNano()) | 1
			key = fs.key
		}
		return [][]byte{fileObject(2, dnp3.FileAuth{Key: key}.Encode())}, 0
	case dnp3.FCOpenFile, dnp3.FCDeleteFile:
		cmd, err := dnp3.ParseFileCommand(raw)
		if err != nil {
			return nil, dnp3.IINParameterError
		}
		st := dnp3.FileStatus{RequestID: cmd.RequestID}
		f := fs.files[cmd.Name]
		switch {
		case fs.password != "" && (cmd.AuthKey == 0 || cmd.AuthKey != fs.key):
			st.Status = 1 // permission denied
		case req.Func == dnp3.FCDeleteFile && f == nil:
			st.Status = 3
		case req.Func == dnp3.FCDeleteFile:
			delete(fs.files, cmd.Name)
		case cmd.Mode == dnp3.FileModeRead && f == nil:
			st.Status = 3
		case cmd.Mode < dnp3.FileModeRead || cmd.Mode > dnp3.FileModeAppend:
			st.Status = 2
		default:
			fs.next++
			st.Handle, st.MaxBlock = fs.next, min(cmd.MaxBlock, 64)
			o := &openFile{name: cmd.Name, mode: cmd.Mode, max: st.MaxBlock}
			if f != nil {
				st.Size = uint32(len(f.data))
				if f.dir {
					st.Size = uint32(len(fs.directory(cmd.Name)))
				}
			}
			if cmd.Mode == dnp3.FileModeWrite {
				st.Size = 0
			}
			if cmd.Mode == dnp3.FileModeAppend && f != nil {
				o.written = append([]byte(nil), f.data...)
			}
			fs.open[st.Handle] = o
		}
		fs.key = 0 // one use only
		return s.answerFile(fileObject(4, st.Encode())), 0
	case dnp3.FCCloseFile, dnp3.FCAbortFile:
		st, err := dnp3.ParseFileStatus(raw)
		if err != nil {
			return nil, dnp3.IINParameterError
		}
		o := fs.open[st.Handle]
		if o == nil {
			st.Status = 6 // invalid handle
		} else {
			if req.Func == dnp3.FCCloseFile && o.mode != dnp3.FileModeRead {
				fs.files[o.name] = &simFile{data: o.written, created: time.Now().UTC()}
			}
			delete(fs.open, st.Handle)
		}
		return s.answerFile(fileObject(4, st.Encode())), 0
	default: // GET_FILE_INFO
		d, err := dnp3.ParseFileDescriptor(raw)
		if err != nil {
			return nil, dnp3.IINParameterError
		}
		f := fs.files[d.Name]
		if f == nil {
			return s.answerFile(fileObject(4, dnp3.FileStatus{RequestID: d.RequestID, Status: 3}.Encode())), 0
		}
		d.Type, d.Size, d.Created, d.Permissions = 1, uint32(len(f.data)), f.created, 0x01FF
		if f.dir {
			entries, _ := dnp3.ParseDirectory(fs.directory(d.Name))
			d.Type, d.Size = 0, uint32(len(entries))
		}
		return s.answerFile(fileObject(7, d.Encode())), 0
	}
}

func (c *conn) fileData(fc byte, raw []byte) ([][]byte, dnp3.IIN) {
	s := c.s
	t, err := dnp3.ParseFileTransport(raw)
	if err != nil {
		return nil, dnp3.IINParameterError
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	fs := s.fileStore()
	o := fs.open[t.Handle]
	status := func(code uint8) [][]byte {
		return s.answerFile(fileObject(6, dnp3.FileTransportStatus{Handle: t.Handle, Block: t.Block, Last: t.Last, Status: code}.Encode()))
	}
	switch {
	case o == nil:
		return status(6), 0
	case t.Block != o.block:
		delete(fs.open, t.Handle)
		return status(20), 0 // bad block number
	}
	o.block++
	if fc == dnp3.FCWrite {
		if o.mode == dnp3.FileModeRead || len(t.Data) > int(o.max) {
			return status(7), 0
		}
		o.written = append(o.written, t.Data...)
		return status(0), 0
	}
	f := fs.files[o.name]
	data := f.data
	if f.dir {
		data = fs.directory(o.name)
	}
	start := min(int(t.Block)*int(o.max), len(data))
	end := min(start+int(o.max), len(data))
	out := dnp3.FileTransport{Handle: t.Handle, Block: t.Block, Last: end == len(data), Data: data[start:end]}
	return s.answerFile(fileObject(5, out.Encode())), 0
}
