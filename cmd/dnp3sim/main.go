// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Command dnp3sim serves a simulated DNP3 outstation, so a DNP3 master
// can be tried without a device. It listens on TCP (or UDP with -udp,
// TLS with -cert and -key) and holds a small demo database:
//
//	g1  binary input 0      breaker closed      (class 1 events)
//	g10 binary output 0     breaker command     (CROB latch/pulse)
//	g20 counter 0           energy pulses       (counts up every -report)
//	g30 analog input 0      feeder voltage, V   (moves every -report, class 2 events)
//	g30 analog input 1      feeder current, A
//	g40 analog output 0     voltage set point
//
// For example:
//
//	dnp3sim -listen 127.0.0.1:20000
//	dnp3sim -listen 127.0.0.1:20000 -udp -reply-port 20000
//	dnp3sim -listen 127.0.0.1:20000 -auth 00112233445566778899aabbccddeeff
//	dnp3sim -preset cp1542sp-1-irc -listen 127.0.0.1:20000 -auth 00112233445566778899aabbccddeeff
//
// The outstation address is -address (default 10) and the master's
// -master (default 1). -auth enables Secure Authentication v5 for user 1
// with that update key (hex, 16 or 32 octets). -preset runs the library's
// outstation limited to a vendor device profile's declared capabilities
// (cp1243-1 or cp1542sp-1-irc) instead of the demo database. All keys are
// demo values.
package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cB-Sigma/dnp3"
	"github.com/cB-Sigma/dnp3-sim/sim"
	"github.com/cB-Sigma/iotsec"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, nil); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "dnp3sim:", err)
		os.Exit(1)
	}
}

// running is what run started: the demo outstation or a preset.
type running struct {
	URL string
	Sim *sim.Sim // nil for a preset
}

// run serves until ctx ends. ready, when not nil, is called once the
// outstation listens.
func run(ctx context.Context, args []string, out io.Writer, ready func(running)) error {
	fs := flag.NewFlagSet("dnp3sim", flag.ContinueOnError)
	fs.SetOutput(out)
	listen := fs.String("listen", "127.0.0.1:20000", "address to listen on")
	udp := fs.Bool("udp", false, "serve UDP datagrams instead of TCP")
	replyPort := fs.Int("reply-port", 0, "over UDP, send every response to this port of the master (0: the request's source port)")
	address := fs.Uint("address", 10, "outstation (DNP3) address")
	master := fs.Uint("master", 1, "master (DNP3) address")
	authKey := fs.String("auth", "", "enable Secure Authentication v5 for user 1 with this update key (hex, 16 or 32 octets)")
	cert := fs.String("cert", "", "serve TCP under TLS with this certificate (PEM file; needs -key)")
	key := fs.String("key", "", "private key of -cert (PEM file)")
	report := fs.Duration("report", 5*time.Second, "how often the demo values change (0: never)")
	preset := fs.String("preset", "", "run a vendor device profile preset instead: cp1243-1 or cp1542sp-1-irc")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if *address > 0xFFEF || *master > 0xFFEF {
		return errors.New("-address and -master are 0 to 65519")
	}
	var update []byte
	if *authKey != "" {
		k, err := hex.DecodeString(*authKey)
		if err != nil || (len(k) != 16 && len(k) != 32) {
			return errors.New("-auth must be 32 or 64 hex digits")
		}
		update = k
	}
	var tlsServer iotsec.TLSServer
	if *cert != "" || *key != "" {
		if *udp {
			return errors.New("TLS needs TCP")
		}
		c, err := tls.LoadX509KeyPair(*cert, *key)
		if err != nil {
			return fmt.Errorf("-cert/-key: %w", err)
		}
		tlsServer = iotsec.StdTLS{Config: &tls.Config{Certificates: []tls.Certificate{c}, MinVersion: tls.VersionTLS12}}
	}
	switch *preset {
	case "":
	case "cp1243-1", "cp1542sp-1-irc":
		return runPreset(ctx, *preset, *listen, *udp, tlsServer, update, out, ready)
	default:
		return fmt.Errorf("-preset %q is not cp1243-1 or cp1542sp-1-irc", *preset)
	}

	s := sim.New(uint16(*address), uint16(*master))
	s.Listen, s.ReplyPort, s.TLS = *listen, *replyPort, tlsServer
	if *udp {
		s.Network = "udp"
	}
	if update != nil {
		s.EnableAuth(dnp3.UserDefault, update, dnp3.MACSHA256Trunc16)
	}
	s.Set(1, 0, 1, 0x01)
	s.Set(10, 0, 0, 0x01)
	s.Set(20, 0, 0, 0x01)
	s.Set(30, 0, 230.5, 0x01)
	s.Set(30, 1, 12.25, 0x01)
	s.Set(40, 0, 230, 0x01)
	if err := s.Start(); err != nil {
		return err
	}
	defer s.Stop()
	fmt.Fprintf(out, "dnp3sim: outstation %d (master %d) at %s\n", *address, *master, s.URL())
	if ready != nil {
		ready(running{URL: s.URL(), Sim: s})
	}
	var tick <-chan time.Time
	if *report > 0 {
		t := time.NewTicker(*report)
		defer t.Stop()
		tick = t.C
	}
	for n := 1; ; n++ {
		select {
		case <-ctx.Done():
			return nil
		case <-tick:
			v := 230.5 + float64(n%5) - 2
			s.Set(30, 0, v, 0x01)
			s.Set(20, 0, float64(n*10), 0x01)
			s.AddEvent(sim.Event{Group: 32, Var: 1, Index: 0, Value: v, Flags: 0x01, Class: 2})
			if n%3 == 0 {
				st := float64(n / 3 % 2)
				s.Set(1, 0, st, 0x01)
				s.AddEvent(sim.Event{Group: 2, Var: 2, Index: 0, Value: st, Flags: 0x01, Time: time.Now(), Class: 1})
			}
		}
	}
}

func runPreset(ctx context.Context, name, listen string, udp bool, tlsServer iotsec.TLSServer, update []byte, out io.Writer, ready func(running)) error {
	var url string
	var closeFn func()
	switch name {
	case "cp1243-1":
		if udp || tlsServer != nil {
			return errors.New("the cp1243-1 preset serves plain TCP only")
		}
		c, err := sim.StartCP1243(ctx, sim.CP1243Options{UpdateKey: update, Listen: listen})
		if err != nil {
			return err
		}
		url, closeFn = c.URL(), c.Close
		fmt.Fprintf(out, "dnp3sim: outstation %d (master %d)\n", c.Address, c.Master)
	default:
		opt := sim.CP1542Options{UpdateKey: update, UDP: udp, Listen: listen}
		if tlsServer != nil {
			// A server built from -cert/-key does not narrow its suites;
			// the preset's suite lists apply with a profile that can.
			opt.TLS = func(iotsec.TLSSelection) (iotsec.TLSServer, error) { return tlsServer, nil }
		}
		c, err := sim.StartCP1542(ctx, opt)
		if err != nil {
			return err
		}
		url, closeFn = c.URL(), c.Close
		fmt.Fprintf(out, "dnp3sim: outstation %d (master %d)\n", c.Address, c.Master)
	}
	defer closeFn()
	fmt.Fprintf(out, "dnp3sim: preset %s at %s\n", name, url)
	if ready != nil {
		ready(running{URL: url})
	}
	<-ctx.Done()
	return nil
}
