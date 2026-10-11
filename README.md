# dnp3-sim

A simulated DNP3 outstation in Go, for testing DNP3 masters without a device.

[![Go Reference](https://pkg.go.dev/badge/github.com/cB-Sigma/dnp3-sim.svg)](https://pkg.go.dev/github.com/cB-Sigma/dnp3-sim) [![test](https://github.com/cB-Sigma/dnp3-sim/actions/workflows/test.yml/badge.svg)](https://github.com/cB-Sigma/dnp3-sim/actions/workflows/test.yml) [![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.24.0-00ADD8.svg)](go.mod)

The simulator answers class polls from a point database, buffers events
with and without time, sends unsolicited responses, sets IIN bits, takes
time synchronisation and controls, and has switches that make it fail
(control status, ignored requests, stop and restart). It runs over TCP,
TLS or UDP (with a fixed reply port), in-process or from the command
line, with Secure Authentication v5 when asked. Two presets behave like
vendor devices' published DNP3 profiles. It is built on the codec and
outstation of [dnp3](https://github.com/cB-Sigma/dnp3). Written for
SigmaM2M, a oneM2M platform; it has no dependency on it.

## What is simulated

| Package | What it does |
|---|---|
| `sim` | `New(outstation, master)`, then `Start` on TCP, UDP (`Network`, `ReplyPort`) or TLS (`TLS`, an `iotsec.TLSServer`): static points (`Set`, `Get`), buffered events (`AddEvent`), unsolicited responses, IIN bits (`SetNeedTime`, `SetRestart`, `SetOverflow`, `SetStuckIIN`), time synchronisation (`Clock`), controls (`Controls`, `SetControlStatus`), faults (`SetIgnore`, `SetDelay`, `Stop` and `Start`); Secure Authentication v5 (`EnableAuth`, aggressive mode, update key change with an authority, `TamperReplies`); file transfer (`PutFile`, `File`); what the master sent (`Requests`, `LinkFunctions`, `AuthStats`) |
| `sim` presets | `StartCP1243` and `StartCP1542`: the dnp3 outstation limited to the declared capabilities of the Siemens CP 1243-1 (document version 1.1) and CP 1542SP-1 IRC (document version 2.2) device profiles: objects, qualifiers, function codes, broadcast, Secure Authentication and the TLS suites they declare; `CP1243Declared`, `CP1542Declared` |
| `cmd/dnp3sim` | Serves the simulator with a small demo database, or a preset |

Not simulated: serial lines, device profile XML, a real device's timing
and firmware quirks beyond those the presets name.

## Install

```
go get github.com/cB-Sigma/dnp3-sim@latest
```

Requires Go 1.24.0 or later. The command:

```
go install github.com/cB-Sigma/dnp3-sim/cmd/dnp3sim@latest
```

## Command line

```
dnp3sim -listen 127.0.0.1:20000
dnp3sim -listen 127.0.0.1:20000 -udp -reply-port 20000
dnp3sim -listen 127.0.0.1:20000 -auth 00112233445566778899aabbccddeeff
dnp3sim -preset cp1542sp-1-irc -listen 127.0.0.1:20000
```

| Flag | Default | Meaning |
|---|---|---|
| `-listen` | `127.0.0.1:20000` | address to listen on |
| `-udp` | off | serve UDP datagrams instead of TCP |
| `-reply-port` | `0` | over UDP, send every response to this port of the master (0: the request's source port) |
| `-address`, `-master` | `10`, `1` | outstation and master DNP3 addresses |
| `-auth` | | Secure Authentication v5 for user 1 with this update key (hex, 16 or 32 octets) |
| `-cert`, `-key` | | serve TCP under TLS with this certificate and key (PEM files) |
| `-report` | `5s` | how often the demo values change (0: never) |
| `-preset` | | `cp1243-1` or `cp1542sp-1-irc` instead of the demo database |

The demo database: binary input 0 (class 1 events), binary output 0
(CROB latch and pulse), counter 0 counting up, analog inputs 0 and 1
(class 2 events), analog output 0.

## In Go tests

From `sim.Example`:

```go
s := sim.New(10, 1)
s.Set(30, 0, 49.5, 0x01) // g30v5: a 32-bit float
s.AddEvent(sim.Event{Group: 2, Var: 1, Index: 0, Value: 1, Flags: 0x01, Class: 1})
if err := s.Start(); err != nil {
	panic(err)
}
defer s.Stop()
m, err := dnp3.Dial(ctx, dnp3.MasterConfig{URL: s.URL(), MasterAddress: 1, OutstationAddress: 10})
frags, err := m.Request(ctx, dnp3.FCRead, dnp3.ClassRequest(1, 0))
// s.Requests() lists what the master asked for: [READ g60v2 g60v1]
```

## Demo values

Every key, password, certificate, address and point value in this module
is a made-up demo value. Do not use them for real devices.

## Documentation

Reference: https://pkg.go.dev/github.com/cB-Sigma/dnp3-sim

## Testing

```
go vet ./...
go test -race ./...
```

The tests at the module root drive the dnp3 master against the
simulator and the presets: Secure Authentication v5 (session key
change, aggressive mode, update key change both ways), link-layer
confirmations and keep-alive, file transfer, the master's polling session
(v0.2.0), the iotsec seams, and the
presets' declared profiles. Tests carry `// Covers: SIG-...` comments:
requirement IDs of the SigmaM2M project's compliance report, with no
meaning outside it. The simulator and the dnp3 master are written by the
same author from the same standard, so these tests show the two agree;
the dnp3 module's interop tests against opendnp3 are the independent
check.

## Related repositories

- [dnp3](https://github.com/cB-Sigma/dnp3): the DNP3 master and
  outstation.

## Status

v0.x. The API may change before v1.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## Licence

Apache-2.0 (see [LICENSE](LICENSE)). Copyright 2026 Abhinav Gautam.
[NOTICE](NOTICE) credits the vendor documents the presets follow and
names the trademarks used.
