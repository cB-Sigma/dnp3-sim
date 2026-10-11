# Provenance

## How the code was written

Written for SigmaM2M, a oneM2M platform, in Go, by the author of the dnp3
module and from the same standard (IEEE Std 1815-2012, read in a licensed
copy). No code was ported or copied from another implementation. The
simulated outstation was first written next to SigmaM2M's DNP3 master to
test it without devices; the presets were added on 2026-10-06 from two
vendor device profiles supplied by the user. The simulator, its command
and the tests that drive it moved out of the dnp3 module into this one on
2026-10-11 (with `git mv`), so the library does not depend on its
simulator. For v0.3.0 (2026-10-12) `Sim.Profile` was added on top of the
library's new `profile` package.

## Sources

| Area (files) | Followed |
|---|---|
| Simulator (sim/sim.go, sim/auth.go, sim/extra.go) | IEEE 1815-2012 clauses 4 to 9 and 13, clause 7 for Secure Authentication, as the dnp3 module reads them; it reuses that module's codec |
| Presets (sim/cp1243.go, sim/cp1542.go) | Siemens CP 1243-1 DNP3 device profile, document version 1.1 (2016-11), and Siemens CP 1542SP-1 IRC DNP3 device profile, document version 2.2 (2022-11), both on the DNP Users Group device profile template; not redistributed |
| Command (cmd/dnp3sim) | none (flags are our own) |

No specification or vendor text is reproduced; comments cite clause and
item numbers in our own words.

## Notes on the vendor profiles (F- numbers)

Where a profile is silent, contradicts itself or IEEE 1815-2012, the
choice was recorded in SigmaM2M's register of findings, and code comments
cite its numbers. In our words:

| Note | Profile | Choice |
|---|---|---|
| F-605, F-1450 | both | requests that other items of the profile imply (freezes, record current time, cold restart, the g50v3 and g80v1 writes) are served although the implementation table leaves them out |
| F-606, F-1453 | both | a response fragment asks for confirmation when it carries events, the only setting that lets events be removed, although the profile says never or ticks several options |
| F-607 | cp1243-1 | the maximum time between select and operate is read as milliseconds, the unit of the profile's other timers |
| F-608 | both | variation 0 is served when some variation of the group is; the binary and analog output event rows keep the qualifiers as printed |
| F-1451 | cp1542sp-1-irc | CROBs are latch on and off only, as the table shows; a pulse is refused with status 4 although pulse times are given |
| F-1452 | cp1542sp-1-irc | events with relative time (g2v3, g4v3) are allowed as the table lists them, without g51 |
| F-1454 | cp1542sp-1-irc | the preset's TLS offer is narrowed to the suites both the profile and the IEC 62351-3 profile offer |
| F-1455 | cp1542sp-1-irc | double-precision variations ticked in part 3 but missing from the table are refused |

## Tests

| Test | Source |
|---|---|
| cp1243_test.go, cp1542_test.go | the presets' declared capabilities, from the vendor profiles above |
| sav5_test.go, procs1815_test.go, seams_test.go, session_test.go, sim/sim_test.go, cmd/dnp3sim/main_test.go, example_test.go | the dnp3 master against this simulator, written from the same standard; not a real device |

All keys, passwords, certificates and addresses are made-up demo values.
