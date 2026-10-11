# Changelog

## v0.3.0 (2026-10-12)

- Builds against github.com/cB-Sigma/dnp3 v0.3.0.
- `Sim.Profile` writes the simulated outstation's device profile
  document (XML) with dnp3's new `profile` package; tested by reading it
  back and defining an outstation database from it.
- No change to the simulator's behaviour or its command.

## v0.2.0 (2026-10-11)

- Builds against github.com/cB-Sigma/dnp3 v0.2.0.
- New test: the master's polling session (`RunSession`) against the
  simulated outstation: restart indication cleared, clock synchronised
  when asked, an integrity poll after an event buffer overflow, the
  start-up again after a restart.
- No change to the simulator's behaviour or its command.

## v0.1.0 (2026-10-11)

First release.
