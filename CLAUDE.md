# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`network_dash` (NetPulse) is a Rust + ratatui full-screen TUI that continuously evaluates
local network health (latency/jitter/loss, DNS, routing, throughput, WiFi link,
reachability). It is macOS-first and designed for a large terminal (~222×56), scaling down.

## Commands

```sh
cargo test                     # fast, hermetic suite (no network / no terminal)
cargo test <name>              # single test by substring, e.g. cargo test debouncer
cargo test -- --ignored        # live-network integration tests (real ping/dns/http)
cargo clippy --all-targets     # keep at ZERO warnings
cargo fmt                      # required before finishing (CI-style check: cargo fmt --check)

cargo run                      # launch the dashboard (needs a real TTY)
cargo run -- --once            # run every probe once, print a text summary, exit (headless)
cargo run -- --print-config    # print the resolved config as TOML (the full schema)
cargo run -- --config PATH     # use a specific config file
```

Verifying the TUI: it needs a real terminal, so `cargo run` fails cleanly (not hangs)
under the sandbox. Use `cargo run -- --once` to exercise the real probe pipeline
headlessly, and rely on `TestBackend` render tests for UI behavior.

## Development workflow (important)

This project is built strictly **red → green → refactor TDD**. Follow it for all changes:
1. Write a failing test first (stub bodies with `todo!()` or a deliberately-wrong skeleton);
   run the test and confirm it fails for the right reason.
2. Implement the minimum to pass.
3. Refactor; keep `cargo clippy --all-targets` at 0 warnings and run `cargo fmt`.

Keep pure logic separable from I/O so it stays unit-testable. Test I/O parsers against
in-code fixtures; mark tests that need real network/sockets `#[ignore]` (they run under
`cargo test -- --ignored`).

The live `#[ignore]` tier has two halves. Per-module ones live beside the code they exercise
(one real socket, one probe). Cross-cutting ones live in `tests/live.rs` and assert the whole
path — probe → `Sample` → reducer → health. Two rules there: never assert on network
*quality* (a test needing low latency fails on a train), and skip absent capability rather
than failing it (no IPv6, no Wi-Fi card — both are correct configurations).

## Architecture

Async (tokio), single-owner state, Elm-style reducer. It is a **lib + bin**: `main.rs` is
thin; everything lives in the library (so `tests/` and unit tests can import it).

Data flow:
```
probe tasks ── mpsc<Sample> ──▶ AppState (reducer) ──▶ ratatui render (~4–8 Hz)
(ping, dns, reachability, throughput, wifi, routing)
```

- **`event.rs`** — the `tokio::select!` loop (`run`/`run_inner`) multiplexing the crossterm
  `EventStream`, a render ticker, and the sample channel. `spawn_probe` drives each `Probe`
  on its own cadence. `map_key` (pure, tested) maps keys → `app::Action`. `run_once` is the
  headless one-shot path. `DemoProbe` is a synthetic fallback when a real ICMP socket can't
  be created.
- **`app.rs`** — `AppState` owns ALL state; the reducer is pure and synchronous. The caller
  passes the timestamp into `apply_sample(now, sample) -> Vec<Incident>` so it is fully
  deterministic and testable. `apply_sample` updates history, re-evaluates **debounced**
  health, and returns incidents (also pushed to the in-memory `events` ring); the event loop
  writes returned incidents to disk. `panel_health`/`overall_health` roll up worst-of.
- **`health.rs`** — `Health {Ok<Warn<Crit}` (ordered, so worst = max), `Thresholds`
  (higher/lower-is-worse), and the `Debouncer` hysteresis state machine that prevents a
  single spurious sample from flipping a panel / logging a bogus incident.
- **`history.rs`** — `RingBuffer<T>`, `Series` (rolling min/avg/max/p95/jitter), `LossWindow`
  (loss %). Pure math.
- **`metrics/`** — one module per probe, each implementing the `Probe` trait
  (`async tick() -> Vec<Sample>`) in `metrics/mod.rs`, plus the `Sample` enum and `MetricId`.
  Ping uses **unprivileged ICMP** (`surge-ping` with `sock_type_hint = Type::DGRAM`; no root
  on macOS) and is dual-stack: `pingable_targets` drops v6 targets on a host with no v6 route
  rather than pinging them into timeouts, and `AppState::retain_targets` then drops their rows
  (an empty series renders as a flawless `0ms / 0% loss`). `metrics::reachability`
  applies the same policy via `checkable_endpoints`. `tcp`/`tls` time a handshake apiece —
  what a real connection waits on that ICMP never sees — and `tls` also reads the leaf
  certificate's expiry off the completed handshake. WiFi/routing/gateway detection shell out
  and are split into a **pure parser**
  (unit-tested against fixtures: `parse_airport`, `parse_traceroute`, `net::parse_default_gateway`)
  and a thin subprocess wrapper. `FakeProbe` replays scripted samples for tests.
- **`ui/`** — `theme.rs` (the `Theme` palette struct + the health→border-style contract, a
  named catalog — `default`, `neon_sunset`, `moss_goblin`, `cybercity_night`, `cottage_fire`
  — via `Theme::by_name`/`resolve`/`next`), `widgets.rs` (`metric_block`,
  `line_chart`/`LineSeries`), `panels.rs` (each panel is a `pub fn(frame, area, &AppState)`
  renderable in isolation), and the composed `render`. The active `Theme` lives on
  `AppState.theme` (resolved from `config.ui.theme`, cycled live by the `t` key →
  `Action::CycleTheme`).
- **`diagnosis.rs`** — the correlation ruleset. `AppState` is projected into a pure `Signals`
  snapshot, `diagnose_signals` reasons over it, and `primary_layer` is a *reading* of that
  list rather than a second ruleset (two engines disagree, and then the panel and the event
  feed tell the user different stories about one outage).
- **`config.rs`** — complete built-in defaults; TOML load where any omitted field falls back
  to its default (`#[serde(default)]` on every container). `incidents.rs` — JSONL log written
  through an injectable `Write` sink.

## Conventions / gotchas

- **The core visual contract**: an unhealthy panel's border goes yellow/red. It lives in
  `Theme::border_style(Health)` applied via `widgets::metric_block(title, health, &theme)`;
  UI tests assert border cell colors via ratatui `TestBackend` (`buffer()[(x,y)].fg`). Every
  theme in the catalog must preserve this (warn = amber/yellow family, crit = red family) —
  `theme.rs`'s `every_theme_keeps_the_contract` test enforces it.
- ratatui is **0.30** / crossterm **0.29** (unified versions — don't split crossterm major).
- Adding a new metric touches several places in lockstep: `Sample` variant (`metrics/mod.rs`),
  a reducer arm + state + `panel_health` (`app.rs`), a `MetricId`, a probe module, a panel,
  and wiring in `event::run_inner`.
- **If the new metric joins `overall_health`, it needs a `diagnosis.rs` rule too.** Otherwise
  the header banner says PROBLEM while the DIAGNOSIS panel below it says "No problems
  detected" — `the_header_never_claims_worse_than_the_diagnosis_can_explain` enforces this.
- An absent capability is not a fault. IPv6 on a v4-only host is the standing example: drop
  the probe target rather than reporting 100% loss, which is the loudest possible way to say
  "this is normal".
- **An empty answer is not a failed one.** DNS is the standing example: a resolver that
  replies "I have nothing" (NODATA/NXDOMAIN) is *up*, and painting it the same red as one
  that never replied is how an intercepted resolver got reported as unreachable. `dns::Answer`
  keeps `Addresses`/`Empty`/`Silence` apart all the way to the panel, and interception is
  reported as its own finding (`dns::Integrity`) rather than smuggled into the timing health.
- Probe names must be **absolute** (trailing dot). A relative name picks up the OS search
  list, so a "does not exist" control name can resolve via a search domain and read as a
  hijack (`dns::absolute`).
- Incident log path (macOS): `~/Library/Application Support/network_dash/incidents.jsonl`.
- Keep probes lightweight (no active bandwidth flooding); that is a hard requirement.
