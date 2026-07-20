# NetPulse (`network_dash`)

A colorful, full-screen terminal dashboard that continuously evaluates your machine's
network health — latency, jitter, packet loss, DNS, routing, throughput, and wireless
link/reachability. Leave it running; when something feels off, glance at it. Each panel's
**border turns yellow (degraded) or red (problem)** the moment that metric is unhealthy,
and threshold breaches are written to an incident log so you can see what happened while
you were away.

Built for macOS (uses unprivileged ICMP and `system_profiler` for WiFi); the pure logic is
cross-platform and the I/O is behind small wrappers.

## Highlights

- **No root required.** ICMP uses an unprivileged datagram socket (`SOCK_DGRAM`).
- **Lightweight.** ~3 pings/sec, a DNS lookup every 5s, an HTTP check every 15s, a
  traceroute every 60s, and passive throughput counters. No active bandwidth flooding.
- **Health at a glance.** Per-panel red/yellow borders + a top status banner (worst-of-all).
- **Incident log.** Debounced threshold breaches are appended as JSON lines to
  `~/Library/Application Support/network_dash/incidents.jsonl`.
- **Zero-config**, with a TOML file for overrides.

## Metrics

| Panel | What it measures |
|-------|------------------|
| Latency & Jitter | ICMP RTT + jitter to the gateway and internet hosts (1.1.1.1, 8.8.8.8) |
| Packet Loss | unanswered echoes over a rolling window, per target |
| DNS Health | lookup latency + failures across system / Cloudflare / Google resolvers |
| Routing & Path | hop count, reachability, and route-change detection (traceroute) |
| Throughput | passive rx/tx rates from OS interface counters |
| Link & Reachability | WiFi SSID/RSSI + HTTP(S)/captive-portal/IPv6 reachability |

## Usage

```sh
cargo run                # launch the full-screen dashboard
cargo run -- --once      # run every probe once, print a text summary, exit
cargo run -- --print-config   # print the resolved config as TOML
cargo run -- --config path/to/config.toml
```

Keys: `q`/`Esc` quit · `r` refresh · `p` pause · `c` clear events · `t` cycle theme · `?` help.

The layout is designed for a large terminal (≈222×56) but scales to the actual size.

## Themes

Five built-in color themes. Set one in config with `ui.theme = "<name>"`, or press `t`
to cycle through them live while the dashboard is running:

| Name | Feel |
|------|------|
| `default` | neutral terminal palette (cyan/green/yellow/red) |
| `neon_sunset` | hot-pink accent, teal/amber health, warm neon charts |
| `moss_goblin` | earthy moss/ochre/rust, mushroom-cottage forest |
| `cybercity_night` | cyberpunk cyan + neon green/magenta on steel blue |
| `cottage_fire` | cozy hearth: warm orange, ember/gold, firelit charts |

The four non-default themes use 24-bit color (best on a true-color terminal). Whatever the
theme, the health contract holds: healthy borders stay quiet, degraded goes amber, problem
goes red. An unknown `ui.theme` name silently falls back to `default`.

## Configuration

Defaults live in code; drop a `config.toml` in the platform config dir (see
`--print-config` for the full schema) to override targets, cadences, thresholds, the
throughput floor, and the theme (`ui.theme`). Any omitted field falls back to its default.

## Architecture

Async (tokio) with an Elm-style reducer. Each metric is an independent probe task that
streams `Sample`s over an mpsc channel to a single UI task that owns all state, evaluates
debounced health, emits incidents, and redraws (~4–8 Hz).

```
probe tasks ──mpsc──▶ AppState (history + debounced health + events) ──▶ ratatui render
   (ping, dns, reachability, throughput, wifi, routing)
```

Modules: `health` (thresholds + debounce), `history` (ring buffers + rolling stats),
`config`, `incidents` (JSONL log), `app` (the reducer), `metrics/*` (probes + pure
parsers), `ui/*` (theme, widgets, panels), `event`/`tui` (event loop + terminal).

## Development

Built test-first (red → green → refactor). The fast suite is hermetic — no network or
terminal:

```sh
cargo test                 # ~100 unit tests (pure logic + TestBackend rendering)
cargo test -- --ignored    # live-network integration tests (ping/dns/http)
cargo clippy --all-targets
cargo fmt
```

UI is tested via ratatui's `TestBackend` — including asserting that an unhealthy panel's
border cells render red. Probe parsers (`system_profiler`, `traceroute`, `route`) are
unit-tested against captured fixtures; the socket/subprocess calls are thin wrappers
exercised by the ignored integration tests.
