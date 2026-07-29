//! The live tier: tests that talk to the real network.
//!
//! Everything here is `#[ignore]`d, so `cargo test` stays hermetic and these run only under
//! `cargo test -- --ignored`. They exist because the fast suite deliberately cannot answer one
//! question: does the wiring between a real socket and the dashboard actually work? Unit tests
//! prove each parser against a fixture, and a fixture cannot tell you that the ICMP identifier
//! is wrong, that the resolver config never reaches the resolver, or that a probe returns
//! samples the reducer silently ignores.
//!
//! So these are integration tests in the strict sense: probe → `Sample` → reducer → health,
//! asserted at the far end. Where a module already has its own live unit test (`ping.rs`,
//! `tcp.rs`, `tls.rs`, …) this file does not repeat it — it picks up where that one stops.
//!
//! Two rules keep them honest rather than merely green:
//!
//! * **No assertions on network quality.** A test that requires low latency fails on a train.
//!   These assert that a measurement *happened* and that the pipeline carried it, never that
//!   the number was good.
//! * **Absent capability is skipped, not failed.** A host with no IPv6 and a Mac with no Wi-Fi
//!   card are both correct configurations. They print why they skipped and pass.

use std::time::Duration;

use network_dash::app::AppState;
use network_dash::config::Config;
use network_dash::diagnosis::diagnose;
use network_dash::metrics::{Probe, Sample};
use pretty_assertions::assert_eq;

/// Announce a skip so a passing run cannot quietly mean "nothing was tested".
fn skipped(reason: &str) {
    eprintln!("SKIPPED: {reason}");
}

/// A config with the debouncer wide open, so one real sample is enough to move a verdict.
/// The dwell times exist to filter noise over minutes; a test that waited for them would be
/// measuring `tokio::time`, not the network.
fn immediate_config() -> Config {
    let mut cfg = Config::default();
    cfg.thresholds.trip_after_secs = 0.0;
    cfg.thresholds.clear_after_secs = 0.0;
    cfg
}

// --- ICMP, both families ---

#[tokio::test]
#[ignore = "requires network"]
async fn icmp_reaches_the_public_internet_over_v4() {
    let targets = vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()];
    let mut probe = network_dash::metrics::ping::PingProbe::new(&targets, Duration::from_secs(3))
        .expect("an unprivileged ICMP datagram socket should be available on macOS");
    let samples = probe.tick().await;
    assert_eq!(samples.len(), 2, "one sample per target: {samples:?}");

    let answered = samples
        .iter()
        .filter(|s| {
            matches!(
                s,
                Sample::Latency {
                    rtt_ms: Some(_),
                    ..
                }
            )
        })
        .count();
    assert!(
        answered > 0,
        "at least one well-known resolver should answer a ping: {samples:?}"
    );

    // …and the reducer keeps it. A probe that measures correctly into a state that drops the
    // sample is the failure this whole file exists to catch.
    let mut state = AppState::new(immediate_config());
    let now = chrono::Utc::now();
    for s in samples {
        state.apply_sample(now, s);
    }
    let recorded = state
        .targets
        .values()
        .filter(|t| t.latency_ms.latest().is_some())
        .count();
    assert_eq!(recorded, answered, "every answered ping reached the state");
}

#[tokio::test]
#[ignore = "requires network"]
async fn icmp_reaches_the_public_internet_over_v6() {
    if !network_dash::metrics::ping::has_ipv6_route() {
        skipped("this host has no IPv6 route — a valid network, not a fault");
        return;
    }
    let targets = vec!["2606:4700:4700::1111".to_string()];
    let mut probe = network_dash::metrics::ping::PingProbe::new(&targets, Duration::from_secs(3))
        .expect("an ICMPv6 datagram socket should be available where a v6 route exists");
    assert_eq!(
        probe.target_names(),
        targets,
        "a v6 target must not be filtered out on a v6-capable host"
    );
    let samples = probe.tick().await;
    assert!(
        samples.iter().any(|s| matches!(
            s,
            Sample::Latency {
                rtt_ms: Some(_),
                ..
            }
        )),
        "a v6 host should get a v6 answer: {samples:?}"
    );
}

#[test]
#[ignore = "requires network"]
fn a_host_without_ipv6_still_has_something_to_ping() {
    let cfg = Config::default();
    let targets = network_dash::metrics::ping::pingable_targets(
        &cfg.targets.internet,
        network_dash::metrics::ping::has_ipv6_route(),
    );
    assert!(
        !targets.is_empty(),
        "the shipped defaults must leave at least one pingable target on any host"
    );
}

// --- DNS ---

#[tokio::test]
#[ignore = "requires network / DNS"]
async fn public_resolvers_answer_and_the_dashboard_records_them() {
    let cfg = immediate_config();
    let mut probe =
        network_dash::metrics::dns::DnsProbe::new(&cfg.resolvers, Duration::from_secs(3));
    let samples = probe.tick().await;
    assert_eq!(
        samples.len(),
        cfg.resolvers.len(),
        "one sample per configured resolver: {samples:?}"
    );
    assert!(
        samples.iter().any(|s| matches!(
            s,
            Sample::Dns {
                latency_ms: Some(_),
                ..
            }
        )),
        "at least one public resolver should answer: {samples:?}"
    );

    let mut state = AppState::new(cfg);
    let now = chrono::Utc::now();
    for s in samples {
        state.apply_sample(now, s);
    }
    assert!(
        state.resolvers.values().any(|r| r.last_ok),
        "a successful lookup must reach the DNS panel"
    );
}

#[tokio::test]
#[ignore = "requires network / DNS"]
async fn the_integrity_check_forms_an_opinion_about_every_resolver() {
    let cfg = Config::default();
    let mut probe = network_dash::metrics::dns::DnsIntegrityProbe::new(
        &cfg.resolvers,
        Duration::from_secs(3),
        1,
    );
    let samples = probe.tick().await;
    // Deliberately not asserting `hijacked == false`: on a network that does intercept DNS,
    // `true` is the correct answer and failing here would be the probe working.
    assert_eq!(
        samples.len(),
        cfg.resolvers.len(),
        "every resolver gets a verdict, honest or not: {samples:?}"
    );
    for s in &samples {
        assert!(matches!(s, Sample::DnsIntegrity { .. }), "{s:?}");
    }
}

// --- TCP and TLS ---

#[tokio::test]
#[ignore = "requires network"]
async fn a_real_handshake_is_timed_into_the_transport_panel() {
    let mut probe = network_dash::metrics::tcp::TcpProbe::new(
        network_dash::metrics::tcp::TcpProbe::default_endpoints(),
        Duration::from_secs(5),
    );
    let samples = probe.tick().await;
    assert!(
        samples.iter().any(|s| matches!(
            s,
            Sample::TcpHandshake {
                connect_ms: Some(_),
                ..
            }
        )),
        "port 443 on a well-known host should open: {samples:?}"
    );

    let mut state = AppState::new(immediate_config());
    let now = chrono::Utc::now();
    for s in samples {
        state.apply_sample(now, s);
    }
    assert!(
        state.tcp.values().any(|e| e.connect_ms.latest().is_some()),
        "the timing must reach the panel that draws it"
    );
}

#[tokio::test]
#[ignore = "requires network"]
async fn a_real_certificate_arrives_with_time_left_on_it() {
    let Some(mut probe) = network_dash::metrics::tls::TlsProbe::new(
        network_dash::metrics::tls::TlsProbe::default_endpoints(),
        Duration::from_secs(10),
    ) else {
        skipped("the platform trust store would not load; there is no verdict to check");
        return;
    };
    let samples = probe.tick().await;

    let mut state = AppState::new(immediate_config());
    let now = chrono::Utc::now();
    for s in samples.clone() {
        state.apply_sample(now, s);
    }
    let dated = state
        .tls
        .values()
        .filter_map(|e| e.expires_in_days)
        .collect::<Vec<_>>();
    assert!(
        !dated.is_empty(),
        "a completed handshake must yield an expiry date: {samples:?}"
    );
    // A *live* site presenting an already-expired certificate would have failed verification
    // and never reached here — so a negative number means the parse is wrong, not the host.
    assert!(
        dated.iter().all(|&d| d > 0),
        "a verified certificate cannot already be expired: {dated:?}"
    );
}

// --- Throughput ---

#[tokio::test]
#[ignore = "requires network; downloads a few MB"]
async fn the_capacity_probe_reports_positive_mbps() {
    let cfg = Config::default();
    let mut probe = network_dash::metrics::throughput::CapacityProbe::new(cfg.throughput.probe_url);
    let samples = probe.tick().await;
    let mbps = samples.iter().find_map(|s| match s {
        Sample::ThroughputProbe { mbps } => Some(*mbps),
        _ => None,
    });
    let Some(mbps) = mbps else {
        panic!("the capacity probe produced no reading: {samples:?}");
    };
    // Positive, not fast: the only wrong answer is zero, which is what a broken byte-count or
    // a broken elapsed-time calculation both produce.
    assert!(mbps > 0.0, "{mbps} Mbps");
}

#[tokio::test]
#[ignore = "requires network"]
async fn passive_counters_read_the_real_interface() {
    let mut probe = network_dash::metrics::throughput::ThroughputProbe::new();
    // The first tick establishes the baseline; a rate needs two readings to exist at all.
    probe.tick().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let samples = probe.tick().await;
    assert!(
        samples
            .iter()
            .any(|s| matches!(s, Sample::Throughput { .. })),
        "a second reading should yield a rate: {samples:?}"
    );
}

// --- macOS-specific paths ---

#[tokio::test]
#[cfg(target_os = "macos")]
#[ignore = "spawns system_profiler; macOS only"]
async fn the_mac_reports_its_own_wireless_link() {
    let samples = network_dash::metrics::link::WifiProbe.tick().await;
    let Some(Sample::Link { rssi_dbm, ssid, .. }) = samples.first() else {
        skipped("no Wi-Fi card, or Wi-Fi is off — a wired Mac is a valid configuration");
        return;
    };
    // Both fields come from the same parse, so either one being present proves the path; RSSI
    // is the one the panel colours on, and a plausible range catches a units mix-up.
    if let Some(rssi) = rssi_dbm {
        assert!(
            (-100.0..0.0).contains(rssi),
            "RSSI is negative dBm, got {rssi}"
        );
    } else {
        assert!(
            ssid.is_some(),
            "a Link sample with neither signal nor network name is an empty parse: {samples:?}"
        );
    }
}

#[tokio::test]
#[cfg(target_os = "macos")]
#[ignore = "spawns traceroute; macOS only"]
async fn traceroute_finds_a_path_to_the_internet() {
    let cfg = Config::default();
    let mut probe = network_dash::metrics::routing::RoutingProbe::new(
        cfg.targets.routing_target,
        cfg.targets.max_hops,
    );
    let samples = probe.tick().await;
    let Some(Sample::Routing { hops, detail, .. }) = samples.first() else {
        panic!("the routing probe produced nothing: {samples:?}");
    };
    assert!(*hops > 0, "a path to the internet has at least one hop");
    assert_eq!(detail.len(), *hops, "per-hop detail must match the count");
}

// --- The whole pipeline ---

#[tokio::test]
#[ignore = "requires network"]
async fn a_full_round_of_real_probes_leaves_the_dashboard_with_an_opinion() {
    let cfg = immediate_config();
    let mut state = AppState::new(cfg.clone());
    let mut samples = Vec::new();

    if let Ok(mut ping) =
        network_dash::metrics::ping::PingProbe::new(&cfg.targets.internet, Duration::from_secs(3))
    {
        state.retain_targets(&ping.target_names());
        samples.extend(ping.tick().await);
    }
    samples.extend(
        network_dash::metrics::dns::DnsProbe::new(&cfg.resolvers, Duration::from_secs(3))
            .tick()
            .await,
    );
    samples.extend(
        network_dash::metrics::tcp::TcpProbe::new(
            network_dash::metrics::tcp::TcpProbe::default_endpoints(),
            Duration::from_secs(5),
        )
        .tick()
        .await,
    );
    samples.extend(
        network_dash::metrics::reachability::ReachabilityProbe::new(
            // Filtered exactly as the app filters it: an IPv6 endpoint on a v4-only host is
            // not a fault, and this test exists to catch the pipeline disagreeing with itself.
            network_dash::metrics::reachability::checkable_endpoints(
                network_dash::metrics::reachability::ReachabilityProbe::default_endpoints(),
                network_dash::metrics::ping::has_ipv6_route(),
            ),
        )
        .tick()
        .await,
    );

    assert!(
        !samples.is_empty(),
        "four probes against a live network produced nothing at all"
    );

    let now = chrono::Utc::now();
    for s in samples {
        state.apply_sample(now, s);
    }

    // The verdict itself is not asserted — a genuinely broken network must be allowed to say
    // so. What is asserted is that the machinery ran: every target the probe kept has a row,
    // and the diagnosis is coherent with the health it was derived from.
    assert!(
        !state.targets.is_empty(),
        "at least one ping target should survive the family filter"
    );
    let verdicts = diagnose(&state);
    assert!(!verdicts.is_empty(), "diagnose is never empty");
    assert_eq!(
        verdicts.iter().map(|v| v.severity).max(),
        Some(state.overall_health()),
        "the diagnosis and the header badge must not disagree about how bad things are"
    );
}
