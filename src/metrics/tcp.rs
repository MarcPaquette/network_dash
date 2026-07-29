//! TCP handshake timing — how long it takes to *open* a connection, not to use one.
//!
//! Ping measures the network. This measures the network plus everything a real connection
//! actually waits on: the SYN queue on the far end, middleboxes doing stateful inspection,
//! and the difference between a host that is up and a host that is up and *accepting*.
//! A handshake several times slower than the ICMP RTT to the same host is the classic
//! signature of a loaded or filtered path, and ping alone cannot see it.
//!
//! Cheap by construction: one connection, opened and immediately dropped, on a slow cadence.
//! No bytes are sent past the handshake.

use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::Instant;

use crate::metrics::{Probe, Sample};

/// Time a single TCP connect to `addr`, in milliseconds.
///
/// `None` on refusal, timeout or DNS failure — all three mean "this port did not open",
/// which is one fact from the dashboard's point of view. The distinction between them is
/// interesting when you are debugging the endpoint, not when you are debugging the network.
pub async fn connect_ms(addr: &str, timeout: Duration) -> Option<f64> {
    let start = Instant::now();
    let stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    // Dropped immediately: the handshake is the whole measurement, and a lingering socket
    // would keep state on a remote host we have no business holding.
    drop(stream);
    Some(elapsed)
}

/// Times TCP handshakes to a set of `host:port` endpoints.
pub struct TcpProbe {
    /// `(label, host:port)` pairs. The label is what the panel and the incident log show.
    endpoints: Vec<(String, String)>,
    timeout: Duration,
}

impl TcpProbe {
    pub fn new(endpoints: Vec<(String, String)>, timeout: Duration) -> Self {
        Self { endpoints, timeout }
    }

    /// Well-known hosts on :443, chosen to sit on different networks so one operator having
    /// a bad day doesn't read as "TCP is broken".
    pub fn default_endpoints() -> Vec<(String, String)> {
        vec![
            ("cloudflare".into(), "1.1.1.1:443".into()),
            ("google".into(), "8.8.8.8:443".into()),
        ]
    }
}

impl Probe for TcpProbe {
    async fn tick(&mut self) -> Vec<Sample> {
        let mut out = Vec::new();
        for (label, addr) in &self.endpoints {
            out.push(Sample::TcpHandshake {
                endpoint: label.clone(),
                connect_ms: connect_ms(addr, self.timeout).await,
            });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[tokio::test]
    async fn a_port_with_nothing_behind_it_reports_no_timing() {
        // Port 1 on loopback: refused immediately, no network involved.
        assert_eq!(
            connect_ms("127.0.0.1:1", Duration::from_secs(1)).await,
            None
        );
    }

    #[tokio::test]
    async fn a_listening_port_is_timed() {
        // A real handshake against a socket we own — exercises the timing path without
        // touching the network.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let ms = connect_ms(&addr, Duration::from_secs(1))
            .await
            .expect("loopback should connect");
        assert!(
            (0.0..1000.0).contains(&ms),
            "implausible loopback time: {ms}"
        );
    }

    #[tokio::test]
    async fn an_unroutable_address_times_out_rather_than_hanging() {
        // 198.51.100.0/24 is TEST-NET-2: reserved, never routed, so the SYN goes nowhere.
        let t = Instant::now();
        let ms = connect_ms("198.51.100.1:443", Duration::from_millis(150)).await;
        assert_eq!(ms, None);
        assert!(
            t.elapsed() < Duration::from_secs(2),
            "the timeout must bound the wait, not the OS default"
        );
    }

    #[tokio::test]
    async fn one_sample_per_endpoint_even_when_they_all_fail() {
        let mut probe = TcpProbe::new(
            vec![
                ("a".into(), "127.0.0.1:1".into()),
                ("b".into(), "127.0.0.1:1".into()),
            ],
            Duration::from_millis(200),
        );
        let samples = probe.tick().await;
        assert_eq!(samples.len(), 2, "{samples:?}");
        assert!(
            samples.iter().all(|s| matches!(
                s,
                Sample::TcpHandshake {
                    connect_ms: None,
                    ..
                }
            )),
            "{samples:?}"
        );
    }

    #[tokio::test]
    #[ignore = "requires network"]
    async fn default_endpoints_complete_a_real_handshake() {
        let mut probe = TcpProbe::new(TcpProbe::default_endpoints(), Duration::from_secs(5));
        let samples = probe.tick().await;
        assert_eq!(samples.len(), 2);
        let timed = samples.iter().filter(
            |s| matches!(s, Sample::TcpHandshake { connect_ms: Some(ms), .. } if *ms > 0.0),
        );
        assert!(
            timed.count() > 0,
            "at least one well-known host should answer on :443: {samples:?}"
        );
    }
}
