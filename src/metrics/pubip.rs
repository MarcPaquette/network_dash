//! Public-IP probe: read the WAN IP from an echo endpoint so the reducer can flag ISP/WAN
//! address changes (a WAN flap, a CGNAT shuffle, a failover). Parsing is pure; the fetch is
//! a thin wrapper covered by an ignored integration test.

use std::time::Duration;

use crate::metrics::{Probe, Sample};

/// Fetches the public IP from a trace endpoint.
pub struct PublicIpProbe {
    client: reqwest::Client,
    url: String,
}

impl PublicIpProbe {
    pub fn new(url: impl Into<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("network_dash/0.1")
            .build()
            .unwrap_or_default();
        Self {
            client,
            url: url.into(),
        }
    }

    /// The default endpoint: Cloudflare's trace, whose body carries an `ip=<addr>` line.
    pub fn cloudflare() -> Self {
        Self::new("https://www.cloudflare.com/cdn-cgi/trace")
    }
}

/// Extract the `ip=` value from a Cloudflare `cdn-cgi/trace` body.
pub fn parse_trace_ip(body: &str) -> Option<String> {
    body.lines()
        .find_map(|l| l.strip_prefix("ip=").map(|s| s.trim().to_string()))
        .filter(|s| !s.is_empty())
}

impl Probe for PublicIpProbe {
    async fn tick(&mut self) -> Vec<Sample> {
        // On any failure emit nothing (rather than a spurious "changed") — the reducer keeps
        // the last known IP.
        match self.client.get(&self.url).send().await {
            Ok(resp) => match resp.text().await.ok().and_then(|b| parse_trace_ip(&b)) {
                Some(ip) => vec![Sample::PublicIp { ip }],
                None => vec![],
            },
            Err(_) => vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    const TRACE: &str = "fl=123abc\nh=www.cloudflare.com\nip=203.0.113.7\nts=1690000000.1\n";

    #[test]
    fn parses_ip_from_trace_body() {
        assert_eq!(parse_trace_ip(TRACE), Some("203.0.113.7".to_string()));
    }

    #[test]
    fn missing_ip_line_is_none() {
        assert_eq!(parse_trace_ip("fl=123\nh=x\n"), None);
    }

    #[tokio::test]
    #[ignore = "requires network"]
    async fn fetches_a_public_ip() {
        let mut probe = PublicIpProbe::cloudflare();
        let samples = probe.tick().await;
        assert_eq!(samples.len(), 1);
        assert!(matches!(&samples[0], Sample::PublicIp { ip } if !ip.is_empty()));
    }
}
