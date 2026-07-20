//! Reachability probe: HTTP(S) checks against well-known endpoints (incl. a captive-portal
//! detector). Emits one [`Sample::Reachability`] per endpoint. Network-bound, so the live
//! behavior is covered by an ignored integration test.

use std::time::Duration;

use crate::metrics::{Probe, Sample};

/// Probes a set of `(label, url)` endpoints for reachability.
pub struct ReachabilityProbe {
    client: reqwest::Client,
    endpoints: Vec<(String, String)>,
}

impl ReachabilityProbe {
    pub fn new(endpoints: Vec<(String, String)>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .user_agent("network_dash/0.1")
            .build()
            .unwrap_or_default();
        Self { client, endpoints }
    }

    /// Default endpoints: a captive-portal detector, an HTTPS trace endpoint, and an
    /// IPv6-only host (its success indicates working IPv6).
    pub fn default_endpoints() -> Vec<(String, String)> {
        vec![
            (
                "http".into(),
                "http://captive.apple.com/hotspot-detect.html".into(),
            ),
            (
                "https".into(),
                "https://www.cloudflare.com/cdn-cgi/trace".into(),
            ),
            ("ipv6".into(), "https://ipv6.google.com/".into()),
        ]
    }
}

impl Probe for ReachabilityProbe {
    fn tick(&mut self) -> impl std::future::Future<Output = Vec<Sample>> + Send {
        let client = &self.client;
        let endpoints = &self.endpoints;
        async move {
            let futs = endpoints.iter().map(|(label, url)| {
                let client = client.clone();
                async move {
                    let ok = match client.get(url).send().await {
                        Ok(resp) => resp.status().is_success() || resp.status().is_redirection(),
                        Err(_) => false,
                    };
                    Sample::Reachability {
                        endpoint: label.clone(),
                        ok,
                    }
                }
            });
            futures::future::join_all(futs).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires network"]
    async fn checks_default_endpoints() {
        let mut probe = ReachabilityProbe::new(ReachabilityProbe::default_endpoints());
        let samples = probe.tick().await;
        assert_eq!(samples.len(), 3);
    }
}
