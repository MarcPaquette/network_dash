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
    /// IPv6-only host (its success indicates working IPv6). The `captive` endpoint gets
    /// special handling (body inspection) — see [`detect_captive`].
    pub fn default_endpoints() -> Vec<(String, String)> {
        vec![
            (
                "captive".into(),
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

/// Whether the captive-portal probe reached the genuine internet or was intercepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptiveOutcome {
    /// The genuine origin answered — no portal.
    Online,
    /// The request was intercepted (a redirect, or a 2xx serving a login page).
    Portal,
}

/// Classify the captive-portal detector's response. Apple's `hotspot-detect.html` returns a
/// 2xx whose body contains `Success` on a genuine connection; a captive portal instead
/// intercepts the request — a redirect, or a 2xx serving a login page — so anything that
/// isn't a 2xx-with-`Success` is treated as a portal. This is the fix for the old logic,
/// which treated the redirect a portal returns as "reachable".
pub fn detect_captive(status: u16, body: &str) -> CaptiveOutcome {
    if (200..300).contains(&status) && body.contains("Success") {
        CaptiveOutcome::Online
    } else {
        CaptiveOutcome::Portal
    }
}

impl Probe for ReachabilityProbe {
    fn tick(&mut self) -> impl std::future::Future<Output = Vec<Sample>> + Send {
        let client = &self.client;
        let endpoints = &self.endpoints;
        async move {
            let futs = endpoints.iter().map(|(label, url)| {
                let client = client.clone();
                let label = label.clone();
                let url = url.clone();
                async move {
                    if label == "captive" {
                        // Inspect the body: a portal serves a login page or redirects, so a
                        // plain 2xx is not enough — emit the reachability status *and* a
                        // distinct captive-portal signal.
                        match client.get(&url).send().await {
                            Ok(resp) => {
                                let status = resp.status().as_u16();
                                let body = resp.text().await.unwrap_or_default();
                                let portal =
                                    detect_captive(status, &body) == CaptiveOutcome::Portal;
                                vec![
                                    Sample::Reachability {
                                        endpoint: label,
                                        ok: !portal,
                                    },
                                    Sample::CaptivePortal { detected: portal },
                                ]
                            }
                            // A network error means offline — we can't tell it's a portal.
                            Err(_) => vec![
                                Sample::Reachability {
                                    endpoint: label,
                                    ok: false,
                                },
                                Sample::CaptivePortal { detected: false },
                            ],
                        }
                    } else {
                        let ok = match client.get(&url).send().await {
                            Ok(resp) => {
                                resp.status().is_success() || resp.status().is_redirection()
                            }
                            Err(_) => false,
                        };
                        vec![Sample::Reachability {
                            endpoint: label,
                            ok,
                        }]
                    }
                }
            });
            futures::future::join_all(futs)
                .await
                .into_iter()
                .flatten()
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn genuine_apple_success_body_is_online() {
        let body = "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>";
        assert_eq!(detect_captive(200, body), CaptiveOutcome::Online);
    }

    #[test]
    fn login_page_served_as_200_is_a_portal() {
        let body = "<html><body><h1>Hotel Wi-Fi — please sign in</h1></body></html>";
        assert_eq!(detect_captive(200, body), CaptiveOutcome::Portal);
    }

    #[test]
    fn a_redirect_is_a_portal_not_reachable() {
        // The old logic treated this as "reachable"; a portal is exactly what redirects.
        assert_eq!(detect_captive(302, ""), CaptiveOutcome::Portal);
    }

    #[tokio::test]
    #[ignore = "requires network"]
    async fn checks_default_endpoints() {
        let mut probe = ReachabilityProbe::new(ReachabilityProbe::default_endpoints());
        let samples = probe.tick().await;
        // captive → 2 samples (reachability + captive-portal), https + ipv6 → 1 each.
        assert_eq!(samples.len(), 4);
    }
}
