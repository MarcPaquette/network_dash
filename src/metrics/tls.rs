//! TLS handshake timing and certificate expiry.
//!
//! Two facts the TCP probe cannot see. The handshake is where the expensive part of opening
//! a connection lives — key exchange, certificate verification, and a second round trip — so
//! a link that connects fast and negotiates slowly is a real and specific complaint. Expiry
//! is the other kind of fault entirely: nothing is slow, nothing is broken, and on a known
//! date everything stops at once.
//!
//! The certificate is read from the completed handshake, which means it is verified the way
//! the platform verifies it: an expired or untrusted chain fails the handshake rather than
//! arriving as a cert to inspect. That is the honest measurement — it is what the user's
//! browser will do — and it is why "handshake failed" and "expires in N days" are separate
//! signals rather than one.
//!
//! Cheap by construction: one handshake per endpoint on a slow cadence, closed immediately.
//! No application bytes are ever sent.

use std::sync::Arc;
use std::time::Duration;

use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use rustls_platform_verifier::ConfigVerifierExt;
use tokio::net::TcpStream;
use tokio::time::Instant;
use tokio_rustls::TlsConnector;

use crate::metrics::{Probe, Sample};

/// The `notAfter` of a DER-encoded certificate, as a Unix timestamp.
///
/// `None` when the bytes are not a certificate at all — a truncated read or a server speaking
/// something other than TLS. Unparseable is not the same as expired, and reporting it as
/// "expires in a very long time ago" would be a lie in the alarming direction.
pub fn cert_expiry_secs(der: &[u8]) -> Option<i64> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    Some(cert.validity().not_after.timestamp())
}

/// Whole days from `now` until `expiry`, rounded towards zero.
///
/// Negative once the certificate has expired, which is deliberately representable: a
/// dashboard that clamps at zero cannot tell you *how long* something has been broken.
pub fn days_until(expiry_secs: i64, now_secs: i64) -> i64 {
    (expiry_secs - now_secs) / 86_400
}

/// Times a TLS handshake and reads the leaf certificate's expiry.
pub struct TlsProbe {
    /// `(label, host, port)`. The host must be the name, not an address — TLS verification
    /// and SNI are both name-based, and an IP literal would fail against most servers.
    endpoints: Vec<(String, String, u16)>,
    timeout: Duration,
    connector: TlsConnector,
}

impl TlsProbe {
    /// `None` when the platform's trust store cannot be loaded — without it there is no
    /// verdict to give, and a permissive fallback would report a handshake as healthy in
    /// exactly the case that matters.
    pub fn new(endpoints: Vec<(String, String, u16)>, timeout: Duration) -> Option<Self> {
        // The platform verifier, so the verdict matches what the user's own software will
        // decide about the same certificate.
        let config = ClientConfig::with_platform_verifier().ok()?;
        Some(Self {
            endpoints,
            timeout,
            connector: TlsConnector::from(Arc::new(config)),
        })
    }

    /// Well-known HTTPS hosts on separate networks, so one operator's bad day does not read
    /// as "TLS is broken".
    pub fn default_endpoints() -> Vec<(String, String, u16)> {
        vec![
            ("cloudflare".into(), "cloudflare.com".into(), 443),
            ("google".into(), "www.google.com".into(), 443),
        ]
    }

    /// One handshake: `(handshake_ms, cert_expiry_unix_secs)`, each `None` if unavailable.
    ///
    /// The timing covers the TLS negotiation only — the TCP connect is measured separately by
    /// [`crate::metrics::tcp`], and folding the two together would make a slow network look
    /// like slow crypto.
    async fn measure(&self, host: &str, port: u16) -> (Option<f64>, Option<i64>) {
        let Ok(name) = ServerName::try_from(host.to_string()) else {
            return (None, None);
        };
        let connect = TcpStream::connect((host, port));
        let Ok(Ok(tcp)) = tokio::time::timeout(self.timeout, connect).await else {
            return (None, None);
        };
        let start = Instant::now();
        let handshake = self.connector.connect(name, tcp);
        let Ok(Ok(stream)) = tokio::time::timeout(self.timeout, handshake).await else {
            return (None, None);
        };
        let elapsed = start.elapsed().as_secs_f64() * 1000.0;
        // The leaf is first; the rest of the chain outlives it in practice, and it is the one
        // whose expiry takes the site down.
        let expiry = stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|c| c.first())
            .and_then(|c| cert_expiry_secs(c));
        (Some(elapsed), expiry)
    }
}

impl Probe for TlsProbe {
    async fn tick(&mut self) -> Vec<Sample> {
        let now = chrono::Utc::now().timestamp();
        let mut out = Vec::new();
        for (label, host, port) in &self.endpoints {
            let (handshake_ms, expiry) = self.measure(host, *port).await;
            out.push(Sample::Tls {
                endpoint: label.clone(),
                handshake_ms,
                expires_in_days: expiry.map(|e| days_until(e, now)),
            });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    /// A self-signed certificate with a fixed, known `notAfter` of
    /// 2036-07-26T13:17:57Z (Unix 2100691077). Its own validity is never asserted — only
    /// that the date is read back correctly — so the fixture does not rot.
    const FIXTURE_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIB+TCCAWKgAwIBAgIBATANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDDA1uZXRw
dWxzZS50ZXN0MB4XDTI2MDcyOTEzMTc1N1oXDTM2MDcyNjEzMTc1N1owGDEWMBQG
A1UEAwwNbmV0cHVsc2UudGVzdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA
uIyH5ffsTaszC5Wnx1z8mJ4zN9oAyLfGQp7nNPdw0CZ2de2DQ3KVtn+ctMpdaf75
Ck2dVg+4JGlmw5L0MwjfGfhlJOK8kF+QecAPekDMrcsPyB3jYrOKX1saR7FYZ3I1
HoWKACa02BnRbj41THfJxUJsR/KEeO9lrUEMy1XjFrcCAwEAAaNTMFEwHQYDVR0O
BBYEFORltUqHD22V0cLyQa+3UmKSA4OfMB8GA1UdIwQYMBaAFORltUqHD22V0cLy
Qa+3UmKSA4OfMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADgYEAc/Y6
a2IglcpWKn8Y22huZj2WisqLXbGMQOcbycNP0mJl4SyP/+af1313bHTmOY5VOzG+
Xu02IttdCdTPv+7H/MINDw/zlNSIzUAz29QFjI835pXqvDpr0fPEsYQQ5+uVgk7b
uZEytRmhV2zuWhwtY5SHpTbCD1xaB6yvAI7cOsc=
-----END CERTIFICATE-----
";

    /// The fixture's `notAfter`: 2036-07-26T13:17:57Z.
    const FIXTURE_NOT_AFTER: i64 = 2_100_691_077;

    fn fixture_der() -> Vec<u8> {
        let (_, pem) = x509_parser::pem::parse_x509_pem(FIXTURE_PEM.as_bytes()).unwrap();
        pem.contents
    }

    #[test]
    fn a_certificates_expiry_is_read_from_its_bytes() {
        assert_eq!(cert_expiry_secs(&fixture_der()), Some(FIXTURE_NOT_AFTER));
    }

    #[test]
    fn bytes_that_are_not_a_certificate_report_nothing_rather_than_guessing() {
        assert_eq!(cert_expiry_secs(b"HTTP/1.1 400 Bad Request"), None);
        assert_eq!(cert_expiry_secs(&[]), None);
    }

    #[test]
    fn expiry_is_counted_in_whole_days() {
        let now = FIXTURE_NOT_AFTER - 10 * 86_400;
        assert_eq!(days_until(FIXTURE_NOT_AFTER, now), 10);
        // Rounded towards zero: 9 days and 23 hours left is not yet 10 days.
        assert_eq!(days_until(FIXTURE_NOT_AFTER, now + 3600), 9);
    }

    #[test]
    fn an_expired_certificate_counts_backwards() {
        let now = FIXTURE_NOT_AFTER + 3 * 86_400;
        assert_eq!(
            days_until(FIXTURE_NOT_AFTER, now),
            -3,
            "clamping at zero would hide how long it has been broken"
        );
    }

    #[tokio::test]
    async fn a_port_that_does_not_speak_tls_reports_neither_timing_nor_expiry() {
        // Port 1 on loopback: refused, so there is no handshake to time and no cert to read.
        let probe = TlsProbe::new(vec![], Duration::from_millis(200)).unwrap();
        assert_eq!(probe.measure("127.0.0.1", 1).await, (None, None));
    }

    #[tokio::test]
    async fn one_sample_per_endpoint_even_when_they_all_fail() {
        let mut probe = TlsProbe::new(
            vec![
                ("a".into(), "127.0.0.1".into(), 1),
                ("b".into(), "127.0.0.1".into(), 1),
            ],
            Duration::from_millis(200),
        )
        .unwrap();
        let samples = probe.tick().await;
        assert_eq!(samples.len(), 2, "{samples:?}");
        assert!(
            samples.iter().all(|s| matches!(
                s,
                Sample::Tls {
                    handshake_ms: None,
                    expires_in_days: None,
                    ..
                }
            )),
            "{samples:?}"
        );
    }

    #[tokio::test]
    #[ignore = "requires network"]
    async fn a_real_endpoint_yields_a_timing_and_a_future_expiry() {
        let mut probe = TlsProbe::new(TlsProbe::default_endpoints(), Duration::from_secs(5))
            .expect("a platform verifier should be available");
        let samples = probe.tick().await;
        assert_eq!(samples.len(), 2);
        let good = samples.iter().filter(|s| {
            matches!(
                s,
                Sample::Tls { handshake_ms: Some(ms), expires_in_days: Some(d), .. }
                    if *ms > 0.0 && *d > 0
            )
        });
        assert!(
            good.count() > 0,
            "at least one well-known host should present a valid certificate: {samples:?}"
        );
    }
}
