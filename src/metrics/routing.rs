//! Routing/path probe: a lightweight `traceroute` with route-change detection.
//!
//! The output parsing is pure (unit-tested against captured output); the subprocess call
//! is thin and runs infrequently on its own cadence. Emits [`Sample::Routing`].

use crate::metrics::{Hop, Probe, Sample};

/// Parsed path to a target.
#[derive(Debug, Clone, PartialEq)]
pub struct Route {
    pub hops: usize,
    pub reachable: bool,
    /// Per-hop address (or `"*"` for a non-responding hop), first hop first.
    pub path: Vec<String>,
    /// Per-hop detail (address, best RTT, probe loss), first hop first.
    pub detail: Vec<Hop>,
}

/// Parse one hop line's tokens (everything after the hop number). With `-q N` a hop may
/// carry several RTT samples and/or `*` (lost probes); `-n` keeps addresses numeric.
fn parse_hop(tokens: &[&str]) -> Hop {
    let mut addr: Option<String> = None;
    let mut rtts: Vec<f64> = Vec::new();
    let mut lost = 0usize;
    let mut i = 0;
    while i < tokens.len() {
        let tok = tokens[i];
        if tok == "*" {
            lost += 1;
            i += 1;
        } else if tok == "ms" {
            i += 1;
        } else if let Ok(v) = tok.parse::<f64>() {
            // A latency reading if the next token is the "ms" unit.
            if tokens.get(i + 1) == Some(&"ms") {
                rtts.push(v);
                i += 2;
            } else {
                i += 1;
            }
        } else {
            // A hop address (IP with `-n`); keep the first responder.
            if addr.is_none() {
                addr = Some(tok.to_string());
            }
            i += 1;
        }
    }
    let total = rtts.len() + lost;
    let loss_pct = if total == 0 {
        0.0
    } else {
        lost as f64 / total as f64 * 100.0
    };
    let min_rtt_ms = rtts
        .into_iter()
        .fold(None, |acc, v| Some(acc.map_or(v, |a: f64| a.min(v))));
    Hop {
        addr: addr.unwrap_or_else(|| "*".to_string()),
        min_rtt_ms,
        loss_pct,
    }
}

/// Parse `traceroute -n` output. `reachable` is true when the final hop is `target`.
pub fn parse_traceroute(output: &str, target: &str) -> Route {
    let mut detail = Vec::new();
    for line in output.lines() {
        let mut it = line.split_whitespace();
        let Some(first) = it.next() else { continue };
        if first.parse::<u32>().is_err() {
            continue; // header or blank line
        }
        let tokens: Vec<&str> = it.collect();
        detail.push(parse_hop(&tokens));
    }
    let path: Vec<String> = detail.iter().map(|h| h.addr.clone()).collect();
    let reachable = path.last().map(|h| h == target).unwrap_or(false);
    Route {
        hops: detail.len(),
        reachable,
        path,
        detail,
    }
}

/// Runs `traceroute` to a stable target and flags path changes between runs.
pub struct RoutingProbe {
    target: String,
    max_hops: usize,
    prev_path: Option<Vec<String>>,
}

impl RoutingProbe {
    pub fn new(target: impl Into<String>, max_hops: usize) -> Self {
        Self {
            target: target.into(),
            max_hops,
            prev_path: None,
        }
    }
}

impl Probe for RoutingProbe {
    async fn tick(&mut self) -> Vec<Sample> {
        let target = self.target.clone();
        let max = self.max_hops.to_string();
        let out = tokio::task::spawn_blocking(move || {
            std::process::Command::new("traceroute")
                // -q 3: three probes per hop, so we get per-hop RTT and loss.
                .args(["-n", "-w", "1", "-q", "3", "-m", &max, &target])
                .output()
                .ok()
        })
        .await
        .ok()
        .flatten();
        let Some(out) = out else {
            return vec![];
        };
        let route = parse_traceroute(&String::from_utf8_lossy(&out.stdout), &self.target);
        let changed = self.prev_path.as_ref().is_some_and(|p| p != &route.path);
        self.prev_path = Some(route.path.clone());
        vec![Sample::Routing {
            target: self.target.clone(),
            hops: route.hops,
            reachable: route.reachable,
            changed,
            detail: route.detail,
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    const REACHED: &str = "traceroute to 1.1.1.1 (1.1.1.1), 15 hops max, 52 byte packets
 1  192.168.1.1  1.234 ms
 2  96.120.1.1  9.567 ms
 3  * * *
 4  1.1.1.1  12.3 ms
";

    const UNREACHED: &str = "traceroute to 1.1.1.1 (1.1.1.1), 15 hops max, 52 byte packets
 1  192.168.1.1  1.2 ms
 2  * * *
 3  * * *
";

    /// `-q 3` output: three probes per hop, with a fully-lost hop and a partial-loss hop.
    const MULTI: &str = "traceroute to 1.1.1.1 (1.1.1.1), 15 hops max, 52 byte packets
 1  192.168.1.1  1.2 ms  1.1 ms  1.0 ms
 2  96.120.1.1  9.5 ms  * 10.2 ms
 3  * * *
 4  1.1.1.1  12.3 ms  11.9 ms  12.1 ms
";

    #[test]
    fn parses_reached_path() {
        let r = parse_traceroute(REACHED, "1.1.1.1");
        assert_eq!(r.hops, 4);
        assert!(r.reachable);
        assert_eq!(r.path, vec!["192.168.1.1", "96.120.1.1", "*", "1.1.1.1"]);
    }

    #[test]
    fn parses_per_hop_rtt_and_loss() {
        let r = parse_traceroute(MULTI, "1.1.1.1");
        assert!(r.reachable);
        // Hop 1: three good probes, best 1.0 ms, no loss.
        assert_eq!(r.detail[0].addr, "192.168.1.1");
        assert_eq!(r.detail[0].min_rtt_ms, Some(1.0));
        assert_eq!(r.detail[0].loss_pct, 0.0);
        // Hop 2: one probe lost of three → 33% loss, best 9.5 ms.
        assert_eq!(r.detail[1].min_rtt_ms, Some(9.5));
        assert!((r.detail[1].loss_pct - 33.333).abs() < 0.01);
        // Hop 3: all three lost → 100% loss, no RTT, address "*".
        assert_eq!(r.detail[2].addr, "*");
        assert_eq!(r.detail[2].min_rtt_ms, None);
        assert_eq!(r.detail[2].loss_pct, 100.0);
        // Hop 4 reaches the target.
        assert_eq!(r.detail[3].min_rtt_ms, Some(11.9));
    }

    #[test]
    fn parses_unreached_path() {
        let r = parse_traceroute(UNREACHED, "1.1.1.1");
        assert_eq!(r.hops, 3);
        assert!(!r.reachable);
        assert_eq!(r.path.last().unwrap(), "*");
    }

    #[test]
    fn empty_output_is_unreachable() {
        let r = parse_traceroute("", "1.1.1.1");
        assert_eq!(r.hops, 0);
        assert!(!r.reachable);
    }
}
