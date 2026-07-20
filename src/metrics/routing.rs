//! Routing/path probe: a lightweight `traceroute` with route-change detection.
//!
//! The output parsing is pure (unit-tested against captured output); the subprocess call
//! is thin and runs infrequently on its own cadence. Emits [`Sample::Routing`].

use crate::metrics::{Probe, Sample};

/// Parsed path to a target.
#[derive(Debug, Clone, PartialEq)]
pub struct Route {
    pub hops: usize,
    pub reachable: bool,
    /// Per-hop address (or `"*"` for a non-responding hop), first hop first.
    pub path: Vec<String>,
}

/// Parse `traceroute -n` output. `reachable` is true when the final hop is `target`.
pub fn parse_traceroute(output: &str, target: &str) -> Route {
    let mut path = Vec::new();
    for line in output.lines() {
        let mut it = line.split_whitespace();
        let Some(first) = it.next() else { continue };
        if first.parse::<u32>().is_err() {
            continue; // header or blank line
        }
        path.push(it.next().unwrap_or("*").to_string());
    }
    let reachable = path.last().map(|h| h == target).unwrap_or(false);
    Route {
        hops: path.len(),
        reachable,
        path,
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
                .args(["-n", "-w", "1", "-q", "1", "-m", &max, &target])
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

    #[test]
    fn parses_reached_path() {
        let r = parse_traceroute(REACHED, "1.1.1.1");
        assert_eq!(r.hops, 4);
        assert!(r.reachable);
        assert_eq!(r.path, vec!["192.168.1.1", "96.120.1.1", "*", "1.1.1.1"]);
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
