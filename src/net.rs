//! Small networking helpers: default-gateway detection.
//!
//! The parsing is pure (unit-tested against captured command output); the subprocess call
//! is a thin wrapper covered by an ignored integration test.

/// Parse the gateway IP from `route -n get default` (macOS) output.
pub fn parse_default_gateway(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim() == "gateway" {
            let gw = value.trim();
            (!gw.is_empty()).then(|| gw.to_string())
        } else {
            None
        }
    })
}

/// Detect the default gateway by shelling out to `route -n get default`.
pub fn detect_default_gateway() -> Option<String> {
    let out = std::process::Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    parse_default_gateway(&String::from_utf8_lossy(&out.stdout))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    const ROUTE_OUTPUT: &str = "   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0
";

    #[test]
    fn parses_gateway_from_route_output() {
        assert_eq!(
            parse_default_gateway(ROUTE_OUTPUT),
            Some("192.168.1.1".to_string())
        );
    }

    #[test]
    fn missing_gateway_is_none() {
        let output = "   route to: default\ndestination: default\n  interface: en0\n";
        assert_eq!(parse_default_gateway(output), None);
    }

    #[test]
    fn empty_output_is_none() {
        assert_eq!(parse_default_gateway(""), None);
    }
}
