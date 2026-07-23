//! Small networking helpers: default-route introspection (gateway, interface, MTU, VPN).
//!
//! The parsing is pure (unit-tested against captured command output); the subprocess call
//! is a thin wrapper covered by an ignored integration test.

/// The default route's key facts, parsed from `route -n get default` (macOS).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RouteInfo {
    pub gateway: Option<String>,
    /// The interface carrying the default route (e.g. `en0`, `utun3`).
    pub interface: Option<String>,
    /// Path MTU for the route, when reported.
    pub mtu: Option<u32>,
}

impl RouteInfo {
    /// Whether the default route runs over a VPN/tunnel interface.
    pub fn is_vpn(&self) -> bool {
        self.interface.as_deref().is_some_and(is_vpn_interface)
    }
}

/// Heuristic: does this interface name denote a VPN / tunnel? macOS VPNs carry the default
/// route over `utun*` / `ipsec*` / `ppp*` when a full tunnel is active.
pub fn is_vpn_interface(iface: &str) -> bool {
    ["utun", "ipsec", "ppp", "tun", "tap"]
        .iter()
        .any(|p| iface.starts_with(p))
}

/// Parse the gateway, interface, and MTU from `route -n get default` output.
pub fn parse_route_default(output: &str) -> RouteInfo {
    let lines: Vec<&str> = output.lines().collect();
    let mut info = RouteInfo::default();
    for line in &lines {
        if let Some((key, value)) = line.split_once(':') {
            match key.trim() {
                "gateway" => {
                    let g = value.trim();
                    if !g.is_empty() {
                        info.gateway = Some(g.to_string());
                    }
                }
                "interface" => {
                    let i = value.trim();
                    if !i.is_empty() {
                        info.interface = Some(i.to_string());
                    }
                }
                _ => {}
            }
        }
    }
    // MTU lives in a positional table: a header row containing "mtu" and a values row under
    // it. Locate the "mtu" column by name so we're robust to the column spacing.
    if let Some(hpos) = lines
        .iter()
        .position(|l| l.split_whitespace().any(|c| c == "mtu"))
    {
        let col = lines[hpos]
            .split_whitespace()
            .position(|c| c == "mtu")
            .unwrap();
        if let Some(mtu) = lines
            .get(hpos + 1)
            .and_then(|vals| vals.split_whitespace().nth(col))
            .and_then(|s| s.parse::<u32>().ok())
        {
            info.mtu = Some(mtu);
        }
    }
    info
}

/// Parse just the gateway IP from `route -n get default` output.
pub fn parse_default_gateway(output: &str) -> Option<String> {
    parse_route_default(output).gateway
}

/// Detect the full default-route info by shelling out to `route -n get default`.
pub fn detect_route_info() -> Option<RouteInfo> {
    let out = std::process::Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(parse_route_default(&String::from_utf8_lossy(&out.stdout)))
}

/// Detect the default gateway by shelling out to `route -n get default`.
pub fn detect_default_gateway() -> Option<String> {
    detect_route_info().and_then(|i| i.gateway)
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

    const VPN_ROUTE: &str = "   route to: default
destination: default
    gateway: 10.8.0.1
  interface: utun3
      flags: <UP,GATEWAY,DONE,STATIC>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1400         0
";

    #[test]
    fn parses_gateway_from_route_output() {
        assert_eq!(
            parse_default_gateway(ROUTE_OUTPUT),
            Some("192.168.1.1".to_string())
        );
    }

    #[test]
    fn parses_interface_and_mtu() {
        let info = parse_route_default(ROUTE_OUTPUT);
        assert_eq!(info.interface.as_deref(), Some("en0"));
        assert_eq!(info.mtu, Some(1500));
        assert!(!info.is_vpn(), "en0 is not a VPN interface");
    }

    #[test]
    fn detects_vpn_default_route() {
        let info = parse_route_default(VPN_ROUTE);
        assert_eq!(info.interface.as_deref(), Some("utun3"));
        assert_eq!(info.mtu, Some(1400));
        assert!(info.is_vpn(), "utun3 should read as a VPN tunnel");
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
