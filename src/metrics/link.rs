//! Wireless link probe (macOS): parse `system_profiler SPAirPortDataType`.
//!
//! `airport` was removed in macOS 14.4; `system_profiler SPAirPortDataType` is the
//! sudo-free replacement. Parsing is pure (unit-tested against captured output); the
//! subprocess call is a thin wrapper (it is slow, ~1s, so it runs on its own cadence in a
//! blocking task) and is covered by an ignored integration test.

use crate::metrics::{Probe, Sample};

/// Parsed wireless link details.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct WifiInfo {
    pub ssid: Option<String>,
    pub rssi_dbm: Option<f64>,
    pub noise_dbm: Option<f64>,
    pub tx_rate: Option<f64>,
    pub channel: Option<String>,
    pub phy_mode: Option<String>,
}

/// Parse the output of `system_profiler SPAirPortDataType`. Returns `None` when there is
/// no current network (not connected).
pub fn parse_airport(output: &str) -> Option<WifiInfo> {
    let lines: Vec<&str> = output.lines().collect();
    let start = lines
        .iter()
        .position(|l| l.trim() == "Current Network Information:")?;
    // The current-network block ends where the "Other Local Wi-Fi Networks" list begins.
    let end = lines[start + 1..]
        .iter()
        .position(|l| l.trim().starts_with("Other Local Wi-Fi Networks:"))
        .map(|i| start + 1 + i)
        .unwrap_or(lines.len());
    let section = &lines[start + 1..end];

    // The SSID is the first non-empty line of the block (a "<name>:" header).
    let ssid = section
        .iter()
        .find(|l| !l.trim().is_empty())
        .map(|l| l.trim().trim_end_matches(':').to_string());

    let mut info = WifiInfo {
        ssid,
        ..Default::default()
    };
    for line in section {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("Signal / Noise:") {
            let nums: Vec<f64> = rest
                .split('/')
                .filter_map(|part| part.split_whitespace().next()?.parse().ok())
                .collect();
            info.rssi_dbm = nums.first().copied();
            info.noise_dbm = nums.get(1).copied();
        } else if let Some(rest) = t.strip_prefix("Transmit Rate:") {
            info.tx_rate = rest.trim().parse().ok();
        } else if let Some(rest) = t.strip_prefix("Channel:") {
            info.channel = Some(rest.trim().to_string());
        } else if let Some(rest) = t.strip_prefix("PHY Mode:") {
            info.phy_mode = Some(rest.trim().to_string());
        }
    }
    Some(info)
}

/// Reads the wireless link via `system_profiler` on its own cadence.
pub struct WifiProbe;

impl Probe for WifiProbe {
    async fn tick(&mut self) -> Vec<Sample> {
        let info = tokio::task::spawn_blocking(|| {
            let out = std::process::Command::new("system_profiler")
                .arg("SPAirPortDataType")
                .output()
                .ok()?;
            parse_airport(&String::from_utf8_lossy(&out.stdout))
        })
        .await
        .ok()
        .flatten();
        match info {
            Some(w) => vec![Sample::Link {
                rssi_dbm: w.rssi_dbm,
                ssid: w.ssid,
            }],
            None => vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    const AIRPORT: &str = "Wi-Fi:

      Interfaces:
        en0:
          Card Type: Wi-Fi (0x14E4, 0x4387)
          Status: Connected
          Current Network Information:
            MyNetwork:
              PHY Mode: 802.11ax
              Channel: 149 (5GHz, 80MHz)
              Country Code: US
              Network Type: Infrastructure
              Security: WPA2 Personal
              Signal / Noise: -42 dBm / -92 dBm
              Transmit Rate: 866
              MCS Index: 9
          Other Local Wi-Fi Networks:
            SomeoneElse:
              PHY Mode: 802.11ac
";

    #[test]
    fn parses_signal_noise_and_details() {
        let info = parse_airport(AIRPORT).unwrap();
        assert_eq!(info.rssi_dbm, Some(-42.0));
        assert_eq!(info.noise_dbm, Some(-92.0));
        assert_eq!(info.tx_rate, Some(866.0));
        assert_eq!(info.phy_mode.as_deref(), Some("802.11ax"));
        assert_eq!(info.channel.as_deref(), Some("149 (5GHz, 80MHz)"));
    }

    #[test]
    fn parses_current_ssid() {
        let info = parse_airport(AIRPORT).unwrap();
        assert_eq!(info.ssid.as_deref(), Some("MyNetwork"));
    }

    #[test]
    fn returns_none_when_not_connected() {
        let output = "Wi-Fi:\n\n      Interfaces:\n        en0:\n          Status: Off\n";
        assert_eq!(parse_airport(output), None);
    }
}
