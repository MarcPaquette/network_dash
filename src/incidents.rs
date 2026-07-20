//! Incident records and the append-only JSONL log.
//!
//! An [`Incident`] is emitted on a confirmed health transition (see the reducer). Each is
//! written as one JSON object per line so the log is both human-greppable and
//! machine-parseable. [`IncidentLog`] writes to any [`Write`] sink, so tests can target an
//! in-memory buffer instead of the real data directory.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::health::Health;
use crate::metrics::MetricId;

/// A single logged network-health event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Incident {
    /// When it occurred (serialized as RFC3339 / ISO-8601 UTC).
    pub ts: DateTime<Utc>,
    pub metric: MetricId,
    /// Severity the metric transitioned *to* (`ok` marks a recovery).
    pub severity: Health,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub value: Option<f64>,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub unit: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub threshold: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub target: Option<String>,
    pub message: String,
}

impl Incident {
    pub fn new(
        ts: DateTime<Utc>,
        metric: MetricId,
        severity: Health,
        message: impl Into<String>,
    ) -> Self {
        Self {
            ts,
            metric,
            severity,
            value: None,
            unit: String::new(),
            threshold: None,
            target: None,
            message: message.into(),
        }
    }

    pub fn with_value(mut self, value: f64, unit: impl Into<String>) -> Self {
        self.value = Some(value);
        self.unit = unit.into();
        self
    }

    pub fn with_threshold(mut self, threshold: f64) -> Self {
        self.threshold = Some(threshold);
        self
    }

    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    /// Serialize to a single JSONL line terminated with `\n`.
    pub fn to_jsonl_line(&self) -> Result<String, serde_json::Error> {
        let mut s = serde_json::to_string(self)?;
        s.push('\n');
        Ok(s)
    }

    /// Parse one JSONL line (trailing newline optional).
    pub fn from_jsonl_line(line: &str) -> Result<Incident, serde_json::Error> {
        serde_json::from_str(line.trim_end())
    }
}

/// Append-only writer for incidents over any [`Write`] sink.
pub struct IncidentLog<W: Write> {
    sink: W,
}

impl<W: Write> IncidentLog<W> {
    pub fn new(sink: W) -> Self {
        Self { sink }
    }

    /// Append one incident as a JSONL line and flush.
    pub fn append(&mut self, incident: &Incident) -> io::Result<()> {
        let line = incident.to_jsonl_line().map_err(io::Error::other)?;
        self.sink.write_all(line.as_bytes())?;
        self.sink.flush()
    }

    /// Recover the underlying sink (useful in tests).
    pub fn into_inner(self) -> W {
        self.sink
    }
}

impl IncidentLog<std::fs::File> {
    /// Open (creating parent dirs) the on-disk log in append mode.
    pub fn open_append(path: &Path) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self::new(file))
    }

    /// Default on-disk log path (`<data_local_dir>/network_dash/incidents.jsonl`).
    pub fn default_path() -> Option<PathBuf> {
        directories::ProjectDirs::from("", "", "network_dash")
            .map(|d| d.data_local_dir().join("incidents.jsonl"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use pretty_assertions::assert_eq;

    fn sample() -> Incident {
        let ts = Utc.with_ymd_and_hms(2026, 7, 20, 14, 20, 3).unwrap();
        Incident::new(ts, MetricId::Dns, Health::Warn, "DNS spike 180ms (google)")
            .with_value(180.0, "ms")
            .with_threshold(100.0)
            .with_target("8.8.8.8")
    }

    #[test]
    fn builders_populate_fields() {
        let inc = sample();
        assert_eq!(inc.metric, MetricId::Dns);
        assert_eq!(inc.severity, Health::Warn);
        assert_eq!(inc.value, Some(180.0));
        assert_eq!(inc.unit, "ms");
        assert_eq!(inc.threshold, Some(100.0));
        assert_eq!(inc.target.as_deref(), Some("8.8.8.8"));
    }

    #[test]
    fn jsonl_line_is_single_line_and_terminated() {
        let line = sample().to_jsonl_line().unwrap();
        assert!(line.ends_with('\n'), "line must end with newline");
        assert_eq!(
            line.trim_end().lines().count(),
            1,
            "must be exactly one line"
        );
    }

    #[test]
    fn jsonl_round_trips() {
        let inc = sample();
        let line = inc.to_jsonl_line().unwrap();
        let parsed = Incident::from_jsonl_line(&line).unwrap();
        assert_eq!(parsed, inc);
    }

    #[test]
    fn severity_and_metric_serialize_lowercase() {
        let line = sample().to_jsonl_line().unwrap();
        assert!(line.contains("\"severity\":\"warn\""), "got: {line}");
        assert!(line.contains("\"metric\":\"dns\""), "got: {line}");
    }

    #[test]
    fn timestamp_serializes_as_rfc3339() {
        let line = sample().to_jsonl_line().unwrap();
        assert!(line.contains("2026-07-20T14:20:03"), "got: {line}");
    }

    #[test]
    fn log_appends_parseable_lines_to_sink() {
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut log = IncidentLog::new(&mut buf);
            let a = sample();
            let b = Incident::new(
                Utc.with_ymd_and_hms(2026, 7, 20, 14, 25, 0).unwrap(),
                MetricId::Loss,
                Health::Crit,
                "loss 6% (gw)",
            );
            log.append(&a).unwrap();
            log.append(&b).unwrap();
        }
        let text = String::from_utf8(buf).unwrap();
        let parsed: Vec<Incident> = text
            .lines()
            .map(|l| Incident::from_jsonl_line(l).unwrap())
            .collect();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].metric, MetricId::Dns);
        assert_eq!(parsed[1].metric, MetricId::Loss);
        assert_eq!(parsed[1].severity, Health::Crit);
    }
}
