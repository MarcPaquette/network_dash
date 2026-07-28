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

use crate::diagnosis::Layer;
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
    /// The upstream layer that already accounts for this incident, when one does — a DNS
    /// timeout during a gateway outage is an echo, not a second fault.
    ///
    /// Recorded, never used to drop the incident: the correlation is a judgement about the
    /// state at one instant, and a log that quietly omits events is worse than a noisy one
    /// when you are reading it back at 2am to work out what actually happened.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cause: Option<Layer>,
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
            cause: None,
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

    /// Mark this incident as already explained by a fault at `layer`.
    pub fn caused_by(mut self, layer: Layer) -> Self {
        self.cause = Some(layer);
        self
    }

    /// Whether an upstream fault already accounts for this incident.
    pub fn is_downstream(&self) -> bool {
        self.cause.is_some()
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
    written: u64,
}

impl<W: Write> IncidentLog<W> {
    pub fn new(sink: W) -> Self {
        Self { sink, written: 0 }
    }

    /// Same as [`IncidentLog::new`], but starting the byte count at `written` — used when
    /// reopening a log that already has content on disk.
    pub fn resuming(sink: W, written: u64) -> Self {
        Self { sink, written }
    }

    /// Bytes appended through this log, including any pre-existing content it resumed.
    pub fn written(&self) -> u64 {
        self.written
    }

    /// Append one incident as a JSONL line and flush.
    pub fn append(&mut self, incident: &Incident) -> io::Result<()> {
        let line = incident.to_jsonl_line().map_err(io::Error::other)?;
        self.sink.write_all(line.as_bytes())?;
        self.sink.flush()?;
        // Counted only after the write lands, so a failed append can't inflate the count
        // and trigger a rotation over bytes that were never stored.
        self.written += line.len() as u64;
        Ok(())
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
        let existing = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self::resuming(file, existing))
    }

    /// Default on-disk log path (`<data_local_dir>/network_dash/incidents.jsonl`).
    pub fn default_path() -> Option<PathBuf> {
        directories::ProjectDirs::from("", "", "network_dash")
            .map(|d| d.data_local_dir().join("incidents.jsonl"))
    }
}

/// Rotate the log once it passes ~5 MB. At roughly 200 bytes per incident that is ~25k
/// events, far more history than anyone reads, and it bounds the log at 2x the cap.
pub const DEFAULT_MAX_BYTES: u64 = 5 * 1024 * 1024;

/// File-backed incident log with single-generation size rotation: once the live file
/// passes `max_bytes` it is renamed to `<name>.1` (replacing any previous `.1`) and a
/// fresh file is opened. A dashboard left running for months therefore costs a bounded
/// amount of disk instead of growing without limit.
pub struct RotatingLog {
    path: PathBuf,
    max_bytes: u64,
    log: IncidentLog<std::fs::File>,
}

impl RotatingLog {
    /// Open `path` in append mode, resuming its current size so the cap survives restarts.
    pub fn open(path: &Path, max_bytes: u64) -> io::Result<Self> {
        Ok(Self {
            path: path.to_path_buf(),
            max_bytes: max_bytes.max(1),
            log: IncidentLog::open_append(path)?,
        })
    }

    /// Open the default on-disk log at the default size cap.
    pub fn open_default() -> Option<Self> {
        let path = IncidentLog::default_path()?;
        Self::open(&path, DEFAULT_MAX_BYTES).ok()
    }

    /// Bytes in the live generation.
    pub fn written(&self) -> u64 {
        self.log.written()
    }

    /// The retired-generation path (`<name>.1`).
    fn rolled_path(&self) -> PathBuf {
        let mut name = self.path.as_os_str().to_os_string();
        name.push(".1");
        PathBuf::from(name)
    }

    /// Append one incident, rolling the file over first if it is already at the cap.
    pub fn append(&mut self, incident: &Incident) -> io::Result<()> {
        if self.log.written() >= self.max_bytes {
            self.roll()?;
        }
        self.log.append(incident)
    }

    fn roll(&mut self) -> io::Result<()> {
        std::fs::rename(&self.path, self.rolled_path())?;
        self.log = IncidentLog::open_append(&self.path)?;
        Ok(())
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
    fn a_cause_round_trips_and_is_absent_unless_correlated() {
        let plain = sample();
        assert_eq!(plain.cause, None);
        assert!(
            !plain.to_jsonl_line().unwrap().contains("cause"),
            "an uncorrelated incident must not carry an empty field"
        );

        let caused = sample().caused_by(Layer::Gateway);
        let line = caused.to_jsonl_line().unwrap();
        assert!(line.contains("\"cause\":\"gateway\""), "got: {line}");
        assert_eq!(Incident::from_jsonl_line(&line).unwrap(), caused);
    }

    #[test]
    fn a_line_written_before_correlation_existed_still_parses() {
        let line =
            r#"{"ts":"2026-07-20T14:20:03Z","metric":"dns","severity":"warn","message":"x"}"#;
        let inc = Incident::from_jsonl_line(line).expect("old logs must keep loading");
        assert_eq!(inc.cause, None);
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

    /// A unique scratch directory under the OS temp dir, removed by the caller.
    fn scratch(tag: &str) -> PathBuf {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("network_dash-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn log_tracks_bytes_written() {
        let mut log = IncidentLog::new(Vec::new());
        let line_len = sample().to_jsonl_line().unwrap().len() as u64;
        assert_eq!(log.written(), 0);
        log.append(&sample()).unwrap();
        log.append(&sample()).unwrap();
        assert_eq!(log.written(), line_len * 2);
    }

    #[test]
    fn log_rotates_when_over_size_cap() {
        let dir = scratch("rotate");
        let path = dir.join("incidents.jsonl");
        let line_len = sample().to_jsonl_line().unwrap().len() as u64;
        // A cap of exactly two lines: the third append finds the file at the cap and rolls.
        let mut log = RotatingLog::open(&path, line_len * 2).unwrap();
        for _ in 0..3 {
            log.append(&sample()).unwrap();
        }

        let rolled = dir.join("incidents.jsonl.1");
        assert!(rolled.exists(), "the previous generation must be kept");
        assert_eq!(
            std::fs::read_to_string(&rolled).unwrap().lines().count(),
            2,
            "the retired generation holds everything written before the roll"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap().lines().count(),
            1,
            "the live generation restarts empty and holds the triggering incident"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rotating_log_resumes_an_existing_file_without_truncating_it() {
        let dir = scratch("resume");
        let path = dir.join("incidents.jsonl");
        {
            let mut log = RotatingLog::open(&path, 1_000_000).unwrap();
            log.append(&sample()).unwrap();
        }
        // Reopening must count what is already on disk, or the cap resets every launch and
        // an always-restarting dashboard grows the file forever.
        let log = RotatingLog::open(&path, 1_000_000).unwrap();
        assert_eq!(
            log.written(),
            sample().to_jsonl_line().unwrap().len() as u64
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn append_error_is_reported() {
        /// A sink whose every write fails, standing in for a full or read-only disk.
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::StorageFull, "no space left"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let mut log = IncidentLog::new(Broken);
        let err = log
            .append(&sample())
            .expect_err("a failed write must surface");
        assert_eq!(err.kind(), io::ErrorKind::StorageFull);
        // A write that never landed must not count toward the rotation cap.
        assert_eq!(log.written(), 0);
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
