//! Small async subprocess helper shared by the shell-out probes (routing, link).
//!
//! Probes run external tools (`traceroute`, `system_profiler`) that can each take several
//! seconds. Running them via `tokio::task::spawn_blocking` + `std::process::Command` makes
//! them **uncancellable**: on quit, dropping the tokio runtime blocks until any in-flight
//! blocking closure returns, so the program appears to hang. Using async
//! [`tokio::process::Command`] with `kill_on_drop(true)` instead means an aborted probe (or
//! a runtime shutdown) drops the future and kills the child immediately.

/// Run `program` with `args` to completion, returning its captured stdout as a lossy
/// UTF-8 string, or `None` if the process could not be spawned. Exit status is ignored
/// (tools like `traceroute` exit non-zero but still print a useful path).
///
/// The child is killed if this future is dropped (e.g. the probe task is aborted on quit),
/// so it can never delay shutdown.
pub async fn run_capture(program: &str, args: &[&str]) -> Option<String> {
    let out = tokio::process::Command::new(program)
        .args(args)
        .kill_on_drop(true)
        .output()
        .await
        .ok()?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[tokio::test]
    async fn captures_stdout() {
        let out = run_capture("echo", &["netpulse-ok"]).await.unwrap();
        assert_eq!(out.trim(), "netpulse-ok");
    }

    #[tokio::test]
    async fn missing_program_returns_none() {
        let out = run_capture("network_dash_no_such_binary_xyz", &[]).await;
        assert_eq!(out, None);
    }

    /// Regression for the shutdown-hang bug: a still-running child must be killed when the
    /// `run_capture` future is dropped, rather than surviving to complete its work. Uses a
    /// real subprocess + the filesystem, so it is `#[ignore]`d out of the fast suite.
    #[tokio::test]
    #[ignore = "spawns a real subprocess and touches the filesystem"]
    async fn dropping_the_future_kills_the_child() {
        use std::time::Duration;

        let marker =
            std::env::temp_dir().join(format!("netpulse_killtest_{}.marker", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        let script = format!("sleep 2; touch {}", marker.display());

        // Drop the future well before the child would create the marker.
        let dropped = tokio::time::timeout(
            Duration::from_millis(200),
            run_capture("sh", &["-c", &script]),
        )
        .await;
        assert!(dropped.is_err(), "child unexpectedly finished within 200ms");

        // Wait past the point where a surviving child would have touched the marker.
        tokio::time::sleep(Duration::from_millis(2500)).await;
        let existed = marker.exists();
        let _ = std::fs::remove_file(&marker);
        assert!(
            !existed,
            "child was not killed on drop: it survived and created {}",
            marker.display()
        );
    }
}
