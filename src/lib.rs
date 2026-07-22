//! NetPulse — a network-health TUI dashboard.
//!
//! The crate is split into pure-logic modules (unit-tested without any network or
//! terminal) and thin I/O wrappers. See the design plan for the full architecture.

pub mod app;
pub mod config;
pub mod diagnosis;
pub mod event;
pub mod health;
pub mod history;
pub mod incidents;
pub mod metrics;
pub mod net;
pub mod tui;
pub mod ui;
