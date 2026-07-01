//! Library crate for Custode.
//!
//! Custode runs an untrusted harness behind a small provider gateway. The
//! library contains the typed configuration, allowlist, audit, header, body,
//! and gateway decision surfaces. The binary wires those decisions to HTTP,
//! process startup, and container runtime edges.

#[cfg(test)]
use tempfile as _;
#[cfg(test)]
use tower as _;
use tracing_subscriber as _;

pub mod allowlist;
pub mod audit;
pub mod body;
pub mod config;
pub mod gateway;
pub mod headers;
pub mod health;
pub mod http;
pub mod process;

pub use config::Cli;
