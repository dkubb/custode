//! Command-line entry point for the Custode provider gateway.

use axum as _;
use blake3 as _;
use clap::Parser as _;
use custode::Cli;
use futures_util as _;
use getrandom as _;
use http as _;
use http_body_util as _;
use humantime as _;
use non_empty_string as _;
#[cfg(test)]
use pretty_assertions as _;
#[cfg(test)]
use proptest as _;
use reqwest as _;
use serde as _;
use serde_json as _;
use std::io::{self, Write as _};
use std::process::ExitCode;
#[cfg(test)]
use tempfile as _;
use thiserror as _;
use tokio_stream as _;
#[cfg(test)]
use tower as _;
use tracing as _;
use tracing_subscriber::EnvFilter;
use url as _;

#[tokio::main]
async fn main() -> ExitCode {
    initialize_tracing();

    let cli = Cli::parse();
    match cli.run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            writeln!(io::stderr(), "{error}").expect("stderr should accept errors");
            error.exit_code()
        }
    }
}

/// Initializes optional `RUST_LOG` tracing for runtime diagnostics.
fn initialize_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("off"));
    let _result = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(io::stderr)
        .try_init();
    tracing::debug!("tracing initialized");
}
