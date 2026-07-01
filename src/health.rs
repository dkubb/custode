//! Healthcheck command and endpoint.

use clap::Args;
use core::net::SocketAddr;
use std::io;
use thiserror::Error;
use tokio::net::TcpStream;

/// Healthcheck CLI arguments.
#[derive(Clone, Copy, Debug, Args)]
pub(crate) struct HealthcheckArgs {
    /// Gateway socket address to probe from inside the proxy container.
    #[arg(long, default_value = "127.0.0.1:8080")]
    addr: SocketAddr,
}

/// Healthcheck error.
#[derive(Debug, Error)]
pub(crate) enum HealthcheckError {
    /// TCP healthcheck failed.
    #[error("healthcheck TCP connection failed: {0}")]
    Connect(io::Error),
}

/// Runs a healthcheck request.
///
/// # Errors
///
/// Returns an error when the request fails or the gateway is not healthy.
pub(crate) async fn check(args: HealthcheckArgs) -> Result<(), HealthcheckError> {
    TcpStream::connect(args.addr)
        .await
        .map(|_stream| ())
        .map_err(HealthcheckError::Connect)
}
