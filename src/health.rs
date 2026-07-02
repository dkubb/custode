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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{HealthcheckArgs, HealthcheckError, check};
    use clap::Parser;
    use pretty_assertions::assert_eq;
    use tokio::net::TcpListener;

    /// Test wrapper that parses healthcheck arguments.
    #[derive(Debug, Parser)]
    struct HealthcheckCommand {
        /// Parsed healthcheck arguments.
        #[command(flatten)]
        args: HealthcheckArgs,
    }

    #[test]
    fn parse_defaults_addr_to_local_gateway_port() {
        let command = HealthcheckCommand::try_parse_from(["healthcheck"])
            .expect("empty arguments should parse");

        assert_eq!(
            command.args.addr.to_string(),
            "127.0.0.1:8080",
            "default addr should probe the local gateway port"
        );
    }

    #[test]
    fn parse_accepts_an_explicit_addr() {
        let command = HealthcheckCommand::try_parse_from(["healthcheck", "--addr", "127.0.0.1:1"])
            .expect("explicit addr should parse");

        assert_eq!(
            command.args.addr.to_string(),
            "127.0.0.1:1",
            "explicit addr should override the default"
        );
    }

    #[tokio::test]
    async fn check_succeeds_against_listening_socket() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind an ephemeral port");
        let addr = listener
            .local_addr()
            .expect("listener should expose its address");

        let result = check(HealthcheckArgs { addr }).await;

        assert!(result.is_ok(), "listening socket should pass healthcheck");
    }

    #[tokio::test]
    async fn check_fails_against_closed_port() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind an ephemeral port");
        let addr = listener
            .local_addr()
            .expect("listener should expose its address");
        drop(listener);

        let result = check(HealthcheckArgs { addr }).await;

        assert!(
            matches!(result, Err(HealthcheckError::Connect(_))),
            "closed port should fail healthcheck"
        );
    }
}
