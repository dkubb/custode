//! Binary process edge: command-line interface, dispatch, and exit codes.

use crate::config::{ConfigError, ServeArgs};
use crate::gateway::GatewayError;
use crate::health::{self, HealthcheckError};
use crate::http;
use clap::{Parser, Subcommand};
use std::process::ExitCode;
use thiserror::Error;

/// Custode command-line interface.
#[derive(Debug, Parser)]
#[command(name = "custode-proxy")]
#[command(about = "Run the Custode provider gateway")]
pub struct Cli {
    /// Selected command.
    #[command(subcommand)]
    command: Command,
}

/// Top-level CLI command.
#[derive(Debug, Subcommand)]
enum Command {
    /// Probe a running gateway health endpoint.
    Healthcheck(health::HealthcheckArgs),

    /// Run the HTTP gateway.
    Serve(ServeArgs),
}

impl Cli {
    /// Runs the selected command.
    ///
    /// # Errors
    ///
    /// Returns an error when configuration parsing, serving, or healthchecking
    /// fails.
    #[inline]
    pub async fn run(self) -> Result<(), RunError> {
        match self.command {
            Command::Healthcheck(args) => health::check(args).await.map_err(RunError::from),
            Command::Serve(args) => http::serve(args.try_into()?).await.map_err(RunError::from),
        }
    }
}

/// Process-level error returned by the Custode binary.
#[derive(Debug, Error)]
#[error("{kind}")]
pub struct RunError {
    /// Process exit code.
    code: ExitCode,
    /// Internal error kind.
    kind: RunErrorKind,
}

impl RunError {
    /// Returns the process exit code for this error.
    #[inline]
    #[must_use]
    pub const fn exit_code(&self) -> ExitCode {
        self.code
    }
}

impl From<ConfigError> for RunError {
    #[inline]
    fn from(error: ConfigError) -> Self {
        Self {
            code: ExitCode::from(78),
            kind: RunErrorKind::Config(error),
        }
    }
}

impl From<GatewayError> for RunError {
    #[inline]
    fn from(error: GatewayError) -> Self {
        Self {
            code: ExitCode::from(70),
            kind: RunErrorKind::Gateway(error),
        }
    }
}

impl From<HealthcheckError> for RunError {
    #[inline]
    fn from(error: HealthcheckError) -> Self {
        Self {
            code: ExitCode::from(1),
            kind: RunErrorKind::Healthcheck(error),
        }
    }
}

/// Process-level error variants.
#[derive(Debug, Error)]
enum RunErrorKind {
    /// Gateway configuration is invalid.
    #[error("configuration error: {0}")]
    Config(#[from] ConfigError),

    /// The gateway failed while serving requests.
    #[error("gateway error: {0}")]
    Gateway(#[from] GatewayError),

    /// The healthcheck command failed.
    #[error("healthcheck error: {0}")]
    Healthcheck(#[from] HealthcheckError),
}
