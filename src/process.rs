//! Binary process edge: command-line interface, dispatch, and exit codes.

use crate::config::{ConfigError, ServeArgs};
use crate::health::{self, HealthcheckError};
use crate::http::{self, ServeError};
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
    /// ```
    /// use clap::Parser as _;
    /// use custode::Cli;
    ///
    /// let cli = Cli::try_parse_from([
    ///     "custode-proxy",
    ///     "serve",
    ///     "--upstream-origin",
    ///     "https://api.openai.com",
    /// ])?;
    /// let result = tokio::runtime::Runtime::new()?.block_on(cli.run());
    ///
    /// assert!(result.is_err());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
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
    ///
    /// ```
    /// use clap::Parser as _;
    /// use custode::Cli;
    ///
    /// let cli = Cli::try_parse_from([
    ///     "custode-proxy",
    ///     "serve",
    ///     "--upstream-origin",
    ///     "https://api.openai.com",
    /// ])?;
    /// let error = tokio::runtime::Runtime::new()?
    ///     .block_on(cli.run())
    ///     .expect_err("empty allowlist should fail closed");
    ///
    /// let _exit_code = error.exit_code();
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
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

impl From<ServeError> for RunError {
    #[inline]
    fn from(error: ServeError) -> Self {
        Self {
            code: ExitCode::from(70),
            kind: RunErrorKind::Serve(error),
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

    /// The healthcheck command failed.
    #[error("healthcheck error: {0}")]
    Healthcheck(#[from] HealthcheckError),

    /// The gateway failed while serving requests.
    #[error("gateway error: {0}")]
    Serve(#[from] ServeError),
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[expect(
    clippy::inline_modules,
    reason = "inline tests keep file-local coverage ownership explicit"
)]
mod tests {
    use super::{Cli, Command, RunError};
    use crate::config::ConfigError;
    use crate::health::HealthcheckError;
    use crate::http::ServeError;
    use clap::Parser as _;
    use pretty_assertions::assert_eq;
    use std::io;
    use std::process::ExitCode;
    use tempfile::tempdir;
    use tokio::net::TcpListener;

    /// Renders an exit code for comparison because `ExitCode` has no equality.
    fn rendered(code: ExitCode) -> String {
        format!("{code:?}")
    }

    #[test]
    fn from_config_error_uses_configuration_exit_code() {
        let error = RunError::from(ConfigError::EmptyOperations);

        assert_eq!(
            rendered(error.exit_code()),
            rendered(ExitCode::from(78)),
            "configuration errors should exit with EX_CONFIG"
        );
    }

    #[test]
    fn from_serve_error_uses_software_exit_code() {
        let error = RunError::from(ServeError::Server(io::Error::other("boom")));

        assert_eq!(
            rendered(error.exit_code()),
            rendered(ExitCode::from(70)),
            "serve errors should exit with EX_SOFTWARE"
        );
    }

    #[test]
    fn from_healthcheck_error_uses_failure_exit_code() {
        let error = RunError::from(HealthcheckError::Connect(io::Error::other("boom")));

        assert_eq!(
            rendered(error.exit_code()),
            rendered(ExitCode::from(1)),
            "healthcheck errors should exit with a generic failure"
        );
    }

    #[test]
    fn display_prefixes_configuration_errors() {
        let error = RunError::from(ConfigError::EmptyOperations);

        assert_eq!(
            error.to_string(),
            "configuration error: at least one allowed operation is required"
        );
    }

    #[test]
    fn display_prefixes_serve_errors() {
        let error = RunError::from(ServeError::Server(io::Error::other("boom")));

        assert_eq!(
            error.to_string(),
            "gateway error: gateway server failed: boom"
        );
    }

    #[test]
    fn display_prefixes_healthcheck_errors() {
        let error = RunError::from(HealthcheckError::Connect(io::Error::other("boom")));

        assert_eq!(
            error.to_string(),
            "healthcheck error: healthcheck TCP connection failed: boom"
        );
    }

    #[test]
    fn parse_selects_the_healthcheck_command() {
        let cli = Cli::try_parse_from(["custode-proxy", "healthcheck", "--addr", "127.0.0.1:1"])
            .expect("healthcheck arguments should parse");

        assert!(
            matches!(cli.command, Command::Healthcheck(_)),
            "healthcheck subcommand should be selected"
        );
    }

    #[test]
    fn parse_selects_the_serve_command() {
        let cli = Cli::try_parse_from([
            "custode-proxy",
            "serve",
            "--upstream-origin",
            "https://api.openai.com",
            "--allowed-operations",
            "GET:exact:/v1/models",
        ])
        .expect("serve arguments should parse");

        assert!(
            matches!(cli.command, Command::Serve(_)),
            "serve subcommand should be selected"
        );
    }

    #[tokio::test]
    async fn run_healthcheck_succeeds_against_listening_gateway() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind an ephemeral port");
        let addr = listener
            .local_addr()
            .expect("listener should expose its address")
            .to_string();
        let cli = Cli::try_parse_from(["custode-proxy", "healthcheck", "--addr", &addr])
            .expect("healthcheck arguments should parse");

        let result = cli.run().await;

        assert!(result.is_ok(), "healthcheck should reach the listener");
    }

    #[tokio::test]
    async fn run_healthcheck_fails_against_closed_port() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind an ephemeral port");
        let addr = listener
            .local_addr()
            .expect("listener should expose its address")
            .to_string();
        drop(listener);
        let cli = Cli::try_parse_from(["custode-proxy", "healthcheck", "--addr", &addr])
            .expect("healthcheck arguments should parse");

        let result = cli.run().await;

        let error = result.expect_err("closed port should fail healthcheck");
        assert_eq!(
            rendered(error.exit_code()),
            rendered(ExitCode::from(1)),
            "healthcheck failures should exit with a generic failure"
        );
    }

    #[tokio::test]
    async fn run_serve_rejects_an_empty_allowlist() {
        let cli = Cli::try_parse_from([
            "custode-proxy",
            "serve",
            "--upstream-origin",
            "https://api.openai.com",
        ])
        .expect("serve arguments should parse");

        let result = cli.run().await;

        let error = result.expect_err("an empty allowlist should fail closed");
        assert_eq!(
            rendered(error.exit_code()),
            rendered(ExitCode::from(78)),
            "configuration errors should exit with EX_CONFIG"
        );
    }

    #[tokio::test]
    async fn run_serve_fails_when_audit_log_is_a_directory() {
        let directory = tempdir().expect("temporary directory should be created");
        let audit_log = directory
            .path()
            .to_str()
            .expect("temporary path should be UTF-8")
            .to_owned();
        let cli = Cli::try_parse_from([
            "custode-proxy",
            "serve",
            "--upstream-origin",
            "https://api.openai.com",
            "--allowed-operations",
            "GET:exact:/v1/models",
            "--bind",
            "127.0.0.1:0",
            "--audit-log",
            &audit_log,
        ])
        .expect("serve arguments should parse");

        let result = cli.run().await;

        let error = result.expect_err("a directory audit log should fail serving");
        assert_eq!(
            rendered(error.exit_code()),
            rendered(ExitCode::from(70)),
            "serve errors should exit with EX_SOFTWARE"
        );
    }
}
