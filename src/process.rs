//! Process-level error surface.

use crate::config::ConfigError;
use crate::gateway::GatewayError;
use crate::health::HealthcheckError;
use std::process::ExitCode;
use thiserror::Error;

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
