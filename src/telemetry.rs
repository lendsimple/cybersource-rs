//! `tracing` instrumentation (feature `tracing`). Everything logged goes
//! through [`crate::redact`]; secrets and auth headers are never logged.

use tracing::Span;
use web_time::Instant;

use crate::Result;
use crate::config::Config;
use crate::operation::OperationMeta;
use crate::response::Response;

/// Warn this long before a certificate expires.
const EXPIRY_WARNING_SECS: u64 = 90 * 24 * 60 * 60;

pub(crate) fn span(meta: &OperationMeta) -> Span {
    tracing::debug_span!(
        "cybersource.request",
        operation = meta.id,
        method = %meta.method,
        path = meta.path_template,
        status = tracing::field::Empty,
        correlation_id = tracing::field::Empty,
        elapsed_ms = tracing::field::Empty,
    )
}

pub(crate) fn finished<T>(span: &Span, result: &Result<Response<T>>, start: Instant) {
    let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    span.record("elapsed_ms", elapsed_ms);
    match result {
        Ok(response) => {
            span.record("status", response.status.as_u16());
            if let Some(id) = response.correlation_id() {
                span.record("correlation_id", id);
            }
            tracing::debug!(parent: span, status = response.status.as_u16(), elapsed_ms, "cybersource request succeeded");
        }
        Err(error) => {
            if let Some(api) = error.as_api() {
                span.record("status", api.status.as_u16());
                if let Some(id) = &api.correlation_id {
                    span.record("correlation_id", id.as_str());
                }
            }
            tracing::debug!(parent: span, %error, elapsed_ms, "cybersource request failed");
        }
    }
}

/// Logs certificate expiry and MLE configuration warnings once, when a
/// [`Config`] is built.
pub(crate) fn config_warnings(config: &Config) {
    let now = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    for cert in config.certificate_expiries() {
        if cert.not_after_unix <= now {
            tracing::warn!(role = ?cert.role, subject = %cert.subject, "certificate has expired");
        } else if cert.not_after_unix - now < EXPIRY_WARNING_SECS {
            let days = (cert.not_after_unix - now) / 86_400;
            tracing::warn!(role = ?cert.role, subject = %cert.subject, days, "certificate expires soon");
        }
    }
    for warning in config.mle().warnings() {
        tracing::warn!("{warning}");
    }
}
