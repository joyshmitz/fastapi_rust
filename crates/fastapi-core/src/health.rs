//! Health check endpoint helpers for operations.
//!
//! Provides standard health check patterns:
//! - Basic health: returns `{"status":"healthy"}` on `GET /health`
//! - Detailed health with named checks, critical flags, and per-check latency
//! - Kubernetes-style liveness (`/healthz`) and readiness (`/ready`) probes
//!
//! # Example
//!
//! ```ignore
//! use fastapi_core::health::{HealthCheckRegistry, HealthStatus};
//!
//! let mut registry = HealthCheckRegistry::new();
//! registry.add("database", true, || async {
//!     // Check database connection
//!     Ok(())
//! });
//! registry.add("cache", false, || async {
//!     // Check cache connection (non-critical)
//!     Ok(())
//! });
//!
//! let result = futures_executor::block_on(registry.check_all());
//! assert_eq!(result.status, HealthStatus::Healthy);
//! ```

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

use crate::context::RequestContext;
use crate::request::Request;
use crate::response::{Response, ResponseBody, StatusCode};

/// Overall health status of the application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HealthStatus {
    /// All checks pass.
    Healthy,
    /// At least one non-critical check failed, but all critical checks pass.
    Degraded,
    /// At least one critical check failed.
    Unhealthy,
}

impl HealthStatus {
    /// Returns the string representation.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Unhealthy => "unhealthy",
        }
    }

    /// Returns the HTTP status code for this health status.
    #[must_use]
    pub fn status_code(self) -> StatusCode {
        match self {
            Self::Healthy | Self::Degraded => StatusCode::OK,
            Self::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Result of a single named health check.
#[derive(Debug, Clone)]
pub struct HealthCheckResult {
    /// Name of the check.
    pub name: String,
    /// Whether the check passed.
    pub passed: bool,
    /// Whether this is a critical check.
    pub critical: bool,
    /// Time the check took.
    pub latency_ms: u64,
    /// Error message if the check failed.
    pub error: Option<String>,
}

/// Aggregate result of all health checks.
#[derive(Debug, Clone)]
pub struct HealthReport {
    /// Overall status.
    pub status: HealthStatus,
    /// Individual check results.
    pub checks: Vec<HealthCheckResult>,
    /// Total time for all checks.
    pub total_latency_ms: u64,
}

impl HealthReport {
    /// Serialize the report to JSON bytes.
    #[must_use]
    pub fn to_json(&self) -> Vec<u8> {
        let mut json = String::with_capacity(256);
        json.push_str("{\"status\":\"");
        json.push_str(self.status.as_str());
        json.push_str("\",\"total_latency_ms\":");
        json.push_str(&self.total_latency_ms.to_string());
        json.push_str(",\"checks\":[");

        for (i, check) in self.checks.iter().enumerate() {
            if i > 0 {
                json.push(',');
            }
            json.push_str("{\"name\":\"");
            json.push_str(&check.name);
            json.push_str("\",\"passed\":");
            json.push_str(if check.passed { "true" } else { "false" });
            json.push_str(",\"critical\":");
            json.push_str(if check.critical { "true" } else { "false" });
            json.push_str(",\"latency_ms\":");
            json.push_str(&check.latency_ms.to_string());
            if let Some(ref err) = check.error {
                json.push_str(",\"error\":\"");
                // Escape JSON special characters
                for ch in err.chars() {
                    match ch {
                        '"' => json.push_str("\\\""),
                        '\\' => json.push_str("\\\\"),
                        '\n' => json.push_str("\\n"),
                        '\r' => json.push_str("\\r"),
                        '\t' => json.push_str("\\t"),
                        c => json.push(c),
                    }
                }
                json.push('"');
            }
            json.push('}');
        }

        json.push_str("]}");
        json.into_bytes()
    }
}

/// A boxed future for health check functions.
type CheckFn =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>> + Send + Sync>;

/// A single health check entry.
struct HealthCheckEntry {
    name: String,
    critical: bool,
    check_fn: CheckFn,
}

/// Registry of health checks.
///
/// Collects named health checks that can be evaluated together to produce
/// a [`HealthReport`].
///
/// # Example
///
/// ```ignore
/// let mut registry = HealthCheckRegistry::new();
///
/// // Critical check — failure makes the app "unhealthy"
/// registry.add("database", true, || async {
///     // db.ping().await?;
///     Ok(())
/// });
///
/// // Non-critical check — failure makes the app "degraded"
/// registry.add("cache", false, || async {
///     // cache.ping().await?;
///     Ok(())
/// });
/// ```
pub struct HealthCheckRegistry {
    checks: Vec<HealthCheckEntry>,
}

impl HealthCheckRegistry {
    /// Create a new empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self { checks: Vec::new() }
    }

    /// Add a named health check.
    ///
    /// # Parameters
    ///
    /// - `name`: Identifier for the check (e.g., "database", "cache").
    /// - `critical`: If `true`, failure of this check makes the overall status `Unhealthy`.
    ///   If `false`, failure makes it `Degraded` (unless another critical check fails).
    /// - `check_fn`: Async function that returns `Ok(())` on success or `Err(message)` on failure.
    pub fn add<F, Fut>(&mut self, name: impl Into<String>, critical: bool, check_fn: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), String>> + Send + 'static,
    {
        let check_fn = Arc::new(move || {
            let fut = check_fn();
            Box::pin(fut) as Pin<Box<dyn Future<Output = Result<(), String>> + Send>>
        }) as CheckFn;

        self.checks.push(HealthCheckEntry {
            name: name.into(),
            critical,
            check_fn,
        });
    }

    /// Run all health checks and produce a report.
    pub async fn check_all(&self) -> HealthReport {
        let total_start = Instant::now();
        let mut results = Vec::with_capacity(self.checks.len());
        let mut has_critical_failure = false;
        let mut has_non_critical_failure = false;

        for entry in &self.checks {
            let start = Instant::now();
            let outcome = (entry.check_fn)().await;
            let latency_ms = start.elapsed().as_millis() as u64;

            let (passed, error) = match outcome {
                Ok(()) => (true, None),
                Err(msg) => {
                    if entry.critical {
                        has_critical_failure = true;
                    } else {
                        has_non_critical_failure = true;
                    }
                    (false, Some(msg))
                }
            };

            results.push(HealthCheckResult {
                name: entry.name.clone(),
                passed,
                critical: entry.critical,
                latency_ms,
                error,
            });
        }

        let status = if has_critical_failure {
            HealthStatus::Unhealthy
        } else if has_non_critical_failure {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };

        HealthReport {
            status,
            checks: results,
            total_latency_ms: total_start.elapsed().as_millis() as u64,
        }
    }

    /// Returns the number of registered checks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.checks.len()
    }

    /// Returns true if no checks are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.checks.is_empty()
    }
}

impl Default for HealthCheckRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a basic health check handler that returns `{"status":"healthy"}`.
///
/// This is the simplest health check — always returns 200 OK. Useful as a
/// basic liveness probe when you just need to confirm the process is running.
pub fn basic_health_handler()
-> impl Fn(&RequestContext, &mut Request) -> std::future::Ready<Response> + Send + Sync + 'static {
    |_ctx: &RequestContext, _req: &mut Request| {
        let body = br#"{"status":"healthy"}"#.to_vec();
        std::future::ready(
            Response::with_status(StatusCode::OK)
                .header("Content-Type", b"application/json".to_vec())
                .body(ResponseBody::Bytes(body)),
        )
    }
}

/// Create a detailed health check handler from a registry.
///
/// Runs all registered checks and returns:
/// - 200 OK with `{"status":"healthy", ...}` when all checks pass
/// - 200 OK with `{"status":"degraded", ...}` when non-critical checks fail
/// - 503 Service Unavailable with `{"status":"unhealthy", ...}` when critical checks fail
pub fn detailed_health_handler(
    registry: Arc<HealthCheckRegistry>,
) -> impl Fn(&RequestContext, &mut Request) -> Pin<Box<dyn Future<Output = Response> + Send>>
+ Send
+ Sync
+ 'static {
    move |_ctx: &RequestContext, _req: &mut Request| {
        let registry = Arc::clone(&registry);
        Box::pin(async move {
            let report = registry.check_all().await;
            let status_code = report.status.status_code();
            let body = report.to_json();

            Response::with_status(status_code)
                .header("Content-Type", b"application/json".to_vec())
                .header("Cache-Control", b"no-cache, no-store".to_vec())
                .body(ResponseBody::Bytes(body))
        })
    }
}

/// Create a Kubernetes liveness probe handler.
///
/// Returns 200 OK if the process is alive. This is equivalent to `basic_health_handler()`
/// but semantically represents a liveness check.
pub fn liveness_handler()
-> impl Fn(&RequestContext, &mut Request) -> std::future::Ready<Response> + Send + Sync + 'static {
    basic_health_handler()
}

/// Create a Kubernetes readiness probe handler from a registry.
///
/// Runs all checks and returns:
/// - 200 OK when the app is ready to serve traffic
/// - 503 Service Unavailable when critical checks fail
///
/// Kubernetes will stop routing traffic to pods that fail readiness checks.
pub fn readiness_handler(
    registry: Arc<HealthCheckRegistry>,
) -> impl Fn(&RequestContext, &mut Request) -> Pin<Box<dyn Future<Output = Response> + Send>>
+ Send
+ Sync
+ 'static {
    detailed_health_handler(registry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::Method;

    fn run_handler<F, Fut>(handler: F) -> Response
    where
        F: Fn(&RequestContext, &mut Request) -> Fut,
        Fut: Future<Output = Response>,
    {
        let ctx = RequestContext::new(asupersync::Cx::for_testing(), 1);
        let mut req = Request::new(Method::Get, "/health");
        futures_executor::block_on(handler(&ctx, &mut req))
    }

    #[test]
    fn health_status_as_str() {
        assert_eq!(HealthStatus::Healthy.as_str(), "healthy");
        assert_eq!(HealthStatus::Degraded.as_str(), "degraded");
        assert_eq!(HealthStatus::Unhealthy.as_str(), "unhealthy");
    }

    #[test]
    fn health_status_display() {
        assert_eq!(format!("{}", HealthStatus::Healthy), "healthy");
        assert_eq!(format!("{}", HealthStatus::Unhealthy), "unhealthy");
    }

    #[test]
    fn health_status_code() {
        assert_eq!(HealthStatus::Healthy.status_code(), StatusCode::OK);
        assert_eq!(HealthStatus::Degraded.status_code(), StatusCode::OK);
        assert_eq!(
            HealthStatus::Unhealthy.status_code(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn empty_registry_is_healthy() {
        let registry = HealthCheckRegistry::new();
        assert!(registry.is_empty());
        let report = futures_executor::block_on(registry.check_all());
        assert_eq!(report.status, HealthStatus::Healthy);
        assert!(report.checks.is_empty());
    }

    #[test]
    fn all_checks_pass_is_healthy() {
        let mut registry = HealthCheckRegistry::new();
        registry.add("database", true, || async { Ok(()) });
        registry.add("cache", false, || async { Ok(()) });

        let report = futures_executor::block_on(registry.check_all());
        assert_eq!(report.status, HealthStatus::Healthy);
        assert_eq!(report.checks.len(), 2);
        assert!(report.checks[0].passed);
        assert!(report.checks[1].passed);
    }

    #[test]
    fn non_critical_failure_is_degraded() {
        let mut registry = HealthCheckRegistry::new();
        registry.add("database", true, || async { Ok(()) });
        registry.add("cache", false, || async {
            Err("Cache connection refused".to_string())
        });

        let report = futures_executor::block_on(registry.check_all());
        assert_eq!(report.status, HealthStatus::Degraded);
        assert!(report.checks[0].passed);
        assert!(!report.checks[1].passed);
        assert_eq!(
            report.checks[1].error.as_deref(),
            Some("Cache connection refused")
        );
    }

    #[test]
    fn critical_failure_is_unhealthy() {
        let mut registry = HealthCheckRegistry::new();
        registry.add("database", true, || async {
            Err("Connection timeout".to_string())
        });
        registry.add("cache", false, || async { Ok(()) });

        let report = futures_executor::block_on(registry.check_all());
        assert_eq!(report.status, HealthStatus::Unhealthy);
        assert!(!report.checks[0].passed);
        assert!(report.checks[0].critical);
        assert!(report.checks[1].passed);
    }

    #[test]
    fn latency_is_measured() {
        let mut registry = HealthCheckRegistry::new();
        registry.add("fast", true, || async { Ok(()) });

        let report = futures_executor::block_on(registry.check_all());
        // Latency should be >= 0 (can't be negative)
        assert!(report.checks[0].latency_ms < 1000);
        assert!(report.total_latency_ms < 1000);
    }

    #[test]
    fn report_to_json_healthy() {
        let report = HealthReport {
            status: HealthStatus::Healthy,
            checks: vec![HealthCheckResult {
                name: "database".to_string(),
                passed: true,
                critical: true,
                latency_ms: 5,
                error: None,
            }],
            total_latency_ms: 5,
        };

        let json = String::from_utf8(report.to_json()).unwrap();
        assert!(json.contains("\"status\":\"healthy\""));
        assert!(json.contains("\"name\":\"database\""));
        assert!(json.contains("\"passed\":true"));
        assert!(json.contains("\"critical\":true"));
        assert!(json.contains("\"latency_ms\":5"));
    }

    #[test]
    fn report_to_json_unhealthy_with_error() {
        let report = HealthReport {
            status: HealthStatus::Unhealthy,
            checks: vec![HealthCheckResult {
                name: "database".to_string(),
                passed: false,
                critical: true,
                latency_ms: 3000,
                error: Some("Connection refused".to_string()),
            }],
            total_latency_ms: 3000,
        };

        let json = String::from_utf8(report.to_json()).unwrap();
        assert!(json.contains("\"status\":\"unhealthy\""));
        assert!(json.contains("\"passed\":false"));
        assert!(json.contains("\"error\":\"Connection refused\""));
    }

    #[test]
    fn report_to_json_escapes_special_chars() {
        let report = HealthReport {
            status: HealthStatus::Unhealthy,
            checks: vec![HealthCheckResult {
                name: "test".to_string(),
                passed: false,
                critical: true,
                latency_ms: 0,
                error: Some("Error with \"quotes\" and \\backslash".to_string()),
            }],
            total_latency_ms: 0,
        };

        let json = String::from_utf8(report.to_json()).unwrap();
        assert!(json.contains(r#"\"quotes\""#));
        assert!(json.contains(r"\\backslash"));
    }

    #[test]
    fn basic_health_handler_returns_200() {
        let handler = basic_health_handler();
        let resp = run_handler(handler);
        assert_eq!(resp.status(), StatusCode::OK);

        if let ResponseBody::Bytes(body) = resp.body_ref() {
            let body_str = std::str::from_utf8(body).unwrap();
            assert!(body_str.contains("\"status\":\"healthy\""));
        } else {
            panic!("expected Bytes body");
        }
    }

    #[test]
    fn detailed_health_handler_healthy() {
        let mut registry = HealthCheckRegistry::new();
        registry.add("db", true, || async { Ok(()) });
        let handler = detailed_health_handler(Arc::new(registry));

        let ctx = RequestContext::new(asupersync::Cx::for_testing(), 1);
        let mut req = Request::new(Method::Get, "/health");
        let resp = futures_executor::block_on(handler(&ctx, &mut req));
        assert_eq!(resp.status(), StatusCode::OK);

        if let ResponseBody::Bytes(body) = resp.body_ref() {
            let body_str = std::str::from_utf8(body).unwrap();
            assert!(body_str.contains("\"status\":\"healthy\""));
            assert!(body_str.contains("\"name\":\"db\""));
        } else {
            panic!("expected Bytes body");
        }
    }

    #[test]
    fn detailed_health_handler_unhealthy_returns_503() {
        let mut registry = HealthCheckRegistry::new();
        registry.add("db", true, || async { Err("down".to_string()) });
        let handler = detailed_health_handler(Arc::new(registry));

        let ctx = RequestContext::new(asupersync::Cx::for_testing(), 1);
        let mut req = Request::new(Method::Get, "/health");
        let resp = futures_executor::block_on(handler(&ctx, &mut req));
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        if let ResponseBody::Bytes(body) = resp.body_ref() {
            let body_str = std::str::from_utf8(body).unwrap();
            assert!(body_str.contains("\"status\":\"unhealthy\""));
        } else {
            panic!("expected Bytes body");
        }
    }

    #[test]
    fn detailed_health_handler_has_cache_headers() {
        let registry = HealthCheckRegistry::new();
        let handler = detailed_health_handler(Arc::new(registry));

        let ctx = RequestContext::new(asupersync::Cx::for_testing(), 1);
        let mut req = Request::new(Method::Get, "/health");
        let resp = futures_executor::block_on(handler(&ctx, &mut req));

        let has_no_cache = resp
            .headers()
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case("cache-control") && v == b"no-cache, no-store");
        assert!(
            has_no_cache,
            "should have Cache-Control: no-cache, no-store"
        );
    }

    #[test]
    fn registry_len_and_is_empty() {
        let mut registry = HealthCheckRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);

        registry.add("db", true, || async { Ok(()) });
        assert!(!registry.is_empty());
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn liveness_handler_returns_200() {
        let handler = liveness_handler();
        let resp = run_handler(handler);
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn readiness_handler_healthy_returns_200() {
        let mut registry = HealthCheckRegistry::new();
        registry.add("db", true, || async { Ok(()) });
        let handler = readiness_handler(Arc::new(registry));

        let ctx = RequestContext::new(asupersync::Cx::for_testing(), 1);
        let mut req = Request::new(Method::Get, "/ready");
        let resp = futures_executor::block_on(handler(&ctx, &mut req));
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn readiness_handler_unhealthy_returns_503() {
        let mut registry = HealthCheckRegistry::new();
        registry.add("db", true, || async { Err("down".to_string()) });
        let handler = readiness_handler(Arc::new(registry));

        let ctx = RequestContext::new(asupersync::Cx::for_testing(), 1);
        let mut req = Request::new(Method::Get, "/ready");
        let resp = futures_executor::block_on(handler(&ctx, &mut req));
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn multiple_checks_mixed_results() {
        let mut registry = HealthCheckRegistry::new();
        registry.add("database", true, || async { Ok(()) });
        registry.add("cache", false, || async {
            Err("Cache timeout".to_string())
        });
        registry.add("search", false, || async { Ok(()) });

        let report = futures_executor::block_on(registry.check_all());
        assert_eq!(report.status, HealthStatus::Degraded);
        assert_eq!(report.checks.len(), 3);

        // Database passed
        assert!(report.checks[0].passed);
        assert!(report.checks[0].critical);

        // Cache failed (non-critical)
        assert!(!report.checks[1].passed);
        assert!(!report.checks[1].critical);
        assert!(report.checks[1].error.is_some());

        // Search passed
        assert!(report.checks[2].passed);
    }
}
