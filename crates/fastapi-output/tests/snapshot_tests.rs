//! Visual regression tests using insta snapshots.
//!
//! These tests ensure output formatting remains stable across changes.
//! Run `cargo insta review` to update snapshots after intentional changes.

use fastapi_output::components::banner::{Banner, ServerInfo};
use fastapi_output::components::dependency_tree::{DependencyNode, DependencyTreeDisplay};
use fastapi_output::components::errors::{ErrorFormatter, HttpErrorInfo, LocItem, ValidationErrorDetail};
use fastapi_output::components::logging::{HttpMethod, LogEntry, RequestLogger, ResponseTiming};
use fastapi_output::components::middleware_stack::{MiddlewareInfo, MiddlewareStackDisplay};
use fastapi_output::components::routes::{RouteDisplay, RouteEntry};
use fastapi_output::components::shutdown_progress::{ShutdownPhase, ShutdownProgress, ShutdownProgressDisplay};
use fastapi_output::components::test_results::{TestCaseResult, TestModuleResult, TestReport, TestReportDisplay, TestStatus};
use fastapi_output::mode::OutputMode;
use fastapi_output::testing::strip_ansi_codes;
use insta::assert_snapshot;
use std::time::Duration;

// =============================================================================
// Banner Snapshots
// =============================================================================

#[test]
fn snapshot_banner_plain() {
    eprintln!("[SNAPSHOT] Testing: Banner (plain mode)");
    let banner = Banner::new(OutputMode::Plain);
    let info = ServerInfo::new("1.0.0", "localhost", 8000)
        .docs_path("/docs")
        .redoc_path("/redoc")
        .openapi_path("/openapi.json");

    let output = banner.render(&info);
    eprintln!("[SNAPSHOT] Output length: {} chars", output.len());
    assert_snapshot!("banner_plain", output);
}

#[test]
fn snapshot_banner_rich_content() {
    eprintln!("[SNAPSHOT] Testing: Banner (rich mode, stripped)");
    let banner = Banner::new(OutputMode::Rich);
    let info = ServerInfo::new("1.0.0", "localhost", 8000)
        .docs_path("/docs");

    let output = banner.render(&info);
    // Strip ANSI for readable snapshot
    let normalized = strip_ansi_codes(&output);
    eprintln!("[SNAPSHOT] Output length: {} chars (stripped)", normalized.len());
    assert_snapshot!("banner_rich_content", normalized);
}

#[test]
fn snapshot_banner_minimal() {
    eprintln!("[SNAPSHOT] Testing: Banner (minimal info)");
    let banner = Banner::new(OutputMode::Plain);
    let info = ServerInfo::new("0.1.0", "0.0.0.0", 3000);

    let output = banner.render(&info);
    assert_snapshot!("banner_minimal", output);
}

// =============================================================================
// Routes Table Snapshots
// =============================================================================

#[test]
fn snapshot_routes_table_basic() {
    eprintln!("[SNAPSHOT] Testing: Routes table (basic)");
    let display = RouteDisplay::new(OutputMode::Plain);
    let routes = vec![
        RouteEntry::new("GET", "/users").handler("list_users"),
        RouteEntry::new("POST", "/users").handler("create_user"),
        RouteEntry::new("GET", "/users/{id}").handler("get_user"),
        RouteEntry::new("PUT", "/users/{id}").handler("update_user"),
        RouteEntry::new("DELETE", "/users/{id}").handler("delete_user"),
    ];

    let output = display.render(&routes);
    eprintln!("[SNAPSHOT] Routes count: {}", routes.len());
    assert_snapshot!("routes_table_basic", output);
}

#[test]
fn snapshot_routes_table_empty() {
    eprintln!("[SNAPSHOT] Testing: Routes table (empty)");
    let display = RouteDisplay::new(OutputMode::Plain);
    let routes: Vec<RouteEntry> = vec![];

    let output = display.render(&routes);
    assert_snapshot!("routes_table_empty", output);
}

#[test]
fn snapshot_routes_table_with_tags() {
    eprintln!("[SNAPSHOT] Testing: Routes table (with tags)");
    let display = RouteDisplay::new(OutputMode::Plain);
    let routes = vec![
        RouteEntry::new("GET", "/api/v1/users")
            .handler("list_users")
            .tags(vec!["users", "api-v1"]),
        RouteEntry::new("GET", "/api/v1/posts")
            .handler("list_posts")
            .tags(vec!["posts", "api-v1"]),
    ];

    let output = display.render(&routes);
    assert_snapshot!("routes_table_with_tags", output);
}

// =============================================================================
// Validation Error Snapshots
// =============================================================================

#[test]
fn snapshot_validation_error_single() {
    eprintln!("[SNAPSHOT] Testing: Validation error (single)");
    let formatter = ErrorFormatter::new(OutputMode::Plain);
    let errors = vec![ValidationErrorDetail::new(
        vec![LocItem::field("body"), LocItem::field("email")],
        "value is not a valid email address",
        "value_error.email",
    )];

    let result = formatter.format_validation_errors(&errors);
    assert_snapshot!("validation_error_single", result.plain);
}

#[test]
fn snapshot_validation_error_multi() {
    eprintln!("[SNAPSHOT] Testing: Validation error (multiple)");
    let formatter = ErrorFormatter::new(OutputMode::Plain);
    let errors = vec![
        ValidationErrorDetail::new(
            vec![LocItem::field("body"), LocItem::field("email")],
            "value is not a valid email address",
            "value_error.email",
        ),
        ValidationErrorDetail::new(
            vec![LocItem::field("body"), LocItem::field("age")],
            "ensure this value is greater than 0",
            "value_error.number.not_gt",
        ),
        ValidationErrorDetail::new(
            vec![LocItem::field("body"), LocItem::field("name")],
            "field required",
            "value_error.missing",
        ),
    ];

    let result = formatter.format_validation_errors(&errors);
    assert_snapshot!("validation_error_multi", result.plain);
}

#[test]
fn snapshot_validation_error_nested() {
    eprintln!("[SNAPSHOT] Testing: Validation error (nested path)");
    let formatter = ErrorFormatter::new(OutputMode::Plain);
    let errors = vec![ValidationErrorDetail::new(
        vec![
            LocItem::field("body"),
            LocItem::field("items"),
            LocItem::index(0),
            LocItem::field("price"),
        ],
        "ensure this value is greater than 0",
        "value_error.number.not_gt",
    )];

    let result = formatter.format_validation_errors(&errors);
    assert_snapshot!("validation_error_nested", result.plain);
}

// =============================================================================
// HTTP Error Snapshots
// =============================================================================

#[test]
fn snapshot_http_error_404() {
    eprintln!("[SNAPSHOT] Testing: HTTP error (404)");
    let formatter = ErrorFormatter::new(OutputMode::Plain);
    let err = HttpErrorInfo::new(404, "User not found")
        .path("/api/users/999")
        .method("GET");

    let result = formatter.format_http_error(&err);
    assert_snapshot!("http_error_404", result.plain);
}

#[test]
fn snapshot_http_error_500() {
    eprintln!("[SNAPSHOT] Testing: HTTP error (500)");
    let formatter = ErrorFormatter::new(OutputMode::Plain);
    let err = HttpErrorInfo::new(500, "Database connection failed")
        .code("DB_ERROR")
        .path("/api/users")
        .method("POST");

    let result = formatter.format_http_error(&err);
    assert_snapshot!("http_error_500", result.plain);
}

#[test]
fn snapshot_http_error_401() {
    eprintln!("[SNAPSHOT] Testing: HTTP error (401)");
    let formatter = ErrorFormatter::new(OutputMode::Plain);
    let err = HttpErrorInfo::new(401, "Invalid or expired token")
        .path("/api/protected")
        .method("GET");

    let result = formatter.format_http_error(&err);
    assert_snapshot!("http_error_401", result.plain);
}

#[test]
fn snapshot_http_error_422() {
    eprintln!("[SNAPSHOT] Testing: HTTP error (422)");
    let formatter = ErrorFormatter::new(OutputMode::Plain);
    let err = HttpErrorInfo::new(422, "Validation failed")
        .code("VALIDATION_ERROR")
        .path("/api/users")
        .method("POST");

    let result = formatter.format_http_error(&err);
    assert_snapshot!("http_error_422", result.plain);
}

// =============================================================================
// Request Logger Snapshots
// =============================================================================

#[test]
fn snapshot_request_log_basic() {
    eprintln!("[SNAPSHOT] Testing: Request log (basic)");
    let logger = RequestLogger::new(OutputMode::Plain);
    let entry = LogEntry::new(HttpMethod::Get, "/api/users", 200);

    let output = logger.format(&entry);
    assert_snapshot!("request_log_basic", output);
}

#[test]
fn snapshot_request_log_full() {
    eprintln!("[SNAPSHOT] Testing: Request log (full details)");
    let logger = RequestLogger::new(OutputMode::Plain);
    let entry = LogEntry::new(HttpMethod::Post, "/api/users", 201)
        .query("validate=true")
        .timing(ResponseTiming::new(Duration::from_millis(45)))
        .client_ip("192.168.1.100")
        .request_id("req-abc-123-xyz");

    let output = logger.format(&entry);
    assert_snapshot!("request_log_full", output);
}

#[test]
fn snapshot_request_log_error() {
    eprintln!("[SNAPSHOT] Testing: Request log (error response)");
    let logger = RequestLogger::new(OutputMode::Plain);
    let entry = LogEntry::new(HttpMethod::Delete, "/api/users/42", 500)
        .timing(ResponseTiming::new(Duration::from_millis(150)))
        .request_id("req-error-001");

    let output = logger.format(&entry);
    assert_snapshot!("request_log_error", output);
}

// =============================================================================
// Middleware Stack Snapshots
// =============================================================================

#[test]
fn snapshot_middleware_stack() {
    eprintln!("[SNAPSHOT] Testing: Middleware stack");
    let middlewares = vec![
        MiddlewareInfo::new("CorsMiddleware", 1),
        MiddlewareInfo::new("AuthMiddleware", 2),
        MiddlewareInfo::new("RateLimitMiddleware", 3),
        MiddlewareInfo::new("LoggingMiddleware", 4),
    ];
    let display = MiddlewareStackDisplay::new(middlewares);

    let output = display.as_plain_text();
    assert_snapshot!("middleware_stack", output);
}

// =============================================================================
// Dependency Tree Snapshots
// =============================================================================

#[test]
fn snapshot_dependency_tree() {
    eprintln!("[SNAPSHOT] Testing: Dependency tree");
    let db_node = DependencyNode::new("DatabasePool")
        .scope("singleton");
    let cache_node = DependencyNode::new("RedisCache")
        .scope("singleton");
    let service_node = DependencyNode::new("UserService")
        .scope("request")
        .child(db_node)
        .child(cache_node);
    let root = DependencyNode::new("Handler")
        .scope("request")
        .child(service_node);

    let display = DependencyTreeDisplay::new(OutputMode::Plain, vec![root]);
    let output = display.render();
    assert_snapshot!("dependency_tree", output);
}

// =============================================================================
// Shutdown Progress Snapshots
// =============================================================================

#[test]
fn snapshot_shutdown_progress() {
    eprintln!("[SNAPSHOT] Testing: Shutdown progress");
    let progress = ShutdownProgress::new(ShutdownPhase::GracePeriod)
        .in_flight(5);
    let display = ShutdownProgressDisplay::new(OutputMode::Plain);

    let output = display.render(&progress);
    assert_snapshot!("shutdown_progress", output);
}

#[test]
fn snapshot_shutdown_complete() {
    eprintln!("[SNAPSHOT] Testing: Shutdown complete");
    let progress = ShutdownProgress::new(ShutdownPhase::Complete)
        .in_flight(0);
    let display = ShutdownProgressDisplay::new(OutputMode::Plain);

    let output = display.render(&progress);
    assert_snapshot!("shutdown_complete", output);
}

// =============================================================================
// Test Results Snapshots
// =============================================================================

#[test]
fn snapshot_test_results_passing() {
    eprintln!("[SNAPSHOT] Testing: Test results (all passing)");
    let report = TestReport::new(vec![])
        .module(
            TestModuleResult::new("api::users", vec![])
                .case(TestCaseResult::new("test_create_user", TestStatus::Pass))
                .case(TestCaseResult::new("test_get_user", TestStatus::Pass))
                .case(TestCaseResult::new("test_list_users", TestStatus::Pass)),
        );
    let display = TestReportDisplay::new(OutputMode::Plain);

    let output = display.render(&report);
    assert_snapshot!("test_results_passing", output);
}

#[test]
fn snapshot_test_results_mixed() {
    eprintln!("[SNAPSHOT] Testing: Test results (mixed)");
    let report = TestReport::new(vec![])
        .module(
            TestModuleResult::new("api::users", vec![])
                .case(TestCaseResult::new("test_create_user", TestStatus::Pass))
                .case(
                    TestCaseResult::new("test_validation", TestStatus::Fail)
                        .details("assertion failed: expected 200, got 422"),
                )
                .case(TestCaseResult::new("test_auth", TestStatus::Skip)),
        );
    let display = TestReportDisplay::new(OutputMode::Plain);

    let output = display.render(&report);
    assert_snapshot!("test_results_mixed", output);
}
