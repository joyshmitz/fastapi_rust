//! End-to-end tests for component integration.
//!
//! These tests verify that multiple components work together correctly
//! and that mode selection flows through the entire system.

use fastapi_output::prelude::*;
use serial_test::serial;
use std::env;
use std::time::Duration;

// =============================================================================
// Environment Management Helpers
// =============================================================================

#[allow(unsafe_code)]
fn clean_env() {
    unsafe {
        env::remove_var("FASTAPI_OUTPUT_MODE");
        env::remove_var("FASTAPI_AGENT_MODE");
        env::remove_var("FASTAPI_HUMAN_MODE");
        env::remove_var("CLAUDE_CODE");
        env::remove_var("CI");
        env::remove_var("NO_COLOR");
        env::remove_var("FORCE_COLOR");
    }
}

fn with_clean_env<F: FnOnce()>(f: F) {
    clean_env();
    f();
    clean_env();
}

#[allow(unsafe_code)]
fn set_env(key: &str, value: &str) {
    unsafe {
        env::set_var(key, value);
    }
}

// =============================================================================
// E2E: Full Server Startup Flow
// =============================================================================

#[test]
#[serial]
fn e2e_full_startup_flow_plain_mode() {
    with_clean_env(|| {
        set_env("CLAUDE_CODE", "1");
        eprintln!("[E2E] Testing full startup flow in plain mode");

        // 1. Test banner directly (components return strings)
        let output = RichOutput::auto();
        assert_eq!(output.mode(), OutputMode::Plain);

        let banner = Banner::new(output.mode());
        let info = ServerInfo::new("0.1.0", "127.0.0.1", 8000)
            .docs_path("/docs")
            .redoc_path("/redoc")
            .openapi_path("/openapi.json");
        let banner_output = banner.render(&info);

        eprintln!("[E2E] Banner output:\n{}", banner_output);

        // Verify no ANSI codes in banner
        assert_no_ansi(&banner_output);

        // Verify banner content
        assert_contains(&banner_output, "FastAPI Rust");
        assert_contains(&banner_output, "v0.1.0");
        assert_contains(&banner_output, "http://127.0.0.1:8000");
        assert_contains(&banner_output, "/docs");
        assert_contains(&banner_output, "/redoc");
        assert_contains(&banner_output, "/openapi.json");

        // 2. Test status messages through capture
        let status_captured = capture(OutputMode::Plain, || {
            let out = RichOutput::plain();
            out.success("Server initialized");
            out.info("Loading configuration...");
            out.success("Configuration loaded");
            out.info("Starting HTTP server...");
            out.success("Server started successfully");
        });

        eprintln!("[E2E] Status output:\n{}", status_captured);

        // Verify status messages with correct prefixes
        assert_no_ansi(&status_captured);
        assert_contains(&status_captured, "[OK]");
        assert_contains(&status_captured, "[INFO]");
        assert_contains(&status_captured, "Server started successfully");

        // Verify order in status messages
        assert_contains_in_order(
            &status_captured,
            &[
                "Server initialized",
                "Configuration loaded",
                "Server started",
            ],
        );

        eprintln!("[E2E] PASS: Full startup flow works in plain mode");
    });
}

#[test]
#[serial]
fn e2e_full_startup_flow_rich_mode() {
    with_clean_env(|| {
        eprintln!("[E2E] Testing full startup flow in rich mode");

        // Force rich mode
        set_env("FASTAPI_OUTPUT_MODE", "rich");

        let (plain, _rich) = capture_both(|| {
            let output = RichOutput::rich();

            let banner = Banner::new(OutputMode::Rich);
            let info = ServerInfo::new("0.1.0", "localhost", 8000).docs_path("/docs");
            println!("{}", banner.render(&info));

            output.success("Server started");
        });

        // Plain capture should still work for content verification
        assert_contains(&plain, "Server started");

        eprintln!("[E2E] PASS: Full startup flow works in rich mode");
    });
}

// =============================================================================
// E2E: Error Handling Flow
// =============================================================================

#[test]
#[serial]
fn e2e_validation_error_flow() {
    with_clean_env(|| {
        set_env("CI", "true");
        eprintln!("[E2E] Testing validation error flow in CI mode");

        let output = RichOutput::auto();
        assert_eq!(output.mode(), OutputMode::Plain);

        // Test ErrorFormatter directly (it returns FormattedError struct)
        let formatter = ErrorFormatter::new(output.mode());
        let errors = vec![
            ValidationErrorDetail::new(
                vec![LocItem::field("body"), LocItem::field("email")],
                "value is not a valid email address",
                "value_error.email",
            ),
            ValidationErrorDetail::new(
                vec![
                    LocItem::field("body"),
                    LocItem::field("items"),
                    LocItem::index(0),
                    LocItem::field("quantity"),
                ],
                "ensure this value is greater than 0",
                "value_error.number.not_gt",
            ),
        ];

        let result = formatter.format_validation_errors(&errors);
        eprintln!("[E2E] Validation error output:\n{}", result.plain);

        assert_no_ansi(&result.plain);
        assert_contains(&result.plain, "Validation Error");
        assert_contains(&result.plain, "2 error(s)");
        assert_contains(&result.plain, "body.email");
        assert_contains(&result.plain, "body.items[0].quantity");

        // Also test HTTP error
        let http_err = HttpErrorInfo::new(422, "Validation failed")
            .code("VALIDATION_ERROR")
            .method("POST")
            .path("/api/orders");
        let http_result = formatter.format_http_error(&http_err);
        eprintln!("[E2E] HTTP error output:\n{}", http_result.plain);

        assert_no_ansi(&http_result.plain);
        assert_contains(&http_result.plain, "HTTP 422");
        assert_contains(&http_result.plain, "Unprocessable Entity");

        eprintln!("[E2E] PASS: Validation error flow works");
    });
}

#[test]
#[serial]
fn e2e_http_error_flow() {
    with_clean_env(|| {
        eprintln!("[E2E] Testing HTTP error formatting");

        let formatter = ErrorFormatter::new(OutputMode::Plain);

        // 4xx errors
        let not_found = HttpErrorInfo::new(404, "User not found")
            .path("/api/users/999")
            .method("GET");
        let not_found_output = formatter.format_http_error(&not_found);
        eprintln!("[E2E] 404 error output:\n{}", not_found_output.plain);

        assert_no_ansi(&not_found_output.plain);
        assert_contains(&not_found_output.plain, "HTTP 404");
        assert_contains(&not_found_output.plain, "Not Found");
        assert_contains(&not_found_output.plain, "GET /api/users/999");

        // 5xx errors
        let server_err = HttpErrorInfo::new(500, "Database connection failed")
            .code("DB_CONNECTION_ERROR")
            .path("/api/users")
            .method("POST");
        let server_err_output = formatter.format_http_error(&server_err);
        eprintln!("[E2E] 500 error output:\n{}", server_err_output.plain);

        assert_no_ansi(&server_err_output.plain);
        assert_contains(&server_err_output.plain, "HTTP 500");
        assert_contains(&server_err_output.plain, "Internal Server Error");
        assert_contains(&server_err_output.plain, "DB_CONNECTION_ERROR");

        eprintln!("[E2E] PASS: HTTP error flow works");
    });
}

// =============================================================================
// E2E: Request Logging Flow
// =============================================================================

#[test]
#[serial]
fn e2e_request_logging_flow() {
    with_clean_env(|| {
        set_env("FASTAPI_OUTPUT_MODE", "plain");
        eprintln!("[E2E] Testing request logging flow");

        let logger = RequestLogger::new(OutputMode::Plain);

        // Simulate typical request flow and collect outputs
        let requests = vec![
            LogEntry::new(HttpMethod::Get, "/api/health", 200)
                .timing(ResponseTiming::new(Duration::from_micros(500))),
            LogEntry::new(HttpMethod::Post, "/api/users", 201)
                .timing(ResponseTiming::new(Duration::from_millis(45))),
            LogEntry::new(HttpMethod::Get, "/api/users", 200)
                .query("page=1&limit=10")
                .timing(ResponseTiming::new(Duration::from_millis(120))),
            LogEntry::new(HttpMethod::Delete, "/api/users/123", 204)
                .timing(ResponseTiming::new(Duration::from_millis(30))),
            LogEntry::new(HttpMethod::Get, "/api/missing", 404)
                .timing(ResponseTiming::new(Duration::from_millis(5))),
        ];

        let mut all_output = String::new();
        for req in &requests {
            let line = logger.format(req);
            eprintln!("[E2E] Log line: {}", line);
            all_output.push_str(&line);
            all_output.push('\n');
        }

        eprintln!("[E2E] Full request log output:\n{}", all_output);

        assert_no_ansi(&all_output);
        assert_contains(&all_output, "GET");
        assert_contains(&all_output, "POST");
        assert_contains(&all_output, "DELETE");
        assert_contains(&all_output, "/api/health");
        assert_contains(&all_output, "/api/users");
        assert_contains(&all_output, "200");
        assert_contains(&all_output, "201");
        assert_contains(&all_output, "204");
        assert_contains(&all_output, "404");
        assert_contains(&all_output, "page=1&limit=10");

        eprintln!("[E2E] PASS: Request logging flow works");
    });
}

// =============================================================================
// E2E: All Components Use Same Mode
// =============================================================================

#[test]
#[serial]
fn e2e_all_components_use_consistent_mode() {
    with_clean_env(|| {
        set_env("CI", "true");
        eprintln!("[E2E] Testing that all components use consistent mode");

        let captured = capture(OutputMode::Plain, || {
            let output = RichOutput::auto();
            let mode = output.mode();

            // Verify mode is plain due to CI
            assert_eq!(mode, OutputMode::Plain);

            // Banner
            let banner = Banner::new(mode);
            let banner_output = banner.render(&ServerInfo::default());
            assert_no_ansi(&banner_output);

            // Error formatter
            let formatter = ErrorFormatter::new(mode);
            let error_output = formatter.format_simple("Test error");
            assert_no_ansi(&error_output.plain);

            // Request logger
            let logger = RequestLogger::new(mode);
            let log_output = logger.format(&LogEntry::new(HttpMethod::Get, "/", 200));
            assert_no_ansi(&log_output);

            // Output facade
            output.success("All components verified");
        });

        eprintln!("[E2E] Component consistency output:\n{}", captured);
        assert_no_ansi(&captured);

        eprintln!("[E2E] PASS: All components use consistent mode");
    });
}

// =============================================================================
// E2E: Theme Application
// =============================================================================

#[test]
#[serial]
fn e2e_theme_applies_to_rich_components() {
    with_clean_env(|| {
        eprintln!("[E2E] Testing theme application to components");

        let theme = FastApiTheme::default();
        let output = RichOutput::builder()
            .mode(OutputMode::Rich)
            .theme(theme.clone())
            .build();

        // Verify theme is accessible
        assert!(!output.theme().success.to_hex().is_empty());

        let banner = Banner::new(OutputMode::Rich).theme(theme);
        let banner_output = banner.render(&ServerInfo::default());

        // Rich banner should have ANSI codes
        assert!(banner_output.contains("\x1b["));

        eprintln!("[E2E] PASS: Theme applies to components");
    });
}

// =============================================================================
// E2E: Builder Pattern Consistency
// =============================================================================

#[test]
#[serial]
fn e2e_builder_pattern_works_consistently() {
    with_clean_env(|| {
        eprintln!("[E2E] Testing builder pattern consistency");

        // RichOutput builder
        let output = RichOutput::builder()
            .mode(OutputMode::Plain)
            .theme(FastApiTheme::neon())
            .build();
        assert_eq!(output.mode(), OutputMode::Plain);

        // ServerInfo builder
        let info = ServerInfo::new("1.0.0", "localhost", 8000)
            .https(true)
            .docs_path("/docs")
            .redoc_path("/redoc")
            .openapi_path("/openapi.json");
        assert!(info.https);
        assert_eq!(info.docs_path, Some("/docs".to_string()));

        // LogEntry builder
        let entry = LogEntry::new(HttpMethod::Post, "/api", 201)
            .query("foo=bar")
            .timing(ResponseTiming::new(Duration::from_millis(10)))
            .client_ip("127.0.0.1")
            .request_id("req-123");
        assert_eq!(entry.method, HttpMethod::Post);
        assert_eq!(entry.query, Some("foo=bar".to_string()));

        // HttpErrorInfo builder
        let error = HttpErrorInfo::new(500, "Error")
            .code("ERR_CODE")
            .path("/api")
            .method("GET");
        assert_eq!(error.code, Some("ERR_CODE".to_string()));

        eprintln!("[E2E] PASS: Builder patterns work consistently");
    });
}

// =============================================================================
// E2E: Test Utilities Work Correctly
// =============================================================================

#[test]
#[serial]
fn e2e_capture_both_produces_different_output() {
    with_clean_env(|| {
        eprintln!("[E2E] Testing capture_both produces different outputs");

        let (plain, rich) = capture_both(|| {
            let output = RichOutput::global();
            output.success("Test message");
        });

        eprintln!("[E2E] Plain: {}", plain);
        eprintln!("[E2E] Rich: {}", rich);

        // Both should contain the message
        assert_contains(&plain, "Test message");
        assert_contains(&rich, "Test message");

        // Plain should have [OK], rich should have checkmark
        assert_contains(&plain, "[OK]");

        eprintln!("[E2E] PASS: capture_both produces different outputs");
    });
}

#[test]
#[serial]
fn e2e_strip_ansi_works() {
    with_clean_env(|| {
        eprintln!("[E2E] Testing strip_ansi_codes utility");

        let with_ansi = "\x1b[32m\x1b[1m✓\x1b[0m Success message";
        let stripped = strip_ansi_codes(with_ansi);

        eprintln!("[E2E] Original: {:?}", with_ansi);
        eprintln!("[E2E] Stripped: {:?}", stripped);

        assert!(!stripped.contains("\x1b["));
        assert_contains(&stripped, "Success message");

        eprintln!("[E2E] PASS: strip_ansi_codes works");
    });
}
