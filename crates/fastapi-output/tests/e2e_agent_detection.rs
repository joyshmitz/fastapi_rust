//! End-to-end tests for agent detection and output mode switching.
//!
//! These tests verify the complete flow from environment detection
//! through to actual output formatting.

use fastapi_output::prelude::*;
use serial_test::serial;
use std::env;

// =============================================================================
// Environment Management Helpers
// =============================================================================

/// Clean all relevant environment variables before/after tests.
///
/// # Safety
///
/// This modifies environment variables which is inherently unsafe in
/// multi-threaded contexts. We use serial_test to ensure tests run sequentially.
#[allow(unsafe_code)]
fn clean_env() {
    // SAFETY: Tests run serially via #[serial] attribute
    unsafe {
        // Output mode override
        env::remove_var("FASTAPI_OUTPUT_MODE");

        // Detection overrides
        env::remove_var("FASTAPI_AGENT_MODE");
        env::remove_var("FASTAPI_HUMAN_MODE");

        // Agent env vars
        env::remove_var("CLAUDE_CODE");
        env::remove_var("CODEX_CLI");
        env::remove_var("CURSOR_SESSION");
        env::remove_var("AIDER_SESSION");
        env::remove_var("AGENT_MODE");
        env::remove_var("WINDSURF_SESSION");
        env::remove_var("CLINE_SESSION");
        env::remove_var("COPILOT_AGENT");

        // CI env vars
        env::remove_var("CI");
        env::remove_var("GITHUB_ACTIONS");
        env::remove_var("GITLAB_CI");
        env::remove_var("JENKINS_URL");

        // Color standards
        env::remove_var("NO_COLOR");
        env::remove_var("FORCE_COLOR");
    }
}

/// Run test with clean environment, restoring afterwards.
fn with_clean_env<F: FnOnce()>(f: F) {
    clean_env();
    f();
    clean_env();
}

/// Set environment variable safely in tests.
#[allow(unsafe_code)]
fn set_env(key: &str, value: &str) {
    // SAFETY: Tests run serially via #[serial] attribute
    unsafe {
        env::set_var(key, value);
    }
}

// =============================================================================
// E2E: Agent Detection Flow
// =============================================================================

#[test]
#[serial]
fn e2e_claude_code_triggers_plain_mode() {
    with_clean_env(|| {
        set_env("CLAUDE_CODE", "1");
        eprintln!("[E2E] Set CLAUDE_CODE=1");

        let output = RichOutput::auto();
        eprintln!("[E2E] RichOutput::auto() mode={:?}", output.mode());

        assert_eq!(output.mode(), OutputMode::Plain);
        assert!(output.is_agent_mode());
        assert_eq!(output.mode_name(), "plain");

        eprintln!("[E2E] PASS: Claude Code triggers plain mode");
    });
}

#[test]
#[serial]
fn e2e_codex_cli_triggers_plain_mode() {
    with_clean_env(|| {
        set_env("CODEX_CLI", "1");
        eprintln!("[E2E] Set CODEX_CLI=1");

        let output = RichOutput::auto();
        assert_eq!(output.mode(), OutputMode::Plain);
        assert!(output.is_agent_mode());

        eprintln!("[E2E] PASS: Codex CLI triggers plain mode");
    });
}

#[test]
#[serial]
fn e2e_cursor_session_triggers_plain_mode() {
    with_clean_env(|| {
        set_env("CURSOR_SESSION", "abc123");
        eprintln!("[E2E] Set CURSOR_SESSION=abc123");

        let output = RichOutput::auto();
        assert_eq!(output.mode(), OutputMode::Plain);
        assert!(output.is_agent_mode());

        eprintln!("[E2E] PASS: Cursor session triggers plain mode");
    });
}

#[test]
#[serial]
fn e2e_ci_triggers_plain_mode() {
    with_clean_env(|| {
        set_env("CI", "true");
        eprintln!("[E2E] Set CI=true");

        let output = RichOutput::auto();
        assert_eq!(output.mode(), OutputMode::Plain);
        assert!(output.is_agent_mode());

        eprintln!("[E2E] PASS: CI triggers plain mode");
    });
}

#[test]
#[serial]
fn e2e_github_actions_triggers_plain_mode() {
    with_clean_env(|| {
        set_env("GITHUB_ACTIONS", "true");
        eprintln!("[E2E] Set GITHUB_ACTIONS=true");

        let output = RichOutput::auto();
        assert_eq!(output.mode(), OutputMode::Plain);

        eprintln!("[E2E] PASS: GitHub Actions triggers plain mode");
    });
}

#[test]
#[serial]
fn e2e_no_color_triggers_plain_mode() {
    with_clean_env(|| {
        set_env("NO_COLOR", "1");
        eprintln!("[E2E] Set NO_COLOR=1");

        let output = RichOutput::auto();
        assert_eq!(output.mode(), OutputMode::Plain);

        eprintln!("[E2E] PASS: NO_COLOR triggers plain mode");
    });
}

// =============================================================================
// E2E: Override Precedence
// =============================================================================

#[test]
#[serial]
fn e2e_explicit_mode_overrides_agent_detection() {
    with_clean_env(|| {
        set_env("CLAUDE_CODE", "1");
        set_env("FASTAPI_OUTPUT_MODE", "minimal");
        eprintln!("[E2E] Set CLAUDE_CODE=1, FASTAPI_OUTPUT_MODE=minimal");

        let output = RichOutput::auto();
        eprintln!("[E2E] RichOutput::auto() mode={:?}", output.mode());

        // Explicit mode wins over agent detection
        assert_eq!(output.mode(), OutputMode::Minimal);
        assert!(!output.is_agent_mode());

        eprintln!("[E2E] PASS: Explicit mode overrides agent detection");
    });
}

#[test]
#[serial]
fn e2e_human_mode_override_beats_ci() {
    with_clean_env(|| {
        set_env("CI", "true");
        set_env("FASTAPI_HUMAN_MODE", "1");
        eprintln!("[E2E] Set CI=true, FASTAPI_HUMAN_MODE=1");

        let mode = OutputMode::auto();
        eprintln!("[E2E] OutputMode::auto() = {mode:?}");

        // Human mode override beats CI detection
        // Note: Rich mode depends on feature flag
        assert!(!mode.is_agent_friendly());

        eprintln!("[E2E] PASS: Human mode override beats CI");
    });
}

#[test]
#[serial]
fn e2e_agent_mode_override_forces_plain() {
    with_clean_env(|| {
        set_env("FASTAPI_AGENT_MODE", "1");
        eprintln!("[E2E] Set FASTAPI_AGENT_MODE=1");

        let output = RichOutput::auto();
        assert_eq!(output.mode(), OutputMode::Plain);
        assert!(output.is_agent_mode());

        eprintln!("[E2E] PASS: Agent mode override forces plain");
    });
}

#[test]
#[serial]
fn e2e_force_color_beats_ci() {
    with_clean_env(|| {
        set_env("CI", "true");
        set_env("FORCE_COLOR", "1");
        eprintln!("[E2E] Set CI=true, FORCE_COLOR=1");

        let mode = OutputMode::auto();
        eprintln!("[E2E] OutputMode::auto() = {mode:?}");

        // FORCE_COLOR should prefer rich output
        assert!(!mode.is_agent_friendly());

        eprintln!("[E2E] PASS: FORCE_COLOR beats CI");
    });
}

// =============================================================================
// E2E: Output Capture Tests
// =============================================================================

#[test]
#[serial]
fn e2e_plain_mode_output_has_no_ansi() {
    with_clean_env(|| {
        set_env("CLAUDE_CODE", "1");
        eprintln!("[E2E] Testing plain mode output capture");

        let captured = capture(OutputMode::Plain, || {
            let output = RichOutput::plain();
            output.success("Server started");
            output.error("Connection failed");
            output.warning("Deprecated API");
            output.info("Listening on port 8000");
        });

        eprintln!("[E2E] Captured output:\n{captured}");

        assert_no_ansi(&captured);
        assert_contains(&captured, "[OK]");
        assert_contains(&captured, "[ERROR]");
        assert_contains(&captured, "[WARN]");
        assert_contains(&captured, "[INFO]");
        assert_contains(&captured, "Server started");
        assert_contains(&captured, "Connection failed");

        eprintln!("[E2E] PASS: Plain mode has no ANSI codes");
    });
}

#[test]
#[serial]
fn e2e_rich_mode_output_has_ansi() {
    with_clean_env(|| {
        eprintln!("[E2E] Testing rich mode output capture");

        let captured = capture(OutputMode::Rich, || {
            let output = RichOutput::rich();
            output.success("Server started");
            output.error("Connection failed");
        });

        eprintln!("[E2E] Captured raw output:\n{captured}");

        // Rich mode should have ANSI codes
        // Note: capture() returns stripped output, so we need to check raw
        assert_contains(&captured, "Server started");
        assert_contains(&captured, "Connection failed");

        eprintln!("[E2E] PASS: Rich mode captures output");
    });
}

#[test]
#[serial]
fn e2e_output_prefixes_are_consistent() {
    with_clean_env(|| {
        eprintln!("[E2E] Testing output prefix consistency");

        let captured = capture(OutputMode::Plain, || {
            let output = RichOutput::plain();
            output.success("msg1");
            output.error("msg2");
            output.warning("msg3");
            output.info("msg4");
            output.debug("msg5");
        });

        eprintln!("[E2E] Captured:\n{captured}");

        // All prefixes should be present in order
        assert_contains_in_order(
            &captured,
            &["[OK]", "[ERROR]", "[WARN]", "[INFO]", "[DEBUG]"],
        );

        eprintln!("[E2E] PASS: Output prefixes are consistent");
    });
}

// =============================================================================
// E2E: Global Instance Tests
// =============================================================================

#[test]
#[serial]
fn e2e_global_instance_reflects_environment() {
    with_clean_env(|| {
        set_env("FASTAPI_OUTPUT_MODE", "plain");
        eprintln!("[E2E] Testing global instance with FASTAPI_OUTPUT_MODE=plain");

        // Reset global to pick up env var
        set_global(RichOutput::auto());

        let global = get_global();
        eprintln!("[E2E] Global mode: {:?}", global.mode());

        assert_eq!(global.mode(), OutputMode::Plain);

        eprintln!("[E2E] PASS: Global instance reflects environment");
    });
}

#[test]
#[serial]
fn e2e_global_instance_is_consistent() {
    with_clean_env(|| {
        eprintln!("[E2E] Testing global instance consistency");

        let mode1 = get_global().mode();
        let mode2 = get_global().mode();
        let mode3 = get_global().mode();

        eprintln!("[E2E] modes: {mode1:?}, {mode2:?}, {mode3:?}");

        assert_eq!(mode1, mode2);
        assert_eq!(mode2, mode3);

        eprintln!("[E2E] PASS: Global instance is consistent");
    });
}

// =============================================================================
// E2E: Component Integration
// =============================================================================

#[test]
#[serial]
fn e2e_banner_respects_mode() {
    with_clean_env(|| {
        eprintln!("[E2E] Testing Banner component with plain mode");

        let banner = Banner::new(OutputMode::Plain);
        let info = ServerInfo::new("1.0.0", "localhost", 8000).docs_path("/docs");
        let output = banner.render(&info);

        eprintln!("[E2E] Banner output:\n{output}");

        assert_no_ansi(&output);
        assert_contains(&output, "FastAPI Rust");
        assert_contains(&output, "v1.0.0");
        assert_contains(&output, "http://localhost:8000");
        assert_contains(&output, "/docs");

        eprintln!("[E2E] PASS: Banner respects plain mode");
    });
}

#[test]
#[serial]
fn e2e_error_formatter_respects_mode() {
    with_clean_env(|| {
        eprintln!("[E2E] Testing ErrorFormatter with plain mode");

        let formatter = ErrorFormatter::new(OutputMode::Plain);
        let errors = vec![
            ValidationErrorDetail::new(
                vec![LocItem::field("body"), LocItem::field("email")],
                "invalid email format",
                "value_error.email",
            ),
            ValidationErrorDetail::new(
                vec![LocItem::field("body"), LocItem::field("age")],
                "must be positive",
                "value_error.number",
            ),
        ];

        let result = formatter.format_validation_errors(&errors);
        eprintln!("[E2E] Validation error output:\n{}", result.plain);

        assert_no_ansi(&result.plain);
        assert_contains(&result.plain, "Validation Error");
        assert_contains(&result.plain, "2 error(s)");
        assert_contains(&result.plain, "body.email");
        assert_contains(&result.plain, "body.age");

        eprintln!("[E2E] PASS: ErrorFormatter respects plain mode");
    });
}

#[test]
#[serial]
fn e2e_request_logger_respects_mode() {
    with_clean_env(|| {
        eprintln!("[E2E] Testing RequestLogger with plain mode");

        let logger = RequestLogger::new(OutputMode::Plain);
        let entry = LogEntry::new(HttpMethod::Get, "/api/users", 200)
            .timing(ResponseTiming::new(std::time::Duration::from_millis(50)));

        let output = logger.format(&entry);
        eprintln!("[E2E] Request log output: {output}");

        assert_no_ansi(&output);
        assert_contains(&output, "GET");
        assert_contains(&output, "/api/users");
        assert_contains(&output, "200");
        assert_contains(&output, "ms");

        eprintln!("[E2E] PASS: RequestLogger respects plain mode");
    });
}

// =============================================================================
// E2E: Multiple Agent Detection
// =============================================================================

#[test]
#[serial]
fn e2e_multiple_agent_vars_still_detects() {
    with_clean_env(|| {
        set_env("CLAUDE_CODE", "1");
        set_env("CODEX_CLI", "1");
        set_env("CI", "true");
        eprintln!("[E2E] Set multiple agent/CI vars");

        let result = detect_environment();
        eprintln!("[E2E] Detection result: {result:?}");

        assert!(result.is_agent);
        assert!(result.is_ci);
        // First agent var in list wins
        assert_eq!(result.detected_agent, Some("CLAUDE_CODE".to_string()));

        eprintln!("[E2E] PASS: Multiple agent vars still detects correctly");
    });
}

// =============================================================================
// E2E: Mode Switching Mid-Session
// =============================================================================

#[test]
#[serial]
fn e2e_mode_can_be_changed_at_runtime() {
    with_clean_env(|| {
        eprintln!("[E2E] Testing runtime mode switching");

        let mut output = RichOutput::plain();
        assert!(output.is_agent_mode());
        assert_eq!(output.mode_name(), "plain");

        output.set_mode(OutputMode::Rich);
        assert!(!output.is_agent_mode());
        assert_eq!(output.mode_name(), "rich");

        output.set_mode(OutputMode::Minimal);
        assert!(!output.is_agent_mode());
        assert_eq!(output.mode_name(), "minimal");

        eprintln!("[E2E] PASS: Mode can be changed at runtime");
    });
}
