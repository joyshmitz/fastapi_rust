//! Authentication Example - Bearer Token Authentication with Protected Routes
//!
//! This example demonstrates authentication patterns in fastapi_rust:
//! - Bearer token authentication
//! - Protected routes that return 401 without valid token
//! - A simulated login endpoint
//! - Public and private endpoints
//! - Secure token comparison to prevent timing attacks
//!
//! # Running This Example
//!
//! ```bash
//! cargo run --example auth_example
//! ```
//!
//! # Expected Output
//!
//! ```text
//! fastapi_rust Authentication Example
//! ====================================
//!
//! 1. Public endpoint - no auth required
//!    GET /public -> 200 OK
//!
//! 2. Protected endpoint - without token
//!    GET /protected -> 401 Unauthorized
//!
//! 3. Login endpoint - get a token
//!    POST /login -> 200 OK
//!    Bearer value: demo-bearer-value
//!
//! 4. Protected endpoint - with valid token
//!    GET /protected (Authorization: Bearer demo-bearer-value) -> 200 OK
//!
//! 5. Protected endpoint - with invalid token
//!    GET /protected (Authorization: Bearer wrong_token) -> 403 Forbidden
//!
//! 6. Protected endpoint - with wrong auth scheme
//!    GET /protected (Authorization: Basic ...) -> 401 Unauthorized
//!
//! 7. Login with wrong Content-Type
//!    POST /login (Content-Type: text/plain) -> 415 Unsupported Media Type
//!
//! 8. Token case sensitivity (lowercase 'bearer')
//!    GET /protected (Authorization: bearer demo-bearer-value) -> 200 OK
//!
//! All authentication tests passed!
//! ```
//!
//! # Security Notes
//!
//! This example uses a hardcoded secret token for demonstration purposes.
//! In a production application:
//! - Use cryptographically secure random tokens (e.g., UUID v4 or JWT)
//! - Store tokens securely (hashed in database)
//! - Implement token expiration
//! - Use HTTPS to protect tokens in transit
//! - Consider using OAuth2 or JWT for more complex scenarios

use fastapi_rust::core::{
    App, Request, RequestContext, Response, ResponseBody, SecureCompare, StatusCode, TestClient,
};
use serde::Serialize;

/// The secret token used for authentication in this demo.
/// In production, this would be generated per-user and stored securely.
const DEMO_BEARER_VALUE: &str = "demo-bearer-value";

/// Login response body.
#[derive(Debug, Serialize)]
struct LoginResponse {
    access_token: String,
    token_type: &'static str,
}

/// User info returned from protected endpoints.
#[derive(Debug, Serialize)]
struct UserInfo {
    username: String,
    message: String,
}

/// Handler for public endpoint - accessible without authentication.
///
/// This endpoint demonstrates a route that anyone can access.
fn public_handler(_ctx: &RequestContext, _req: &mut Request) -> std::future::Ready<Response> {
    let body = serde_json::json!({
        "message": "This is a public endpoint - no authentication required!"
    });
    std::future::ready(
        Response::ok()
            .header("content-type", b"application/json".to_vec())
            .body(ResponseBody::Bytes(body.to_string().into_bytes())),
    )
}

/// Handler for the login endpoint.
///
/// In a real application, this would:
/// 1. Validate username/password against a database
/// 2. Generate a unique token (JWT or random)
/// 3. Store the token with associated user info
/// 4. Return the token to the client
///
/// For this demo, we accept any credentials and return a fixed token.
fn login_handler(_ctx: &RequestContext, req: &mut Request) -> std::future::Ready<Response> {
    // In a real app, we would parse the JSON body and validate credentials.
    // For this demo, we just check that it's a POST with some body.

    // Check Content-Type
    let is_json = req
        .headers()
        .get("content-type")
        .is_some_and(|ct| ct.starts_with(b"application/json"));

    if !is_json {
        let error = serde_json::json!({
            "detail": "Content-Type must be application/json"
        });
        return std::future::ready(
            Response::with_status(StatusCode::UNSUPPORTED_MEDIA_TYPE)
                .header("content-type", b"application/json".to_vec())
                .body(ResponseBody::Bytes(error.to_string().into_bytes())),
        );
    }

    // For demo purposes, we don't validate credentials - just return the token
    // In production, you would:
    // 1. Parse the request body as LoginRequest
    // 2. Verify username/password against your database
    // 3. Generate a unique, cryptographically secure token
    // 4. Store token -> user_id mapping (with expiration)

    let response = LoginResponse {
        access_token: DEMO_BEARER_VALUE.to_string(),
        token_type: "bearer",
    };

    std::future::ready(
        Response::ok()
            .header("content-type", b"application/json".to_vec())
            .body(ResponseBody::Bytes(json_bytes(&response))),
    )
}

/// Handler for protected endpoint - requires valid bearer token.
///
/// This handler manually extracts and validates the bearer token:
/// 1. Gets the Authorization header
/// 2. Verifies it uses the Bearer scheme
/// 3. Validates the token against our secret using constant-time comparison
///
/// Returns appropriate error responses for each failure mode.
fn protected_handler(_ctx: &RequestContext, req: &mut Request) -> std::future::Ready<Response> {
    // Step 1: Get the Authorization header
    let Some(auth_header) = req.headers().get("authorization") else {
        // Missing header -> 401 Unauthorized
        let body = serde_json::json!({
            "detail": "Not authenticated"
        });
        return std::future::ready(
            Response::with_status(StatusCode::UNAUTHORIZED)
                .header("www-authenticate", b"Bearer".to_vec())
                .header("content-type", b"application/json".to_vec())
                .body(ResponseBody::Bytes(body.to_string().into_bytes())),
        );
    };

    // Step 2: Parse the Authorization header
    let Ok(auth_str) = std::str::from_utf8(auth_header) else {
        // Invalid UTF-8 -> 401 Unauthorized
        let body = serde_json::json!({
            "detail": "Invalid authentication credentials"
        });
        return std::future::ready(
            Response::with_status(StatusCode::UNAUTHORIZED)
                .header("www-authenticate", b"Bearer".to_vec())
                .header("content-type", b"application/json".to_vec())
                .body(ResponseBody::Bytes(body.to_string().into_bytes())),
        );
    };

    // Step 3: Check for "Bearer " prefix (case-insensitive for the scheme)
    let Some(bearer_value) = auth_str
        .strip_prefix("Bearer ")
        .or_else(|| auth_str.strip_prefix("bearer "))
    else {
        // Wrong scheme -> 401 Unauthorized
        let body = serde_json::json!({
            "detail": "Invalid authentication credentials"
        });
        return std::future::ready(
            Response::with_status(StatusCode::UNAUTHORIZED)
                .header("www-authenticate", b"Bearer".to_vec())
                .header("content-type", b"application/json".to_vec())
                .body(ResponseBody::Bytes(body.to_string().into_bytes())),
        );
    };

    let bearer_value = bearer_value.trim();
    if bearer_value.is_empty() {
        // Empty token -> 401 Unauthorized
        let body = serde_json::json!({
            "detail": "Invalid authentication credentials"
        });
        return std::future::ready(
            Response::with_status(StatusCode::UNAUTHORIZED)
                .header("www-authenticate", b"Bearer".to_vec())
                .header("content-type", b"application/json".to_vec())
                .body(ResponseBody::Bytes(body.to_string().into_bytes())),
        );
    }

    // Step 4: Validate the bearer value using constant-time comparison
    if !bearer_value.secure_eq(DEMO_BEARER_VALUE) {
        // Invalid token -> 403 Forbidden
        let body = serde_json::json!({
            "detail": "Invalid token"
        });
        return std::future::ready(
            Response::with_status(StatusCode::FORBIDDEN)
                .header("content-type", b"application/json".to_vec())
                .body(ResponseBody::Bytes(body.to_string().into_bytes())),
        );
    }

    // Token is valid - return protected data
    let user_info = UserInfo {
        username: "demo_user".to_string(),
        message: "You have accessed a protected resource!".to_string(),
    };

    std::future::ready(
        Response::ok()
            .header("content-type", b"application/json".to_vec())
            .body(ResponseBody::Bytes(json_bytes(&user_info))),
    )
}

fn json_bytes<T: Serialize>(value: &T) -> Vec<u8> {
    match serde_json::to_string(value) {
        Ok(text) => text.into_bytes(),
        Err(err) => format!(r#"{{"detail":"json serialize error: {err}"}}"#).into_bytes(),
    }
}

fn check(condition: bool, message: &str) -> bool {
    if condition {
        true
    } else {
        eprintln!("Check failed: {message}");
        false
    }
}

#[allow(clippy::needless_pass_by_value)]
fn check_eq<T: PartialEq + std::fmt::Debug>(left: T, right: T, message: &str) -> bool {
    if left == right {
        true
    } else {
        eprintln!("Check failed: {message}. left={left:?} right={right:?}");
        false
    }
}

#[allow(clippy::too_many_lines)]
fn main() {
    println!("fastapi_rust Authentication Example");
    println!("====================================\n");

    // Build the application with public and protected routes
    let app = App::builder()
        // Public endpoints - accessible to everyone
        .get("/public", public_handler)
        // Login endpoint - returns a token
        .post("/login", login_handler)
        // Protected endpoint - requires valid bearer token
        .get("/protected", protected_handler)
        .build();

    println!("App created with {} route(s)\n", app.route_count());

    // Create a test client
    let client = TestClient::new(app);

    // =========================================================================
    // Test 1: Public endpoint - no auth required
    // =========================================================================
    println!("1. Public endpoint - no auth required");
    let response = client.get("/public").send();
    println!(
        "   GET /public -> {} {}",
        response.status().as_u16(),
        response.status().canonical_reason()
    );
    if !check_eq(
        response.status().as_u16(),
        200,
        "GET /public should return 200",
    ) {
        return;
    }
    if !check(
        response.text().contains("public endpoint"),
        "GET /public should include the public endpoint body",
    ) {
        return;
    }

    // =========================================================================
    // Test 2: Protected endpoint - without token (should get 401)
    // =========================================================================
    println!("\n2. Protected endpoint - without token");
    let response = client.get("/protected").send();
    println!(
        "   GET /protected -> {} {}",
        response.status().as_u16(),
        response.status().canonical_reason()
    );
    if !check_eq(
        response.status().as_u16(),
        401,
        "Protected endpoint should return 401 without token",
    ) {
        return;
    }

    // Check for WWW-Authenticate header
    let has_www_auth = response
        .headers()
        .iter()
        .any(|(name, value)| name == "www-authenticate" && value == b"Bearer");
    if !check(
        has_www_auth,
        "401 response should include WWW-Authenticate: Bearer header",
    ) {
        return;
    }

    // =========================================================================
    // Test 3: Login endpoint - get a token
    // =========================================================================
    println!("\n3. Login endpoint - get a token");
    let response = client
        .post("/login")
        .header("content-type", "application/json")
        .body(r#"{"username":"test","password":"test123"}"#)
        .send();
    println!(
        "   POST /login -> {} {}",
        response.status().as_u16(),
        response.status().canonical_reason()
    );
    if !check_eq(
        response.status().as_u16(),
        200,
        "POST /login should return 200",
    ) {
        return;
    }

    // Parse the response to get the token
    let body_text = response.text();
    let body: serde_json::Value = match serde_json::from_str(body_text) {
        Ok(body) => body,
        Err(err) => {
            eprintln!("Failed to parse login response JSON: {err}");
            return;
        }
    };
    let Some(bearer_value) = body.get("access_token").and_then(|value| value.as_str()) else {
        eprintln!("Login response missing access_token");
        return;
    };
    println!("   Bearer value: {bearer_value}");
    if !check_eq(
        bearer_value,
        DEMO_BEARER_VALUE,
        "Login should return the expected bearer value",
    ) {
        return;
    }

    // =========================================================================
    // Test 4: Protected endpoint - with valid token (should get 200)
    // =========================================================================
    println!("\n4. Protected endpoint - with valid token");
    let response = client
        .get("/protected")
        .header("authorization", format!("Bearer {DEMO_BEARER_VALUE}"))
        .send();
    println!(
        "   GET /protected (Authorization: Bearer {}) -> {} {}",
        DEMO_BEARER_VALUE,
        response.status().as_u16(),
        response.status().canonical_reason()
    );
    if !check_eq(
        response.status().as_u16(),
        200,
        "Protected endpoint should return 200 with valid token",
    ) {
        return;
    }
    if !check(
        response.text().contains("protected resource"),
        "Protected endpoint should include protected resource body",
    ) {
        return;
    }

    // =========================================================================
    // Test 5: Protected endpoint - with invalid token (should get 403)
    // =========================================================================
    println!("\n5. Protected endpoint - with invalid token");
    let response = client
        .get("/protected")
        .header("authorization", "Bearer wrong_token")
        .send();
    println!(
        "   GET /protected (Authorization: Bearer wrong_token) -> {} {}",
        response.status().as_u16(),
        response.status().canonical_reason()
    );
    if !check_eq(
        response.status().as_u16(),
        403,
        "Protected endpoint should return 403 with invalid token",
    ) {
        return;
    }

    // =========================================================================
    // Test 6: Protected endpoint - with wrong auth scheme (should get 401)
    // =========================================================================
    println!("\n6. Protected endpoint - with wrong auth scheme");
    let response = client
        .get("/protected")
        .header("authorization", "Basic dXNlcjpwYXNz")
        .send();
    println!(
        "   GET /protected (Authorization: Basic ...) -> {} {}",
        response.status().as_u16(),
        response.status().canonical_reason()
    );
    if !check_eq(
        response.status().as_u16(),
        401,
        "Protected endpoint should return 401 with wrong auth scheme",
    ) {
        return;
    }

    // =========================================================================
    // Test 7: Login with wrong Content-Type (should get 415)
    // =========================================================================
    println!("\n7. Login with wrong Content-Type");
    let response = client
        .post("/login")
        .header("content-type", "text/plain")
        .body("demo=true")
        .send();
    println!(
        "   POST /login (Content-Type: text/plain) -> {} {}",
        response.status().as_u16(),
        response.status().canonical_reason()
    );
    if !check_eq(
        response.status().as_u16(),
        415,
        "Login should return 415 with wrong Content-Type",
    ) {
        return;
    }

    // =========================================================================
    // Test 8: Token case sensitivity (lowercase 'bearer')
    // =========================================================================
    println!("\n8. Token case sensitivity (lowercase 'bearer')");
    let response = client
        .get("/protected")
        .header("authorization", format!("bearer {DEMO_BEARER_VALUE}"))
        .send();
    println!(
        "   GET /protected (Authorization: bearer {}) -> {} {}",
        DEMO_BEARER_VALUE,
        response.status().as_u16(),
        response.status().canonical_reason()
    );
    if !check_eq(
        response.status().as_u16(),
        200,
        "Bearer scheme should be case-insensitive (lowercase accepted)",
    ) {
        return;
    }

    println!("\nAll authentication tests passed!");
}
