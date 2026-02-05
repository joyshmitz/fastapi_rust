//! Getting Started Example
//!
//! This example validates all code snippets from docs/getting-started.md work correctly.
//!
//! Run with: cargo run --example getting_started -p fastapi-rust

use fastapi_rust::core::{
    App, AppConfig, Request, RequestContext, RequestIdMiddleware, Response, ResponseBody,
    SecurityHeaders, TestClient,
};

/// Handler for GET /
fn hello(_ctx: &RequestContext, _req: &mut Request) -> std::future::Ready<Response> {
    std::future::ready(Response::ok().body(ResponseBody::Bytes(b"Hello, World!".to_vec())))
}

/// Handler for GET /health
fn health(_ctx: &RequestContext, _req: &mut Request) -> std::future::Ready<Response> {
    std::future::ready(
        Response::ok().body(ResponseBody::Bytes(b"{\"status\":\"healthy\"}".to_vec())),
    )
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

fn main() {
    println!("Getting Started Guide - Code Validation\n");

    // === Basic App Example ===
    println!("1. Basic app with two routes:");
    let app = App::builder()
        .get("/", hello)
        .get("/health", health)
        .build();

    println!("   Routes: {}", app.route_count());
    let client = TestClient::new(app);

    let response = client.get("/").send();
    println!(
        "   GET / -> {} ({})",
        response.status().as_u16(),
        response.text()
    );
    if !check_eq(response.status().as_u16(), 200, "GET / should return 200") {
        return;
    }
    if !check_eq(response.text(), "Hello, World!", "GET / should return body") {
        return;
    }

    let response = client.get("/health").send();
    println!(
        "   GET /health -> {} ({})",
        response.status().as_u16(),
        response.text()
    );
    if !check_eq(
        response.status().as_u16(),
        200,
        "GET /health should return 200",
    ) {
        return;
    }

    // === App with Middleware ===
    println!("\n2. App with middleware:");
    let app = App::builder()
        .middleware(RequestIdMiddleware::new())
        .middleware(SecurityHeaders::new())
        .get("/", hello)
        .build();

    let client = TestClient::new(app);
    let response = client.get("/").send();
    println!("   GET / -> {}", response.status().as_u16());
    if !check_eq(
        response.status().as_u16(),
        200,
        "GET / with middleware should return 200",
    ) {
        return;
    }

    // === App with Configuration ===
    println!("\n3. App with configuration:");
    let config = AppConfig::new()
        .name("My API")
        .version("1.0.0")
        .debug(true)
        .max_body_size(10 * 1024 * 1024)
        .request_timeout_ms(30_000);

    let app = App::builder().config(config).get("/", hello).build();

    println!("   App name: {}", app.config().name);
    println!("   Version: {}", app.config().version);
    if !check_eq(
        app.config().name.as_str(),
        "My API",
        "Config name should match",
    ) {
        return;
    }
    if !check_eq(
        app.config().version.as_str(),
        "1.0.0",
        "Config version should match",
    ) {
        return;
    }

    // === 404 for unknown routes ===
    println!("\n4. 404 for unknown routes:");
    let app = App::builder().get("/", hello).build();

    let client = TestClient::new(app);
    let response = client.get("/nonexistent").send();
    println!("   GET /nonexistent -> {}", response.status().as_u16());
    if !check_eq(
        response.status().as_u16(),
        404,
        "Unknown routes should return 404",
    ) {
        return;
    }

    println!("\nAll getting started examples validated successfully!");
}
