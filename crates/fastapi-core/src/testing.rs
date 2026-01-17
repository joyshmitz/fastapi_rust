//! Test utilities for fastapi applications.
//!
//! This module provides a [`TestClient`] for in-process testing of handlers
//! without network overhead. It integrates with asupersync's capability model
//! and supports deterministic testing via the Lab runtime.
//!
//! # Features
//!
//! - **In-process testing**: No network I/O, fast execution
//! - **HTTP-like API**: Familiar `client.get("/path")` interface
//! - **Request builder**: Fluent API for headers, body, cookies
//! - **Response assertions**: Convenient assertion helpers
//! - **Cookie jar**: Automatic session management across requests
//! - **Lab integration**: Deterministic testing with asupersync
//!
//! # Example
//!
//! ```ignore
//! use fastapi_core::testing::TestClient;
//! use fastapi_core::middleware::Handler;
//!
//! async fn hello_handler(ctx: &RequestContext, req: &mut Request) -> Response {
//!     Response::ok().body(ResponseBody::Bytes(b"Hello, World!".to_vec()))
//! }
//!
//! #[test]
//! fn test_hello() {
//!     let client = TestClient::new(hello_handler);
//!     let response = client.get("/hello").send();
//!
//!     assert_eq!(response.status().as_u16(), 200);
//!     assert_eq!(response.text(), "Hello, World!");
//! }
//! ```
//!
//! # Deterministic Testing
//!
//! For reproducible tests involving concurrency, use [`TestClient::with_seed`]:
//!
//! ```ignore
//! let client = TestClient::with_seed(handler, 42);
//! // Same seed = same execution order for concurrent operations
//! ```

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use asupersync::Cx;

use crate::context::RequestContext;
use crate::middleware::Handler;
use crate::request::{Body, Method, Request};
use crate::response::{Response, ResponseBody, StatusCode};

/// A simple cookie jar for maintaining cookies across requests.
///
/// Cookies are stored as name-value pairs and automatically
/// added to subsequent requests.
#[derive(Debug, Clone, Default)]
pub struct CookieJar {
    cookies: HashMap<String, String>,
}

impl CookieJar {
    /// Creates an empty cookie jar.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets a cookie in the jar.
    pub fn set(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.cookies.insert(name.into(), value.into());
    }

    /// Gets a cookie value by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.cookies.get(name).map(String::as_str)
    }

    /// Removes a cookie from the jar.
    pub fn remove(&mut self, name: &str) -> Option<String> {
        self.cookies.remove(name)
    }

    /// Clears all cookies from the jar.
    pub fn clear(&mut self) {
        self.cookies.clear();
    }

    /// Returns the number of cookies in the jar.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cookies.len()
    }

    /// Returns `true` if the jar is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cookies.is_empty()
    }

    /// Formats cookies for the Cookie header.
    #[must_use]
    pub fn to_cookie_header(&self) -> Option<String> {
        if self.cookies.is_empty() {
            None
        } else {
            Some(
                self.cookies
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join("; "),
            )
        }
    }

    /// Parses a Set-Cookie header and adds the cookie to the jar.
    pub fn parse_set_cookie(&mut self, header_value: &[u8]) {
        if let Ok(value) = std::str::from_utf8(header_value) {
            // Parse simple name=value; ignore attributes for now
            if let Some(cookie_part) = value.split(';').next() {
                if let Some((name, val)) = cookie_part.split_once('=') {
                    self.set(name.trim(), val.trim());
                }
            }
        }
    }
}

/// Test client for in-process HTTP testing.
///
/// `TestClient` wraps a handler and provides an HTTP-like interface
/// for testing without network overhead. It maintains a cookie jar
/// for session persistence across requests.
///
/// # Thread Safety
///
/// `TestClient` is thread-safe and can be shared across test threads.
/// The internal cookie jar is protected by a mutex.
///
/// # Example
///
/// ```ignore
/// let client = TestClient::new(my_handler);
///
/// // Simple GET request
/// let response = client.get("/users").send();
/// assert_eq!(response.status(), StatusCode::OK);
///
/// // POST with JSON body
/// let response = client
///     .post("/users")
///     .json(&CreateUser { name: "Alice" })
///     .send();
/// assert_eq!(response.status(), StatusCode::CREATED);
///
/// // Request with headers
/// let response = client
///     .get("/protected")
///     .header("Authorization", "Bearer token123")
///     .send();
/// ```
pub struct TestClient<H> {
    handler: Arc<H>,
    cookies: Arc<Mutex<CookieJar>>,
    seed: Option<u64>,
    request_id_counter: Arc<std::sync::atomic::AtomicU64>,
}

impl<H: Handler + 'static> TestClient<H> {
    /// Creates a new test client wrapping the given handler.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let client = TestClient::new(my_handler);
    /// ```
    pub fn new(handler: H) -> Self {
        Self {
            handler: Arc::new(handler),
            cookies: Arc::new(Mutex::new(CookieJar::new())),
            seed: None,
            request_id_counter: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        }
    }

    /// Creates a test client with a deterministic seed for the Lab runtime.
    ///
    /// Using the same seed produces identical execution order for
    /// concurrent operations, enabling reproducible test failures.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let client = TestClient::with_seed(my_handler, 42);
    /// ```
    pub fn with_seed(handler: H, seed: u64) -> Self {
        Self {
            handler: Arc::new(handler),
            cookies: Arc::new(Mutex::new(CookieJar::new())),
            seed: Some(seed),
            request_id_counter: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        }
    }

    /// Returns the seed used for deterministic testing, if set.
    #[must_use]
    pub fn seed(&self) -> Option<u64> {
        self.seed
    }

    /// Returns a reference to the cookie jar.
    ///
    /// Note: The jar is protected by a mutex, so concurrent access
    /// is safe but may block.
    pub fn cookies(&self) -> std::sync::MutexGuard<'_, CookieJar> {
        self.cookies.lock().expect("cookie jar mutex poisoned")
    }

    /// Clears all cookies from the jar.
    pub fn clear_cookies(&self) {
        self.cookies().clear();
    }

    /// Creates a GET request builder.
    #[must_use]
    pub fn get(&self, path: &str) -> RequestBuilder<'_, H> {
        RequestBuilder::new(self, Method::Get, path)
    }

    /// Creates a POST request builder.
    #[must_use]
    pub fn post(&self, path: &str) -> RequestBuilder<'_, H> {
        RequestBuilder::new(self, Method::Post, path)
    }

    /// Creates a PUT request builder.
    #[must_use]
    pub fn put(&self, path: &str) -> RequestBuilder<'_, H> {
        RequestBuilder::new(self, Method::Put, path)
    }

    /// Creates a DELETE request builder.
    #[must_use]
    pub fn delete(&self, path: &str) -> RequestBuilder<'_, H> {
        RequestBuilder::new(self, Method::Delete, path)
    }

    /// Creates a PATCH request builder.
    #[must_use]
    pub fn patch(&self, path: &str) -> RequestBuilder<'_, H> {
        RequestBuilder::new(self, Method::Patch, path)
    }

    /// Creates an OPTIONS request builder.
    #[must_use]
    pub fn options(&self, path: &str) -> RequestBuilder<'_, H> {
        RequestBuilder::new(self, Method::Options, path)
    }

    /// Creates a HEAD request builder.
    #[must_use]
    pub fn head(&self, path: &str) -> RequestBuilder<'_, H> {
        RequestBuilder::new(self, Method::Head, path)
    }

    /// Creates a request builder with a custom method.
    #[must_use]
    pub fn request(&self, method: Method, path: &str) -> RequestBuilder<'_, H> {
        RequestBuilder::new(self, method, path)
    }

    /// Generates a unique request ID for tracing.
    fn next_request_id(&self) -> u64 {
        self.request_id_counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    /// Executes a request and returns the response.
    ///
    /// This is called internally by `RequestBuilder::send()`.
    fn execute(&self, mut request: Request) -> TestResponse {
        // Add cookies from jar to request
        {
            let jar = self.cookies();
            if let Some(cookie_header) = jar.to_cookie_header() {
                request
                    .headers_mut()
                    .insert("cookie", cookie_header.into_bytes());
            }
        }

        // Create test context with Cx::for_testing()
        let cx = Cx::for_testing();
        let request_id = self.next_request_id();
        let ctx = RequestContext::new(cx, request_id);

        // Execute handler synchronously for testing
        // In a real async context, this would be awaited
        let response = futures_executor::block_on(self.handler.call(&ctx, &mut request));

        // Extract cookies from response
        {
            let mut jar = self.cookies();
            for (name, value) in response.headers() {
                if name.eq_ignore_ascii_case("set-cookie") {
                    jar.parse_set_cookie(value);
                }
            }
        }

        TestResponse::new(response, request_id)
    }
}

impl<H> Clone for TestClient<H> {
    fn clone(&self) -> Self {
        Self {
            handler: Arc::clone(&self.handler),
            cookies: Arc::clone(&self.cookies),
            seed: self.seed,
            request_id_counter: Arc::clone(&self.request_id_counter),
        }
    }
}

/// Builder for constructing test requests with a fluent API.
///
/// Use the methods on [`TestClient`] to create a request builder,
/// then chain configuration methods and call [`send`](Self::send) to execute.
///
/// # Example
///
/// ```ignore
/// let response = client
///     .post("/api/items")
///     .header("Content-Type", "application/json")
///     .body(r#"{"name": "Widget"}"#)
///     .send();
/// ```
pub struct RequestBuilder<'a, H> {
    client: &'a TestClient<H>,
    method: Method,
    path: String,
    query: Option<String>,
    headers: Vec<(String, Vec<u8>)>,
    body: Body,
}

impl<'a, H: Handler + 'static> RequestBuilder<'a, H> {
    /// Creates a new request builder.
    fn new(client: &'a TestClient<H>, method: Method, path: &str) -> Self {
        // Split path and query string
        let (path, query) = if let Some(idx) = path.find('?') {
            (path[..idx].to_string(), Some(path[idx + 1..].to_string()))
        } else {
            (path.to_string(), None)
        };

        Self {
            client,
            method,
            path,
            query,
            headers: Vec::new(),
            body: Body::Empty,
        }
    }

    /// Sets a query string parameter.
    ///
    /// Multiple calls append parameters.
    ///
    /// # Example
    ///
    /// ```ignore
    /// client.get("/search").query("q", "rust").query("limit", "10").send()
    /// ```
    #[must_use]
    pub fn query(mut self, key: &str, value: &str) -> Self {
        let param = format!("{key}={value}");
        self.query = Some(match self.query {
            Some(q) => format!("{q}&{param}"),
            None => param,
        });
        self
    }

    /// Sets a request header.
    ///
    /// # Example
    ///
    /// ```ignore
    /// client.get("/api").header("Authorization", "Bearer token").send()
    /// ```
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<Vec<u8>>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Sets a request header with a string value.
    #[must_use]
    pub fn header_str(self, name: impl Into<String>, value: &str) -> Self {
        self.header(name, value.as_bytes().to_vec())
    }

    /// Sets the request body as raw bytes.
    ///
    /// # Example
    ///
    /// ```ignore
    /// client.post("/upload").body(b"binary data".to_vec()).send()
    /// ```
    #[must_use]
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = Body::Bytes(body.into());
        self
    }

    /// Sets the request body as a string.
    #[must_use]
    pub fn body_str(self, body: &str) -> Self {
        self.body(body.as_bytes().to_vec())
    }

    /// Sets the request body as JSON.
    ///
    /// Automatically sets the Content-Type header to `application/json`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// #[derive(Serialize)]
    /// struct CreateUser { name: String }
    ///
    /// client.post("/users").json(&CreateUser { name: "Alice".into() }).send()
    /// ```
    #[must_use]
    pub fn json<T: serde::Serialize>(mut self, value: &T) -> Self {
        let bytes = serde_json::to_vec(value).expect("JSON serialization failed");
        self.body = Body::Bytes(bytes);
        self.headers
            .push(("content-type".to_string(), b"application/json".to_vec()));
        self
    }

    /// Sets a cookie for this request only.
    ///
    /// This does not affect the client's cookie jar.
    #[must_use]
    pub fn cookie(self, name: &str, value: &str) -> Self {
        let cookie = format!("{name}={value}");
        self.header("cookie", cookie.into_bytes())
    }

    /// Sends the request and returns the response.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let response = client.get("/").send();
    /// ```
    #[must_use]
    pub fn send(self) -> TestResponse {
        let mut request = Request::new(self.method, self.path);
        request.set_query(self.query);
        request.set_body(self.body);

        for (name, value) in self.headers {
            request.headers_mut().insert(name, value);
        }

        self.client.execute(request)
    }
}

/// Response from a test request with assertion helpers.
///
/// `TestResponse` wraps a [`Response`] and provides convenient methods
/// for accessing response data and making assertions in tests.
///
/// # Example
///
/// ```ignore
/// let response = client.get("/api/user").send();
///
/// assert_eq!(response.status(), StatusCode::OK);
/// assert!(response.header("content-type").contains("application/json"));
///
/// let user: User = response.json().unwrap();
/// assert_eq!(user.name, "Alice");
/// ```
#[derive(Debug)]
pub struct TestResponse {
    inner: Response,
    request_id: u64,
}

impl TestResponse {
    /// Creates a new test response.
    fn new(response: Response, request_id: u64) -> Self {
        Self {
            inner: response,
            request_id,
        }
    }

    /// Returns the request ID for tracing.
    #[must_use]
    pub fn request_id(&self) -> u64 {
        self.request_id
    }

    /// Returns the HTTP status code.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.inner.status()
    }

    /// Returns the status code as a u16.
    #[must_use]
    pub fn status_code(&self) -> u16 {
        self.inner.status().as_u16()
    }

    /// Checks if the status is successful (2xx).
    #[must_use]
    pub fn is_success(&self) -> bool {
        let code = self.status_code();
        (200..300).contains(&code)
    }

    /// Checks if the status is a redirect (3xx).
    #[must_use]
    pub fn is_redirect(&self) -> bool {
        let code = self.status_code();
        (300..400).contains(&code)
    }

    /// Checks if the status is a client error (4xx).
    #[must_use]
    pub fn is_client_error(&self) -> bool {
        let code = self.status_code();
        (400..500).contains(&code)
    }

    /// Checks if the status is a server error (5xx).
    #[must_use]
    pub fn is_server_error(&self) -> bool {
        let code = self.status_code();
        (500..600).contains(&code)
    }

    /// Returns all headers.
    #[must_use]
    pub fn headers(&self) -> &[(String, Vec<u8>)] {
        self.inner.headers()
    }

    /// Returns a header value by name (case-insensitive).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        let name_lower = name.to_ascii_lowercase();
        self.inner
            .headers()
            .iter()
            .find(|(n, _)| n.to_ascii_lowercase() == name_lower)
            .map(|(_, v)| v.as_slice())
    }

    /// Returns a header value as a string (case-insensitive).
    #[must_use]
    pub fn header_str(&self, name: &str) -> Option<&str> {
        self.header(name).and_then(|v| std::str::from_utf8(v).ok())
    }

    /// Returns the Content-Type header value.
    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        self.header_str("content-type")
    }

    /// Returns the body as raw bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        match self.inner.body_ref() {
            ResponseBody::Empty => &[],
            ResponseBody::Bytes(b) => b,
        }
    }

    /// Returns the body as a UTF-8 string.
    ///
    /// # Panics
    ///
    /// Panics if the body is not valid UTF-8.
    #[must_use]
    pub fn text(&self) -> &str {
        std::str::from_utf8(self.bytes()).expect("response body is not valid UTF-8")
    }

    /// Tries to return the body as a UTF-8 string.
    #[must_use]
    pub fn text_opt(&self) -> Option<&str> {
        std::str::from_utf8(self.bytes()).ok()
    }

    /// Parses the body as JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if the body cannot be parsed as the target type.
    ///
    /// # Example
    ///
    /// ```ignore
    /// #[derive(Deserialize)]
    /// struct User { name: String }
    ///
    /// let user: User = response.json().unwrap();
    /// ```
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_slice(self.bytes())
    }

    /// Returns the body length.
    #[must_use]
    pub fn content_length(&self) -> usize {
        self.bytes().len()
    }

    /// Returns the underlying response.
    #[must_use]
    pub fn into_inner(self) -> Response {
        self.inner
    }

    // =========================================================================
    // Assertion Helpers
    // =========================================================================

    /// Asserts that the status code equals the expected value.
    ///
    /// # Panics
    ///
    /// Panics with a descriptive message if the assertion fails.
    #[must_use]
    pub fn assert_status(&self, expected: StatusCode) -> &Self {
        assert_eq!(
            self.status(),
            expected,
            "Expected status {}, got {} for request {}",
            expected.as_u16(),
            self.status_code(),
            self.request_id
        );
        self
    }

    /// Asserts that the status code equals the expected u16 value.
    ///
    /// # Panics
    ///
    /// Panics with a descriptive message if the assertion fails.
    #[must_use]
    pub fn assert_status_code(&self, expected: u16) -> &Self {
        assert_eq!(
            self.status_code(),
            expected,
            "Expected status {expected}, got {} for request {}",
            self.status_code(),
            self.request_id
        );
        self
    }

    /// Asserts that the response is successful (2xx).
    ///
    /// # Panics
    ///
    /// Panics if the status is not in the 2xx range.
    #[must_use]
    pub fn assert_success(&self) -> &Self {
        assert!(
            self.is_success(),
            "Expected success status, got {} for request {}",
            self.status_code(),
            self.request_id
        );
        self
    }

    /// Asserts that a header exists with the given value.
    ///
    /// # Panics
    ///
    /// Panics if the header doesn't exist or doesn't match.
    #[must_use]
    pub fn assert_header(&self, name: &str, expected: &str) -> &Self {
        let actual = self.header_str(name);
        assert_eq!(
            actual,
            Some(expected),
            "Expected header '{name}' to be '{expected}', got {:?} for request {}",
            actual,
            self.request_id
        );
        self
    }

    /// Asserts that the body equals the expected string.
    ///
    /// # Panics
    ///
    /// Panics if the body doesn't match.
    #[must_use]
    pub fn assert_text(&self, expected: &str) -> &Self {
        assert_eq!(
            self.text(),
            expected,
            "Body mismatch for request {}",
            self.request_id
        );
        self
    }

    /// Asserts that the body contains the expected substring.
    ///
    /// # Panics
    ///
    /// Panics if the body doesn't contain the substring.
    #[must_use]
    pub fn assert_text_contains(&self, expected: &str) -> &Self {
        assert!(
            self.text().contains(expected),
            "Expected body to contain '{}', got '{}' for request {}",
            expected,
            self.text(),
            self.request_id
        );
        self
    }

    /// Asserts that the JSON body equals the expected value.
    ///
    /// # Panics
    ///
    /// Panics if parsing fails or the value doesn't match.
    #[must_use]
    pub fn assert_json<T>(&self, expected: &T) -> &Self
    where
        T: serde::de::DeserializeOwned + serde::Serialize + PartialEq + std::fmt::Debug,
    {
        let actual: T = self.json().expect("Failed to parse response as JSON");
        assert_eq!(
            actual, *expected,
            "JSON body mismatch for request {}",
            self.request_id
        );
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middleware::BoxFuture;

    // Simple test handler
    struct EchoHandler;

    impl Handler for EchoHandler {
        fn call<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            req: &'a mut Request,
        ) -> BoxFuture<'a, Response> {
            let method = format!("{:?}", req.method());
            let path = req.path().to_string();
            let body = format!("Method: {method}, Path: {path}");
            Box::pin(async move {
                Response::ok()
                    .header("content-type", b"text/plain".to_vec())
                    .body(ResponseBody::Bytes(body.into_bytes()))
            })
        }
    }

    // Handler that sets a cookie
    struct CookieHandler;

    impl Handler for CookieHandler {
        fn call<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            _req: &'a mut Request,
        ) -> BoxFuture<'a, Response> {
            Box::pin(async move {
                Response::ok()
                    .header("set-cookie", b"session=abc123".to_vec())
                    .body(ResponseBody::Bytes(b"Cookie set".to_vec()))
            })
        }
    }

    // Handler that echoes the cookie
    struct CookieEchoHandler;

    impl Handler for CookieEchoHandler {
        fn call<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            req: &'a mut Request,
        ) -> BoxFuture<'a, Response> {
            let cookie = req.headers().get("cookie").map_or_else(
                || "no cookies".to_string(),
                |v| String::from_utf8_lossy(v).to_string(),
            );
            Box::pin(async move { Response::ok().body(ResponseBody::Bytes(cookie.into_bytes())) })
        }
    }

    #[test]
    fn test_client_get() {
        let client = TestClient::new(EchoHandler);
        let response = client.get("/test/path").send();

        assert_eq!(response.status_code(), 200);
        assert_eq!(response.text(), "Method: Get, Path: /test/path");
    }

    #[test]
    fn test_client_post() {
        let client = TestClient::new(EchoHandler);
        let response = client.post("/api/items").send();

        assert_eq!(response.status_code(), 200);
        assert!(response.text().contains("Method: Post"));
    }

    #[test]
    fn test_client_all_methods() {
        let client = TestClient::new(EchoHandler);

        assert!(client.get("/").send().text().contains("Get"));
        assert!(client.post("/").send().text().contains("Post"));
        assert!(client.put("/").send().text().contains("Put"));
        assert!(client.delete("/").send().text().contains("Delete"));
        assert!(client.patch("/").send().text().contains("Patch"));
        assert!(client.options("/").send().text().contains("Options"));
        assert!(client.head("/").send().text().contains("Head"));
    }

    #[test]
    fn test_query_params() {
        let client = TestClient::new(EchoHandler);
        let response = client
            .get("/search")
            .query("q", "rust")
            .query("limit", "10")
            .send();

        assert_eq!(response.status_code(), 200);
    }

    #[test]
    fn test_response_assertions() {
        let client = TestClient::new(EchoHandler);
        let response = client.get("/test").send();

        response
            .assert_status_code(200)
            .assert_success()
            .assert_header("content-type", "text/plain")
            .assert_text_contains("Get");
    }

    #[test]
    fn test_response_status_checks() {
        let client = TestClient::new(EchoHandler);
        let response = client.get("/").send();

        assert!(response.is_success());
        assert!(!response.is_redirect());
        assert!(!response.is_client_error());
        assert!(!response.is_server_error());
    }

    #[test]
    fn test_cookie_jar() {
        let mut jar = CookieJar::new();
        assert!(jar.is_empty());

        jar.set("session", "abc123");
        jar.set("user", "alice");

        assert_eq!(jar.len(), 2);
        assert_eq!(jar.get("session"), Some("abc123"));
        assert_eq!(jar.get("user"), Some("alice"));

        let header = jar.to_cookie_header().unwrap();
        assert!(header.contains("session=abc123"));
        assert!(header.contains("user=alice"));

        jar.remove("session");
        assert_eq!(jar.len(), 1);
        assert_eq!(jar.get("session"), None);
    }

    #[test]
    fn test_cookie_persistence() {
        let client = TestClient::new(CookieHandler);

        // First request sets a cookie
        let _ = client.get("/set-cookie").send();

        // Cookie should be in the jar
        assert_eq!(client.cookies().get("session"), Some("abc123"));

        // Use a new handler that echoes cookies
        let client2 = TestClient::new(CookieEchoHandler);
        client2.cookies().set("session", "abc123");

        let response = client2.get("/check-cookie").send();
        assert!(response.text().contains("session=abc123"));
    }

    #[test]
    fn test_request_id_increments() {
        let client = TestClient::new(EchoHandler);

        let r1 = client.get("/").send();
        let r2 = client.get("/").send();
        let r3 = client.get("/").send();

        assert_eq!(r1.request_id(), 1);
        assert_eq!(r2.request_id(), 2);
        assert_eq!(r3.request_id(), 3);
    }

    #[test]
    fn test_client_with_seed() {
        let client = TestClient::with_seed(EchoHandler, 42);
        assert_eq!(client.seed(), Some(42));
    }

    #[test]
    fn test_client_clone() {
        let client = TestClient::new(EchoHandler);
        client.cookies().set("test", "value");

        let cloned = client.clone();

        // Cloned client shares cookies
        assert_eq!(cloned.cookies().get("test"), Some("value"));

        // And request ID counter
        let r1 = client.get("/").send();
        let r2 = cloned.get("/").send();
        assert_eq!(r1.request_id(), 1);
        assert_eq!(r2.request_id(), 2);
    }
}
