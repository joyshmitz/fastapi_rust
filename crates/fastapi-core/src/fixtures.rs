//! Test fixtures and factory helpers for reducing test boilerplate.
//!
//! This module provides factory patterns for creating common test data
//! with minimal setup code. All factories use the builder pattern for
//! customization.
//!
//! # Factory Types
//!
//! - [`RequestFactory`]: Create test HTTP requests
//! - [`ResponseFactory`]: Create test HTTP responses
//! - [`AuthFactory`]: Create authentication tokens and credentials
//! - [`JsonFactory`]: Create JSON test payloads
//! - [`UserFactory`]: Create user test data
//!
//! # Example
//!
//! ```ignore
//! use fastapi_core::fixtures::*;
//!
//! // Create a GET request quickly
//! let req = RequestFactory::get("/users").build();
//!
//! // Create an authenticated POST request
//! let req = RequestFactory::post("/items")
//!     .json(&item)
//!     .bearer_token("abc123")
//!     .build();
//!
//! // Create test users
//! let user = UserFactory::new().email("test@example.com").build();
//!
//! // Create valid/invalid JSON
//! let valid = JsonFactory::valid_object().build();
//! let invalid = JsonFactory::malformed().build();
//! ```

use std::collections::HashMap;

use crate::request::{Body, HttpVersion, Method, Request};
use crate::response::{Response, ResponseBody, StatusCode};

// =============================================================================
// Request Factory
// =============================================================================

/// Factory for creating test HTTP requests with minimal boilerplate.
///
/// # Example
///
/// ```ignore
/// use fastapi_core::fixtures::RequestFactory;
///
/// // Simple GET
/// let req = RequestFactory::get("/users").build();
///
/// // POST with JSON body and auth
/// let req = RequestFactory::post("/items")
///     .json(&Item { name: "Widget" })
///     .bearer_token("token123")
///     .header("X-Request-Id", "abc")
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct RequestFactory {
    method: Method,
    path: String,
    query: Option<String>,
    version: HttpVersion,
    headers: Vec<(String, Vec<u8>)>,
    body: Option<Vec<u8>>,
}

impl RequestFactory {
    /// Create a new request factory with the given method and path.
    #[must_use]
    pub fn new(method: Method, path: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            query: None,
            version: HttpVersion::Http11,
            headers: Vec::new(),
            body: None,
        }
    }

    /// Create a GET request factory.
    #[must_use]
    pub fn get(path: impl Into<String>) -> Self {
        Self::new(Method::Get, path)
    }

    /// Create a POST request factory.
    #[must_use]
    pub fn post(path: impl Into<String>) -> Self {
        Self::new(Method::Post, path)
    }

    /// Create a PUT request factory.
    #[must_use]
    pub fn put(path: impl Into<String>) -> Self {
        Self::new(Method::Put, path)
    }

    /// Create a DELETE request factory.
    #[must_use]
    pub fn delete(path: impl Into<String>) -> Self {
        Self::new(Method::Delete, path)
    }

    /// Create a PATCH request factory.
    #[must_use]
    pub fn patch(path: impl Into<String>) -> Self {
        Self::new(Method::Patch, path)
    }

    /// Create an OPTIONS request factory.
    #[must_use]
    pub fn options(path: impl Into<String>) -> Self {
        Self::new(Method::Options, path)
    }

    /// Create a HEAD request factory.
    #[must_use]
    pub fn head(path: impl Into<String>) -> Self {
        Self::new(Method::Head, path)
    }

    /// Set the query string.
    #[must_use]
    pub fn query(mut self, query: impl Into<String>) -> Self {
        self.query = Some(query.into());
        self
    }

    /// Add query parameters from an iterator.
    #[must_use]
    pub fn query_params<I, K, V>(mut self, params: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let query: String = params
            .into_iter()
            .map(|(k, v)| format!("{}={}", k.as_ref(), v.as_ref()))
            .collect::<Vec<_>>()
            .join("&");
        self.query = Some(query);
        self
    }

    /// Set the HTTP version.
    #[must_use]
    pub fn version(mut self, version: HttpVersion) -> Self {
        self.version = version;
        self
    }

    /// Add a header.
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<Vec<u8>>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Set the Content-Type header.
    #[must_use]
    pub fn content_type(self, content_type: impl AsRef<str>) -> Self {
        self.header("Content-Type", content_type.as_ref().as_bytes().to_vec())
    }

    /// Set the Accept header.
    #[must_use]
    pub fn accept(self, accept: impl AsRef<str>) -> Self {
        self.header("Accept", accept.as_ref().as_bytes().to_vec())
    }

    /// Set a Bearer token for Authorization.
    #[must_use]
    pub fn bearer_token(self, token: impl AsRef<str>) -> Self {
        self.header(
            "Authorization",
            format!("Bearer {}", token.as_ref()).into_bytes(),
        )
    }

    /// Set Basic auth credentials.
    #[must_use]
    pub fn basic_auth(self, username: impl AsRef<str>, password: impl AsRef<str>) -> Self {
        use std::io::Write;
        let mut encoded = Vec::new();
        let _ = write!(
            &mut encoded,
            "Basic {}",
            base64_encode(&format!("{}:{}", username.as_ref(), password.as_ref()))
        );
        self.header("Authorization", encoded)
    }

    /// Set an API key header.
    #[must_use]
    pub fn api_key(self, key: impl AsRef<str>) -> Self {
        self.header("X-API-Key", key.as_ref().as_bytes().to_vec())
    }

    /// Set the raw body bytes.
    #[must_use]
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Set a JSON body (serializes the value).
    #[must_use]
    pub fn json<T: serde::Serialize>(self, value: &T) -> Self {
        let json = serde_json::to_vec(value).unwrap_or_default();
        self.content_type("application/json").body(json)
    }

    /// Set a form-encoded body.
    #[must_use]
    pub fn form<I, K, V>(self, fields: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let body: String = fields
            .into_iter()
            .map(|(k, v)| {
                format!(
                    "{}={}",
                    urlencoding_simple(k.as_ref()),
                    urlencoding_simple(v.as_ref())
                )
            })
            .collect::<Vec<_>>()
            .join("&");
        self.content_type("application/x-www-form-urlencoded")
            .body(body.into_bytes())
    }

    /// Set a plain text body.
    #[must_use]
    pub fn text(self, text: impl AsRef<str>) -> Self {
        self.content_type("text/plain")
            .body(text.as_ref().as_bytes().to_vec())
    }

    /// Build the request.
    #[must_use]
    pub fn build(self) -> Request {
        let mut req = Request::with_version(self.method, self.path, self.version);
        req.set_query(self.query);

        for (name, value) in self.headers {
            req.headers_mut().insert(name, value);
        }

        if let Some(body) = self.body {
            if !body.is_empty() {
                req.headers_mut()
                    .insert("Content-Length", body.len().to_string().into_bytes());
            }
            req.set_body(Body::Bytes(body));
        }

        req
    }
}

// =============================================================================
// Response Factory
// =============================================================================

/// Factory for creating test HTTP responses.
///
/// # Example
///
/// ```ignore
/// use fastapi_core::fixtures::ResponseFactory;
///
/// // Simple 200 OK
/// let resp = ResponseFactory::ok().build();
///
/// // JSON response
/// let resp = ResponseFactory::ok()
///     .json(&user)
///     .build();
///
/// // Error response
/// let resp = ResponseFactory::not_found()
///     .json(&ErrorBody { message: "User not found" })
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct ResponseFactory {
    status: StatusCode,
    headers: Vec<(String, Vec<u8>)>,
    body: Option<Vec<u8>>,
}

impl ResponseFactory {
    /// Create a new response factory with the given status code.
    #[must_use]
    pub fn new(status: StatusCode) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: None,
        }
    }

    /// Create a 200 OK response factory.
    #[must_use]
    pub fn ok() -> Self {
        Self::new(StatusCode::OK)
    }

    /// Create a 201 Created response factory.
    #[must_use]
    pub fn created() -> Self {
        Self::new(StatusCode::CREATED)
    }

    /// Create a 204 No Content response factory.
    #[must_use]
    pub fn no_content() -> Self {
        Self::new(StatusCode::NO_CONTENT)
    }

    /// Create a 301 Moved Permanently response factory.
    #[must_use]
    pub fn moved_permanently(location: impl AsRef<str>) -> Self {
        Self::new(StatusCode::MOVED_PERMANENTLY)
            .header("Location", location.as_ref().as_bytes().to_vec())
    }

    /// Create a 302 Found response factory.
    #[must_use]
    pub fn found(location: impl AsRef<str>) -> Self {
        Self::new(StatusCode::FOUND).header("Location", location.as_ref().as_bytes().to_vec())
    }

    /// Create a 400 Bad Request response factory.
    #[must_use]
    pub fn bad_request() -> Self {
        Self::new(StatusCode::BAD_REQUEST)
    }

    /// Create a 401 Unauthorized response factory.
    #[must_use]
    pub fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED)
    }

    /// Create a 403 Forbidden response factory.
    #[must_use]
    pub fn forbidden() -> Self {
        Self::new(StatusCode::FORBIDDEN)
    }

    /// Create a 404 Not Found response factory.
    #[must_use]
    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND)
    }

    /// Create a 422 Unprocessable Entity response factory.
    #[must_use]
    pub fn unprocessable_entity() -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY)
    }

    /// Create a 500 Internal Server Error response factory.
    #[must_use]
    pub fn internal_server_error() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR)
    }

    /// Set the status code.
    #[must_use]
    pub fn status(mut self, status: StatusCode) -> Self {
        self.status = status;
        self
    }

    /// Add a header.
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<Vec<u8>>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Set the Content-Type header.
    #[must_use]
    pub fn content_type(self, content_type: impl AsRef<str>) -> Self {
        self.header("Content-Type", content_type.as_ref().as_bytes().to_vec())
    }

    /// Set the raw body bytes.
    #[must_use]
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Set a JSON body.
    #[must_use]
    pub fn json<T: serde::Serialize>(self, value: &T) -> Self {
        let json = serde_json::to_vec(value).unwrap_or_default();
        self.content_type("application/json").body(json)
    }

    /// Set a plain text body.
    #[must_use]
    pub fn text(self, text: impl AsRef<str>) -> Self {
        self.content_type("text/plain")
            .body(text.as_ref().as_bytes().to_vec())
    }

    /// Set an HTML body.
    #[must_use]
    pub fn html(self, html: impl AsRef<str>) -> Self {
        self.content_type("text/html")
            .body(html.as_ref().as_bytes().to_vec())
    }

    /// Build the response.
    #[must_use]
    pub fn build(self) -> Response {
        let mut resp = Response::with_status(self.status);

        for (name, value) in self.headers {
            resp = resp.header(name, value);
        }

        if let Some(body) = self.body {
            resp = resp.body(ResponseBody::Bytes(body));
        }

        resp
    }
}

// =============================================================================
// Auth Factory
// =============================================================================

/// Factory for creating authentication test data.
///
/// # Example
///
/// ```ignore
/// use fastapi_core::fixtures::AuthFactory;
///
/// // Bearer token
/// let token = AuthFactory::bearer_token();
///
/// // API key
/// let key = AuthFactory::api_key();
///
/// // JWT-like token
/// let jwt = AuthFactory::jwt_token()
///     .sub("user123")
///     .build();
/// ```
/// Factory for creating authentication test data - provides static methods.
pub struct AuthFactory;

impl AuthFactory {
    /// Generate a random-looking bearer token.
    #[must_use]
    pub fn bearer_token() -> String {
        // Generate a deterministic but realistic-looking token
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U".to_string()
    }

    /// Generate a random-looking API key.
    #[must_use]
    pub fn api_key() -> String {
        "sk_test_abcdefghijklmnopqrstuvwxyz123456".to_string()
    }

    /// Generate a random-looking session ID.
    #[must_use]
    pub fn session_id() -> String {
        "sess_abcdef123456789012345678901234567890".to_string()
    }

    /// Generate a refresh token.
    #[must_use]
    pub fn refresh_token() -> String {
        "rt_abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGH".to_string()
    }

    /// Create a JWT-like token factory.
    #[must_use]
    pub fn jwt_token() -> JwtFactory {
        JwtFactory::new()
    }

    /// Generate basic auth credentials.
    #[must_use]
    pub fn basic_credentials() -> (String, String) {
        ("testuser".to_string(), "testpass123".to_string())
    }

    /// Generate an OAuth2 authorization code.
    #[must_use]
    pub fn oauth_code() -> String {
        "authcode_abcdefghijklmnopqrstuvwxyz123456".to_string()
    }
}

/// Factory for creating JWT-like tokens.
#[derive(Debug, Clone, Default)]
pub struct JwtFactory {
    sub: Option<String>,
    iat: Option<u64>,
    exp: Option<u64>,
    iss: Option<String>,
    aud: Option<String>,
    custom: HashMap<String, String>,
}

impl JwtFactory {
    /// Create a new JWT factory.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the subject claim.
    #[must_use]
    #[allow(clippy::should_implement_trait)]
    pub fn sub(mut self, sub: impl Into<String>) -> Self {
        self.sub = Some(sub.into());
        self
    }

    /// Set the issued-at timestamp.
    #[must_use]
    pub fn iat(mut self, iat: u64) -> Self {
        self.iat = Some(iat);
        self
    }

    /// Set the expiration timestamp.
    #[must_use]
    pub fn exp(mut self, exp: u64) -> Self {
        self.exp = Some(exp);
        self
    }

    /// Set the issuer claim.
    #[must_use]
    pub fn iss(mut self, iss: impl Into<String>) -> Self {
        self.iss = Some(iss.into());
        self
    }

    /// Set the audience claim.
    #[must_use]
    pub fn aud(mut self, aud: impl Into<String>) -> Self {
        self.aud = Some(aud.into());
        self
    }

    /// Add a custom claim.
    #[must_use]
    pub fn claim(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.custom.insert(key.into(), value.into());
        self
    }

    /// Build a JWT-like token string.
    ///
    /// Note: This is NOT cryptographically valid. It's for testing only.
    #[must_use]
    pub fn build(self) -> String {
        // Build a fake JWT for testing
        let mut claims = serde_json::Map::new();

        if let Some(sub) = self.sub {
            claims.insert("sub".into(), serde_json::Value::String(sub));
        }
        if let Some(iat) = self.iat {
            claims.insert("iat".into(), serde_json::Value::Number(iat.into()));
        }
        if let Some(exp) = self.exp {
            claims.insert("exp".into(), serde_json::Value::Number(exp.into()));
        }
        if let Some(iss) = self.iss {
            claims.insert("iss".into(), serde_json::Value::String(iss));
        }
        if let Some(aud) = self.aud {
            claims.insert("aud".into(), serde_json::Value::String(aud));
        }
        for (k, v) in self.custom {
            claims.insert(k, serde_json::Value::String(v));
        }

        let header = base64_encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = base64_encode(&serde_json::to_string(&claims).unwrap_or_default());
        let signature = "test_signature_not_valid";

        format!("{header}.{payload}.{signature}")
    }
}

// =============================================================================
// JSON Factory
// =============================================================================

/// Factory for creating JSON test payloads.
///
/// # Example
///
/// ```ignore
/// use fastapi_core::fixtures::JsonFactory;
///
/// // Valid JSON object
/// let obj = JsonFactory::object()
///     .field("name", "Alice")
///     .field("age", 30)
///     .build();
///
/// // Valid JSON array
/// let arr = JsonFactory::array()
///     .push(1)
///     .push(2)
///     .build();
///
/// // Invalid JSON
/// let invalid = JsonFactory::malformed();
/// ```
pub struct JsonFactory;

impl JsonFactory {
    /// Create an object factory.
    #[must_use]
    pub fn object() -> JsonObjectFactory {
        JsonObjectFactory::new()
    }

    /// Create an array factory.
    #[must_use]
    pub fn array() -> JsonArrayFactory {
        JsonArrayFactory::new()
    }

    /// Generate malformed JSON (unclosed brace).
    #[must_use]
    pub fn malformed() -> Vec<u8> {
        b"{\"key\": \"value\"".to_vec()
    }

    /// Generate JSON with trailing comma.
    #[must_use]
    pub fn trailing_comma() -> Vec<u8> {
        b"{\"key\": \"value\",}".to_vec()
    }

    /// Generate JSON with single quotes (invalid).
    #[must_use]
    pub fn single_quotes() -> Vec<u8> {
        b"{'key': 'value'}".to_vec()
    }

    /// Generate JSON with unquoted keys (invalid).
    #[must_use]
    pub fn unquoted_keys() -> Vec<u8> {
        b"{key: \"value\"}".to_vec()
    }

    /// Generate empty object.
    #[must_use]
    pub fn empty_object() -> Vec<u8> {
        b"{}".to_vec()
    }

    /// Generate empty array.
    #[must_use]
    pub fn empty_array() -> Vec<u8> {
        b"[]".to_vec()
    }

    /// Generate null.
    #[must_use]
    pub fn null() -> Vec<u8> {
        b"null".to_vec()
    }
}

/// Factory for building JSON objects.
#[derive(Debug, Clone, Default)]
pub struct JsonObjectFactory {
    fields: Vec<(String, serde_json::Value)>,
}

impl JsonObjectFactory {
    /// Create a new object factory.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a string field.
    #[must_use]
    pub fn string(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields
            .push((key.into(), serde_json::Value::String(value.into())));
        self
    }

    /// Add a numeric field.
    #[must_use]
    pub fn number(mut self, key: impl Into<String>, value: i64) -> Self {
        self.fields
            .push((key.into(), serde_json::Value::Number(value.into())));
        self
    }

    /// Add a float field.
    #[must_use]
    pub fn float(mut self, key: impl Into<String>, value: f64) -> Self {
        if let Some(n) = serde_json::Number::from_f64(value) {
            self.fields.push((key.into(), serde_json::Value::Number(n)));
        }
        self
    }

    /// Add a boolean field.
    #[must_use]
    pub fn bool(mut self, key: impl Into<String>, value: bool) -> Self {
        self.fields
            .push((key.into(), serde_json::Value::Bool(value)));
        self
    }

    /// Add a null field.
    #[must_use]
    pub fn null(mut self, key: impl Into<String>) -> Self {
        self.fields.push((key.into(), serde_json::Value::Null));
        self
    }

    /// Add a nested object field.
    #[must_use]
    pub fn object(mut self, key: impl Into<String>, factory: JsonObjectFactory) -> Self {
        let map: serde_json::Map<String, serde_json::Value> = factory.fields.into_iter().collect();
        self.fields
            .push((key.into(), serde_json::Value::Object(map)));
        self
    }

    /// Add an array field.
    #[must_use]
    pub fn array(mut self, key: impl Into<String>, factory: JsonArrayFactory) -> Self {
        self.fields
            .push((key.into(), serde_json::Value::Array(factory.items)));
        self
    }

    /// Build the JSON bytes.
    #[must_use]
    pub fn build(self) -> Vec<u8> {
        let map: serde_json::Map<String, serde_json::Value> = self.fields.into_iter().collect();
        serde_json::to_vec(&map).unwrap_or_default()
    }

    /// Build as a serde_json::Value.
    #[must_use]
    pub fn build_value(self) -> serde_json::Value {
        let map: serde_json::Map<String, serde_json::Value> = self.fields.into_iter().collect();
        serde_json::Value::Object(map)
    }
}

/// Factory for building JSON arrays.
#[derive(Debug, Clone, Default)]
pub struct JsonArrayFactory {
    items: Vec<serde_json::Value>,
}

impl JsonArrayFactory {
    /// Create a new array factory.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a string item.
    #[must_use]
    pub fn push_string(mut self, value: impl Into<String>) -> Self {
        self.items.push(serde_json::Value::String(value.into()));
        self
    }

    /// Push a numeric item.
    #[must_use]
    pub fn push_number(mut self, value: i64) -> Self {
        self.items.push(serde_json::Value::Number(value.into()));
        self
    }

    /// Push a boolean item.
    #[must_use]
    pub fn push_bool(mut self, value: bool) -> Self {
        self.items.push(serde_json::Value::Bool(value));
        self
    }

    /// Push a null item.
    #[must_use]
    pub fn push_null(mut self) -> Self {
        self.items.push(serde_json::Value::Null);
        self
    }

    /// Push an object item.
    #[must_use]
    pub fn push_object(mut self, factory: JsonObjectFactory) -> Self {
        self.items.push(factory.build_value());
        self
    }

    /// Build the JSON bytes.
    #[must_use]
    pub fn build(self) -> Vec<u8> {
        serde_json::to_vec(&self.items).unwrap_or_default()
    }
}

// =============================================================================
// User Factory
// =============================================================================

/// Factory for creating user test data.
///
/// # Example
///
/// ```ignore
/// use fastapi_core::fixtures::UserFactory;
///
/// let user = UserFactory::new()
///     .email("test@example.com")
///     .name("Alice")
///     .build();
/// ```
#[derive(Debug, Clone, Default)]
pub struct UserFactory {
    id: Option<i64>,
    email: Option<String>,
    name: Option<String>,
    role: Option<String>,
    active: Option<bool>,
}

impl UserFactory {
    /// Create a new user factory with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the user ID.
    #[must_use]
    pub fn id(mut self, id: i64) -> Self {
        self.id = Some(id);
        self
    }

    /// Set the email.
    #[must_use]
    pub fn email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    /// Set the name.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set the role.
    #[must_use]
    pub fn role(mut self, role: impl Into<String>) -> Self {
        self.role = Some(role.into());
        self
    }

    /// Set whether the user is active.
    #[must_use]
    pub fn active(mut self, active: bool) -> Self {
        self.active = Some(active);
        self
    }

    /// Create an admin user.
    #[must_use]
    pub fn admin() -> Self {
        Self::new()
            .id(1)
            .email("admin@example.com")
            .name("Admin User")
            .role("admin")
            .active(true)
    }

    /// Create a regular user.
    #[must_use]
    pub fn regular() -> Self {
        Self::new()
            .id(2)
            .email("user@example.com")
            .name("Regular User")
            .role("user")
            .active(true)
    }

    /// Create an inactive user.
    #[must_use]
    pub fn inactive() -> Self {
        Self::new()
            .id(3)
            .email("inactive@example.com")
            .name("Inactive User")
            .role("user")
            .active(false)
    }

    /// Build as JSON bytes.
    #[must_use]
    pub fn build(self) -> Vec<u8> {
        let mut map = serde_json::Map::new();

        if let Some(id) = self.id {
            map.insert("id".into(), serde_json::Value::Number(id.into()));
        }
        if let Some(email) = self.email {
            map.insert("email".into(), serde_json::Value::String(email));
        }
        if let Some(name) = self.name {
            map.insert("name".into(), serde_json::Value::String(name));
        }
        if let Some(role) = self.role {
            map.insert("role".into(), serde_json::Value::String(role));
        }
        if let Some(active) = self.active {
            map.insert("active".into(), serde_json::Value::Bool(active));
        }

        serde_json::to_vec(&map).unwrap_or_default()
    }

    /// Build as a serde_json::Value.
    #[must_use]
    pub fn build_value(self) -> serde_json::Value {
        serde_json::from_slice(&self.build()).unwrap_or(serde_json::Value::Null)
    }
}

// =============================================================================
// Common Test Data
// =============================================================================

/// Pre-built common test data for quick access.
pub struct CommonFixtures;

impl CommonFixtures {
    /// A valid email address for testing.
    pub const TEST_EMAIL: &'static str = "test@example.com";

    /// A valid phone number for testing.
    pub const TEST_PHONE: &'static str = "+1234567890";

    /// A valid URL for testing.
    pub const TEST_URL: &'static str = "https://example.com";

    /// A valid UUID for testing.
    pub const TEST_UUID: &'static str = "550e8400-e29b-41d4-a716-446655440000";

    /// A valid ISO date for testing.
    pub const TEST_DATE: &'static str = "2025-01-15";

    /// A valid ISO datetime for testing.
    pub const TEST_DATETIME: &'static str = "2025-01-15T10:30:00Z";

    /// An IPv4 address for testing.
    pub const TEST_IPV4: &'static str = "192.168.1.1";

    /// An IPv6 address for testing.
    pub const TEST_IPV6: &'static str = "::1";
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Simple base64 encoding.
fn base64_encode(input: &str) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let bytes = input.as_bytes();
    let mut result = String::new();

    for chunk in bytes.chunks(3) {
        let b = match chunk.len() {
            1 => [chunk[0], 0, 0],
            2 => [chunk[0], chunk[1], 0],
            _ => [chunk[0], chunk[1], chunk[2]],
        };

        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);

        result.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        result.push(ALPHABET[((n >> 12) & 63) as usize] as char);

        if chunk.len() > 1 {
            result.push(ALPHABET[((n >> 6) & 63) as usize] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(ALPHABET[(n & 63) as usize] as char);
        } else {
            result.push('=');
        }
    }

    result
}

/// Simple URL encoding.
fn urlencoding_simple(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 3);
    for c in s.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => result.push(c),
            ' ' => result.push('+'),
            _ => {
                for byte in c.to_string().as_bytes() {
                    result.push_str(&format!("%{byte:02X}"));
                }
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_factory_get() {
        let req = RequestFactory::get("/users").build();
        assert_eq!(req.method(), Method::Get);
        assert_eq!(req.path(), "/users");
    }

    #[test]
    fn test_request_factory_post_json() {
        let data = serde_json::json!({"name": "Alice"});
        let req = RequestFactory::post("/users").json(&data).build();

        assert_eq!(req.method(), Method::Post);
        assert!(req.headers().get("content-type").is_some());
    }

    #[test]
    fn test_request_factory_with_auth() {
        let req = RequestFactory::get("/protected")
            .bearer_token("token123")
            .build();

        let auth = req.headers().get("authorization").unwrap();
        assert!(std::str::from_utf8(auth).unwrap().starts_with("Bearer "));
    }

    #[test]
    fn test_request_factory_query_params() {
        let req = RequestFactory::get("/search")
            .query_params([("q", "rust"), ("limit", "10")])
            .build();

        assert_eq!(req.query(), Some("q=rust&limit=10"));
    }

    #[test]
    fn test_response_factory_ok() {
        let resp = ResponseFactory::ok().build();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn test_response_factory_not_found_json() {
        let body = serde_json::json!({"error": "Not found"});
        let resp = ResponseFactory::not_found().json(&body).build();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_auth_factory_tokens() {
        let bearer = AuthFactory::bearer_token();
        assert!(!bearer.is_empty());

        let api_key = AuthFactory::api_key();
        assert!(api_key.starts_with("sk_test_"));

        let session = AuthFactory::session_id();
        assert!(session.starts_with("sess_"));
    }

    #[test]
    fn test_jwt_factory() {
        let token = JwtFactory::new().sub("user123").iss("test-issuer").build();

        let parts: Vec<_> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
    }

    #[test]
    fn test_json_factory_object() {
        let json = JsonFactory::object()
            .string("name", "Alice")
            .number("age", 30)
            .bool("active", true)
            .build();

        let parsed: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed["name"], "Alice");
        assert_eq!(parsed["age"], 30);
        assert_eq!(parsed["active"], true);
    }

    #[test]
    fn test_json_factory_array() {
        let json = JsonArrayFactory::new()
            .push_number(1)
            .push_number(2)
            .push_number(3)
            .build();

        let parsed: Vec<i64> = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed, vec![1, 2, 3]);
    }

    #[test]
    fn test_json_factory_malformed() {
        let malformed = JsonFactory::malformed();
        assert!(serde_json::from_slice::<serde_json::Value>(&malformed).is_err());
    }

    #[test]
    fn test_user_factory() {
        let user = UserFactory::admin().build();
        let parsed: serde_json::Value = serde_json::from_slice(&user).unwrap();

        assert_eq!(parsed["role"], "admin");
        assert_eq!(parsed["active"], true);
    }

    #[test]
    fn test_common_fixtures() {
        assert!(CommonFixtures::TEST_EMAIL.contains('@'));
        assert!(CommonFixtures::TEST_UUID.contains('-'));
    }

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode("hello"), "aGVsbG8=");
        assert_eq!(base64_encode("a"), "YQ==");
    }
}
