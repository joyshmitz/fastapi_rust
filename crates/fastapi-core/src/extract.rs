//! Request extraction traits and extractors.
//!
//! This module provides the [`FromRequest`] trait and common extractors
//! like [`Json`] and [`Path`] for parsing request data.

use crate::context::RequestContext;
use crate::error::{HttpError, ValidationError, ValidationErrors};
use crate::request::{Body, Request};
use crate::response::IntoResponse;
use serde::de::{
    self, DeserializeOwned, Deserializer, IntoDeserializer, MapAccess, SeqAccess, Visitor,
};
use std::fmt;
use std::future::Future;
use std::ops::{Deref, DerefMut};

/// Trait for types that can be extracted from a request.
///
/// This is the core abstraction for request handlers. Each parameter
/// in a handler function implements this trait.
///
/// The `ctx` parameter provides access to the request context, including
/// asupersync's capability context for cancellation checkpoints and
/// budget-aware operations.
///
/// # Example
///
/// ```ignore
/// use fastapi_core::{FromRequest, Request, RequestContext};
///
/// struct MyExtractor(String);
///
/// impl FromRequest for MyExtractor {
///     type Error = std::convert::Infallible;
///
///     async fn from_request(
///         ctx: &RequestContext,
///         req: &mut Request,
///     ) -> Result<Self, Self::Error> {
///         // Check for cancellation before expensive work
///         let _ = ctx.checkpoint();
///         Ok(MyExtractor("extracted".to_string()))
///     }
/// }
/// ```
pub trait FromRequest: Sized {
    /// Error type when extraction fails.
    type Error: IntoResponse;

    /// Extract a value from the request.
    ///
    /// # Parameters
    ///
    /// - `ctx`: The request context providing access to asupersync capabilities
    /// - `req`: The HTTP request to extract from
    fn from_request(
        ctx: &RequestContext,
        req: &mut Request,
    ) -> impl Future<Output = Result<Self, Self::Error>> + Send;
}

// Implement for Option to make extractors optional
impl<T: FromRequest> FromRequest for Option<T> {
    type Error = std::convert::Infallible;

    async fn from_request(ctx: &RequestContext, req: &mut Request) -> Result<Self, Self::Error> {
        Ok(T::from_request(ctx, req).await.ok())
    }
}

// Implement for RequestContext itself - allows handlers to receive the context
impl FromRequest for RequestContext {
    type Error = std::convert::Infallible;

    async fn from_request(ctx: &RequestContext, _req: &mut Request) -> Result<Self, Self::Error> {
        Ok(ctx.clone())
    }
}

// ============================================================================
// JSON Body Extractor
// ============================================================================

/// Default maximum JSON body size (1MB).
pub const DEFAULT_JSON_LIMIT: usize = 1024 * 1024;

/// Configuration for JSON extraction.
#[derive(Debug, Clone)]
pub struct JsonConfig {
    /// Maximum body size in bytes.
    limit: usize,
    /// Content-Type header value to accept (case-insensitive).
    /// If None, accepts any application/json variant.
    content_type: Option<String>,
}

impl Default for JsonConfig {
    fn default() -> Self {
        Self {
            limit: DEFAULT_JSON_LIMIT,
            content_type: None,
        }
    }
}

impl JsonConfig {
    /// Create a new JSON configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the maximum body size limit.
    #[must_use]
    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }

    /// Set a specific Content-Type to accept.
    #[must_use]
    pub fn content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }

    /// Returns the configured size limit.
    #[must_use]
    pub fn get_limit(&self) -> usize {
        self.limit
    }
}

/// JSON body extractor.
///
/// Extracts a JSON body from the request and deserializes it to type `T`.
///
/// # Error Responses
///
/// - **415 Unsupported Media Type**: Content-Type is not `application/json`
/// - **413 Payload Too Large**: Body exceeds configured size limit
/// - **422 Unprocessable Entity**: JSON parsing failed
///
/// # Example
///
/// ```ignore
/// use fastapi_core::extract::Json;
/// use serde::Deserialize;
///
/// #[derive(Deserialize)]
/// struct CreateUser {
///     name: String,
///     email: String,
/// }
///
/// async fn create_user(Json(user): Json<CreateUser>) -> impl IntoResponse {
///     format!("Created user: {}", user.name)
/// }
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct Json<T>(pub T);

impl<T> Json<T> {
    /// Unwrap the inner value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> Deref for Json<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for Json<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Error returned when JSON extraction fails.
#[derive(Debug)]
pub enum JsonExtractError {
    /// Content-Type header is missing or not application/json.
    UnsupportedMediaType {
        /// The actual Content-Type received (if any).
        actual: Option<String>,
    },
    /// Request body exceeds the size limit.
    PayloadTooLarge {
        /// The actual body size.
        size: usize,
        /// The configured limit.
        limit: usize,
    },
    /// JSON deserialization failed.
    DeserializeError {
        /// The serde_json error message.
        message: String,
        /// Line number where error occurred (if available).
        line: Option<usize>,
        /// Column number where error occurred (if available).
        column: Option<usize>,
    },
}

impl std::fmt::Display for JsonExtractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedMediaType { actual } => {
                if let Some(ct) = actual {
                    write!(f, "Expected Content-Type: application/json, got: {ct}")
                } else {
                    write!(f, "Missing Content-Type header, expected application/json")
                }
            }
            Self::PayloadTooLarge { size, limit } => {
                write!(
                    f,
                    "Request body too large: {size} bytes exceeds {limit} byte limit"
                )
            }
            Self::DeserializeError {
                message,
                line,
                column,
            } => {
                if let (Some(l), Some(c)) = (line, column) {
                    write!(f, "JSON parse error at line {l}, column {c}: {message}")
                } else {
                    write!(f, "JSON parse error: {message}")
                }
            }
        }
    }
}

impl std::error::Error for JsonExtractError {}

impl IntoResponse for JsonExtractError {
    fn into_response(self) -> crate::response::Response {
        match self {
            Self::UnsupportedMediaType { actual } => {
                let detail = if let Some(ct) = actual {
                    format!("Expected Content-Type: application/json, got: {ct}")
                } else {
                    "Missing Content-Type header, expected application/json".to_string()
                };
                HttpError::unsupported_media_type()
                    .with_detail(detail)
                    .into_response()
            }
            Self::PayloadTooLarge { size, limit } => HttpError::payload_too_large()
                .with_detail(format!(
                    "Request body too large: {size} bytes exceeds {limit} byte limit"
                ))
                .into_response(),
            Self::DeserializeError {
                message,
                line,
                column,
            } => {
                // Return a 422 with validation error format
                let mut errors = ValidationErrors::new();
                errors.push(ValidationError {
                    error_type: "json_invalid",
                    loc: vec!["body".to_string()],
                    msg: if let (Some(l), Some(c)) = (line, column) {
                        format!("JSON parse error at line {l}, column {c}: {message}")
                    } else {
                        format!("JSON parse error: {message}")
                    },
                    input: None,
                    ctx: None,
                });
                errors.into_response()
            }
        }
    }
}

impl<T: DeserializeOwned> FromRequest for Json<T> {
    type Error = JsonExtractError;

    async fn from_request(ctx: &RequestContext, req: &mut Request) -> Result<Self, Self::Error> {
        // Check cancellation at start
        let _ = ctx.checkpoint();

        // Validate Content-Type
        let content_type = req
            .headers()
            .get("content-type")
            .and_then(|v| std::str::from_utf8(v).ok());

        let is_json = content_type.is_some_and(|ct| {
            let ct_lower = ct.to_ascii_lowercase();
            ct_lower.starts_with("application/json")
                || ct_lower.starts_with("application/") && ct_lower.contains("+json")
        });

        if !is_json {
            return Err(JsonExtractError::UnsupportedMediaType {
                actual: content_type.map(String::from),
            });
        }

        // Get body bytes
        let body = req.take_body();
        let bytes = match body {
            Body::Empty => Vec::new(),
            Body::Bytes(b) => b,
        };

        // Check size limit (using default for now - could be made configurable)
        let limit = DEFAULT_JSON_LIMIT;
        if bytes.len() > limit {
            return Err(JsonExtractError::PayloadTooLarge {
                size: bytes.len(),
                limit,
            });
        }

        // Check cancellation before deserialization
        let _ = ctx.checkpoint();

        // Deserialize JSON
        serde_json::from_slice(&bytes)
            .map(Json)
            .map_err(|e| JsonExtractError::DeserializeError {
                message: e.to_string(),
                line: Some(e.line()),
                column: Some(e.column()),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::Method;

    // Helper to create a test context
    fn test_context() -> RequestContext {
        let cx = asupersync::Cx::for_testing();
        RequestContext::new(cx, 12345)
    }

    // Helper to create a request with JSON body
    fn json_request(body: &str) -> Request {
        let mut req = Request::new(Method::Post, "/test");
        req.headers_mut()
            .insert("content-type", b"application/json".to_vec());
        req.set_body(Body::Bytes(body.as_bytes().to_vec()));
        req
    }

    #[test]
    fn json_config_defaults() {
        let config = JsonConfig::default();
        assert_eq!(config.get_limit(), DEFAULT_JSON_LIMIT);
    }

    #[test]
    fn json_config_custom() {
        let config = JsonConfig::new().limit(1024);
        assert_eq!(config.get_limit(), 1024);
    }

    #[test]
    fn json_deref() {
        let json = Json(42i32);
        assert_eq!(*json, 42);
    }

    #[test]
    fn json_into_inner() {
        let json = Json("hello".to_string());
        assert_eq!(json.into_inner(), "hello");
    }

    #[test]
    fn json_extract_success() {
        use serde::Deserialize;

        #[derive(Deserialize, Debug, PartialEq)]
        struct TestPayload {
            name: String,
            value: i32,
        }

        let ctx = test_context();
        let mut req = json_request(r#"{"name": "test", "value": 42}"#);

        let result = futures_executor::block_on(Json::<TestPayload>::from_request(&ctx, &mut req));
        let Json(payload) = result.unwrap();
        assert_eq!(payload.name, "test");
        assert_eq!(payload.value, 42);
    }

    #[test]
    fn json_extract_wrong_content_type() {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct TestPayload {
            #[allow(dead_code)]
            name: String,
        }

        let ctx = test_context();
        let mut req = Request::new(Method::Post, "/test");
        req.headers_mut()
            .insert("content-type", b"text/plain".to_vec());
        req.set_body(Body::Bytes(b"{}".to_vec()));

        let result = futures_executor::block_on(Json::<TestPayload>::from_request(&ctx, &mut req));
        assert!(matches!(
            result,
            Err(JsonExtractError::UnsupportedMediaType { actual: Some(ct) })
            if ct == "text/plain"
        ));
    }

    #[test]
    fn json_extract_missing_content_type() {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct TestPayload {
            #[allow(dead_code)]
            name: String,
        }

        let ctx = test_context();
        let mut req = Request::new(Method::Post, "/test");
        req.set_body(Body::Bytes(b"{}".to_vec()));

        let result = futures_executor::block_on(Json::<TestPayload>::from_request(&ctx, &mut req));
        assert!(matches!(
            result,
            Err(JsonExtractError::UnsupportedMediaType { actual: None })
        ));
    }

    #[test]
    fn json_extract_invalid_json() {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct TestPayload {
            #[allow(dead_code)]
            name: String,
        }

        let ctx = test_context();
        let mut req = json_request(r#"{"name": invalid}"#);

        let result = futures_executor::block_on(Json::<TestPayload>::from_request(&ctx, &mut req));
        assert!(matches!(
            result,
            Err(JsonExtractError::DeserializeError { .. })
        ));
    }

    #[test]
    fn json_extract_application_json_charset() {
        use serde::Deserialize;

        #[derive(Deserialize, PartialEq, Debug)]
        struct TestPayload {
            value: i32,
        }

        let ctx = test_context();
        let mut req = Request::new(Method::Post, "/test");
        req.headers_mut()
            .insert("content-type", b"application/json; charset=utf-8".to_vec());
        req.set_body(Body::Bytes(b"{\"value\": 123}".to_vec()));

        let result = futures_executor::block_on(Json::<TestPayload>::from_request(&ctx, &mut req));
        let Json(payload) = result.unwrap();
        assert_eq!(payload.value, 123);
    }

    #[test]
    fn json_extract_vendor_json() {
        use serde::Deserialize;

        #[derive(Deserialize, PartialEq, Debug)]
        struct TestPayload {
            value: i32,
        }

        let ctx = test_context();
        let mut req = Request::new(Method::Post, "/test");
        // Vendor media types like application/vnd.api+json should work
        req.headers_mut()
            .insert("content-type", b"application/vnd.api+json".to_vec());
        req.set_body(Body::Bytes(b"{\"value\": 456}".to_vec()));

        let result = futures_executor::block_on(Json::<TestPayload>::from_request(&ctx, &mut req));
        let Json(payload) = result.unwrap();
        assert_eq!(payload.value, 456);
    }

    #[test]
    fn json_error_display() {
        let err = JsonExtractError::UnsupportedMediaType {
            actual: Some("text/html".to_string()),
        };
        assert!(err.to_string().contains("text/html"));

        let err = JsonExtractError::PayloadTooLarge {
            size: 2000,
            limit: 1000,
        };
        assert!(err.to_string().contains("2000"));
        assert!(err.to_string().contains("1000"));

        let err = JsonExtractError::DeserializeError {
            message: "unexpected token".to_string(),
            line: Some(1),
            column: Some(10),
        };
        assert!(err.to_string().contains("line 1"));
        assert!(err.to_string().contains("column 10"));
    }
}

// ============================================================================
// Path Parameter Extractor
// ============================================================================

/// Extracted path parameters stored in request extensions.
///
/// This type is set by the router after matching a route and extracting
/// path parameters. The [`Path`] extractor retrieves this from the request.
///
/// # Example
///
/// For a route `/users/{user_id}/posts/{post_id}` matched against
/// `/users/42/posts/99`, this would contain:
/// `[("user_id", "42"), ("post_id", "99")]`
#[derive(Debug, Clone, Default)]
pub struct PathParams(pub Vec<(String, String)>);

impl PathParams {
    /// Create empty path parameters.
    #[must_use]
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Create from a vector of name-value pairs.
    #[must_use]
    pub fn from_pairs(pairs: Vec<(String, String)>) -> Self {
        Self(pairs)
    }

    /// Get a parameter value by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// Get all parameters as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[(String, String)] {
        &self.0
    }

    /// Returns true if there are no parameters.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of parameters.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// Path parameter extractor.
///
/// Extracts path parameters from the URL and deserializes them to type `T`.
///
/// # Supported Types
///
/// - **Single value**: `Path<i64>` extracts the first (or only) path parameter
/// - **Tuple**: `Path<(String, i64)>` extracts parameters in order
/// - **Struct**: `Path<MyParams>` extracts parameters by field name
///
/// # Error Responses
///
/// - **500 Internal Server Error**: Path parameters not set by router (server bug)
/// - **422 Unprocessable Entity**: Parameter missing or type conversion failed
///
/// # Examples
///
/// ## Single Parameter
///
/// ```ignore
/// #[get("/users/{id}")]
/// async fn get_user(Path(id): Path<i64>) -> impl IntoResponse {
///     format!("User ID: {id}")
/// }
/// ```
///
/// ## Multiple Parameters (Tuple)
///
/// ```ignore
/// #[get("/users/{user_id}/posts/{post_id}")]
/// async fn get_post(Path((user_id, post_id)): Path<(i64, i64)>) -> impl IntoResponse {
///     format!("User {user_id}, Post {post_id}")
/// }
/// ```
///
/// ## Struct Extraction
///
/// ```ignore
/// #[derive(Deserialize)]
/// struct PostPath {
///     user_id: i64,
///     post_id: i64,
/// }
///
/// #[get("/users/{user_id}/posts/{post_id}")]
/// async fn get_post(Path(path): Path<PostPath>) -> impl IntoResponse {
///     format!("User {}, Post {}", path.user_id, path.post_id)
/// }
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct Path<T>(pub T);

impl<T> Path<T> {
    /// Unwrap the inner value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> Deref for Path<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for Path<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Error returned when path extraction fails.
#[derive(Debug)]
pub enum PathExtractError {
    /// Path parameters not available in request extensions.
    /// This indicates a server configuration error (router not setting params).
    MissingPathParams,
    /// A required parameter was not found.
    MissingParam {
        /// The parameter name that was missing.
        name: String,
    },
    /// Parameter value could not be converted to the expected type.
    InvalidValue {
        /// The parameter name.
        name: String,
        /// The actual value that couldn't be converted.
        value: String,
        /// Description of the expected type.
        expected: &'static str,
        /// Additional error details.
        message: String,
    },
    /// Deserialization error (e.g., wrong number of parameters for tuple).
    DeserializeError {
        /// The error message.
        message: String,
    },
}

impl fmt::Display for PathExtractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPathParams => {
                write!(f, "Path parameters not available in request")
            }
            Self::MissingParam { name } => {
                write!(f, "Missing path parameter: {name}")
            }
            Self::InvalidValue {
                name,
                value,
                expected,
                message,
            } => {
                write!(
                    f,
                    "Invalid value for path parameter '{name}': expected {expected}, got '{value}': {message}"
                )
            }
            Self::DeserializeError { message } => {
                write!(f, "Path deserialization error: {message}")
            }
        }
    }
}

impl std::error::Error for PathExtractError {}

impl IntoResponse for PathExtractError {
    fn into_response(self) -> crate::response::Response {
        match self {
            Self::MissingPathParams => {
                // Server bug - path params should always be set by router
                HttpError::internal()
                    .with_detail("Path parameters not available")
                    .into_response()
            }
            Self::MissingParam { name } => {
                let mut errors = ValidationErrors::new();
                errors.push(ValidationError {
                    error_type: "missing",
                    loc: vec!["path".to_string(), name],
                    msg: "Path parameter is required".to_string(),
                    input: None,
                    ctx: None,
                });
                errors.into_response()
            }
            Self::InvalidValue {
                name,
                value,
                expected,
                message,
            } => {
                let mut errors = ValidationErrors::new();
                errors.push(ValidationError {
                    error_type: "type_error",
                    loc: vec!["path".to_string(), name],
                    msg: format!("Expected {expected}: {message}"),
                    input: Some(serde_json::Value::String(value)),
                    ctx: None,
                });
                errors.into_response()
            }
            Self::DeserializeError { message } => {
                let mut errors = ValidationErrors::new();
                errors.push(ValidationError {
                    error_type: "value_error",
                    loc: vec!["path".to_string()],
                    msg: message,
                    input: None,
                    ctx: None,
                });
                errors.into_response()
            }
        }
    }
}

impl<T: DeserializeOwned> FromRequest for Path<T> {
    type Error = PathExtractError;

    async fn from_request(_ctx: &RequestContext, req: &mut Request) -> Result<Self, Self::Error> {
        // Get path params from request extensions
        let params = req
            .get_extension::<PathParams>()
            .ok_or(PathExtractError::MissingPathParams)?
            .clone();

        // Deserialize using our custom deserializer
        let value = T::deserialize(PathDeserializer::new(&params))?;

        Ok(Path(value))
    }
}

// ============================================================================
// Path Parameter Deserializer
// ============================================================================

/// Custom serde deserializer for path parameters.
///
/// Handles three modes:
/// - Single value: Deserializes the first parameter value
/// - Sequence (tuple): Deserializes parameters in order
/// - Map (struct): Deserializes parameters by name
struct PathDeserializer<'de> {
    params: &'de PathParams,
}

impl<'de> PathDeserializer<'de> {
    fn new(params: &'de PathParams) -> Self {
        Self { params }
    }
}

impl<'de> Deserializer<'de> for PathDeserializer<'de> {
    type Error = PathExtractError;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        // Default: try as map (struct)
        self.deserialize_map(visitor)
    }

    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let value = self.get_single_value()?;
        let b = value
            .parse::<bool>()
            .map_err(|_| PathExtractError::InvalidValue {
                name: self.get_first_name(),
                value: value.to_string(),
                expected: "boolean",
                message: "expected 'true' or 'false'".to_string(),
            })?;
        visitor.visit_bool(b)
    }

    fn deserialize_i8<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let value = self.get_single_value()?;
        let n = value
            .parse::<i8>()
            .map_err(|e| PathExtractError::InvalidValue {
                name: self.get_first_name(),
                value: value.to_string(),
                expected: "i8",
                message: e.to_string(),
            })?;
        visitor.visit_i8(n)
    }

    fn deserialize_i16<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let value = self.get_single_value()?;
        let n = value
            .parse::<i16>()
            .map_err(|e| PathExtractError::InvalidValue {
                name: self.get_first_name(),
                value: value.to_string(),
                expected: "i16",
                message: e.to_string(),
            })?;
        visitor.visit_i16(n)
    }

    fn deserialize_i32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let value = self.get_single_value()?;
        let n = value
            .parse::<i32>()
            .map_err(|e| PathExtractError::InvalidValue {
                name: self.get_first_name(),
                value: value.to_string(),
                expected: "i32",
                message: e.to_string(),
            })?;
        visitor.visit_i32(n)
    }

    fn deserialize_i64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let value = self.get_single_value()?;
        let n = value
            .parse::<i64>()
            .map_err(|e| PathExtractError::InvalidValue {
                name: self.get_first_name(),
                value: value.to_string(),
                expected: "i64",
                message: e.to_string(),
            })?;
        visitor.visit_i64(n)
    }

    fn deserialize_i128<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let value = self.get_single_value()?;
        let n = value
            .parse::<i128>()
            .map_err(|e| PathExtractError::InvalidValue {
                name: self.get_first_name(),
                value: value.to_string(),
                expected: "i128",
                message: e.to_string(),
            })?;
        visitor.visit_i128(n)
    }

    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let value = self.get_single_value()?;
        let n = value
            .parse::<u8>()
            .map_err(|e| PathExtractError::InvalidValue {
                name: self.get_first_name(),
                value: value.to_string(),
                expected: "u8",
                message: e.to_string(),
            })?;
        visitor.visit_u8(n)
    }

    fn deserialize_u16<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let value = self.get_single_value()?;
        let n = value
            .parse::<u16>()
            .map_err(|e| PathExtractError::InvalidValue {
                name: self.get_first_name(),
                value: value.to_string(),
                expected: "u16",
                message: e.to_string(),
            })?;
        visitor.visit_u16(n)
    }

    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let value = self.get_single_value()?;
        let n = value
            .parse::<u32>()
            .map_err(|e| PathExtractError::InvalidValue {
                name: self.get_first_name(),
                value: value.to_string(),
                expected: "u32",
                message: e.to_string(),
            })?;
        visitor.visit_u32(n)
    }

    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let value = self.get_single_value()?;
        let n = value
            .parse::<u64>()
            .map_err(|e| PathExtractError::InvalidValue {
                name: self.get_first_name(),
                value: value.to_string(),
                expected: "u64",
                message: e.to_string(),
            })?;
        visitor.visit_u64(n)
    }

    fn deserialize_u128<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let value = self.get_single_value()?;
        let n = value
            .parse::<u128>()
            .map_err(|e| PathExtractError::InvalidValue {
                name: self.get_first_name(),
                value: value.to_string(),
                expected: "u128",
                message: e.to_string(),
            })?;
        visitor.visit_u128(n)
    }

    fn deserialize_f32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let value = self.get_single_value()?;
        let n = value
            .parse::<f32>()
            .map_err(|e| PathExtractError::InvalidValue {
                name: self.get_first_name(),
                value: value.to_string(),
                expected: "f32",
                message: e.to_string(),
            })?;
        visitor.visit_f32(n)
    }

    fn deserialize_f64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let value = self.get_single_value()?;
        let n = value
            .parse::<f64>()
            .map_err(|e| PathExtractError::InvalidValue {
                name: self.get_first_name(),
                value: value.to_string(),
                expected: "f64",
                message: e.to_string(),
            })?;
        visitor.visit_f64(n)
    }

    fn deserialize_char<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let value = self.get_single_value()?;
        let mut chars = value.chars();
        let c = chars.next().ok_or_else(|| PathExtractError::InvalidValue {
            name: self.get_first_name(),
            value: value.to_string(),
            expected: "char",
            message: "empty string".to_string(),
        })?;
        if chars.next().is_some() {
            return Err(PathExtractError::InvalidValue {
                name: self.get_first_name(),
                value: value.to_string(),
                expected: "char",
                message: "expected single character".to_string(),
            });
        }
        visitor.visit_char(c)
    }

    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let value = self.get_single_value()?;
        visitor.visit_str(value)
    }

    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let value = self.get_single_value()?;
        visitor.visit_string(value.to_string())
    }

    fn deserialize_bytes<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(PathExtractError::DeserializeError {
            message: "bytes deserialization not supported for path parameters".to_string(),
        })
    }

    fn deserialize_byte_buf<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(PathExtractError::DeserializeError {
            message: "byte_buf deserialization not supported for path parameters".to_string(),
        })
    }

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        // Path params are always present, so always Some
        visitor.visit_some(self)
    }

    fn deserialize_unit<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_unit()
    }

    fn deserialize_unit_struct<V>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_unit()
    }

    fn deserialize_newtype_struct<V>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_seq(PathSeqAccess::new(self.params))
    }

    fn deserialize_tuple<V>(self, _len: usize, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_seq(PathSeqAccess::new(self.params))
    }

    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_seq(PathSeqAccess::new(self.params))
    }

    fn deserialize_map<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_map(PathMapAccess::new(self.params))
    }

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_map(PathMapAccess::new(self.params))
    }

    fn deserialize_enum<V>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let value = self.get_single_value()?;
        visitor.visit_enum(value.into_deserializer())
    }

    fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_str(visitor)
    }

    fn deserialize_ignored_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_unit()
    }
}

impl PathDeserializer<'_> {
    fn get_single_value(&self) -> Result<&str, PathExtractError> {
        self.params
            .0
            .first()
            .map(|(_, v)| v.as_str())
            .ok_or_else(|| PathExtractError::DeserializeError {
                message: "no path parameters available".to_string(),
            })
    }

    fn get_first_name(&self) -> String {
        self.params
            .0
            .first()
            .map_or_else(|| "unknown".to_string(), |(n, _)| n.clone())
    }
}

impl de::Error for PathExtractError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        PathExtractError::DeserializeError {
            message: msg.to_string(),
        }
    }
}

/// Sequence access for deserializing tuples from path params.
struct PathSeqAccess<'de> {
    params: &'de PathParams,
    index: usize,
}

impl<'de> PathSeqAccess<'de> {
    fn new(params: &'de PathParams) -> Self {
        Self { params, index: 0 }
    }
}

impl<'de> SeqAccess<'de> for PathSeqAccess<'de> {
    type Error = PathExtractError;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
    where
        T: de::DeserializeSeed<'de>,
    {
        if self.index >= self.params.0.len() {
            return Ok(None);
        }

        let (name, value) = &self.params.0[self.index];
        self.index += 1;

        seed.deserialize(PathValueDeserializer::new(name, value))
            .map(Some)
    }
}

/// Map access for deserializing structs from path params.
struct PathMapAccess<'de> {
    params: &'de PathParams,
    index: usize,
}

impl<'de> PathMapAccess<'de> {
    fn new(params: &'de PathParams) -> Self {
        Self { params, index: 0 }
    }
}

impl<'de> MapAccess<'de> for PathMapAccess<'de> {
    type Error = PathExtractError;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>, Self::Error>
    where
        K: de::DeserializeSeed<'de>,
    {
        if self.index >= self.params.0.len() {
            return Ok(None);
        }

        let (name, _) = &self.params.0[self.index];
        seed.deserialize(name.as_str().into_deserializer())
            .map(Some)
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value, Self::Error>
    where
        V: de::DeserializeSeed<'de>,
    {
        let (name, value) = &self.params.0[self.index];
        self.index += 1;

        seed.deserialize(PathValueDeserializer::new(name, value))
    }
}

/// Deserializer for a single path parameter value.
struct PathValueDeserializer<'de> {
    name: &'de str,
    value: &'de str,
}

impl<'de> PathValueDeserializer<'de> {
    fn new(name: &'de str, value: &'de str) -> Self {
        Self { name, value }
    }
}

impl<'de> Deserializer<'de> for PathValueDeserializer<'de> {
    type Error = PathExtractError;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        // Default to string
        visitor.visit_str(self.value)
    }

    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let b = self
            .value
            .parse::<bool>()
            .map_err(|_| PathExtractError::InvalidValue {
                name: self.name.to_string(),
                value: self.value.to_string(),
                expected: "boolean",
                message: "expected 'true' or 'false'".to_string(),
            })?;
        visitor.visit_bool(b)
    }

    fn deserialize_i8<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let n = self
            .value
            .parse::<i8>()
            .map_err(|e| PathExtractError::InvalidValue {
                name: self.name.to_string(),
                value: self.value.to_string(),
                expected: "i8",
                message: e.to_string(),
            })?;
        visitor.visit_i8(n)
    }

    fn deserialize_i16<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let n = self
            .value
            .parse::<i16>()
            .map_err(|e| PathExtractError::InvalidValue {
                name: self.name.to_string(),
                value: self.value.to_string(),
                expected: "i16",
                message: e.to_string(),
            })?;
        visitor.visit_i16(n)
    }

    fn deserialize_i32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let n = self
            .value
            .parse::<i32>()
            .map_err(|e| PathExtractError::InvalidValue {
                name: self.name.to_string(),
                value: self.value.to_string(),
                expected: "i32",
                message: e.to_string(),
            })?;
        visitor.visit_i32(n)
    }

    fn deserialize_i64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let n = self
            .value
            .parse::<i64>()
            .map_err(|e| PathExtractError::InvalidValue {
                name: self.name.to_string(),
                value: self.value.to_string(),
                expected: "i64",
                message: e.to_string(),
            })?;
        visitor.visit_i64(n)
    }

    fn deserialize_i128<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let n = self
            .value
            .parse::<i128>()
            .map_err(|e| PathExtractError::InvalidValue {
                name: self.name.to_string(),
                value: self.value.to_string(),
                expected: "i128",
                message: e.to_string(),
            })?;
        visitor.visit_i128(n)
    }

    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let n = self
            .value
            .parse::<u8>()
            .map_err(|e| PathExtractError::InvalidValue {
                name: self.name.to_string(),
                value: self.value.to_string(),
                expected: "u8",
                message: e.to_string(),
            })?;
        visitor.visit_u8(n)
    }

    fn deserialize_u16<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let n = self
            .value
            .parse::<u16>()
            .map_err(|e| PathExtractError::InvalidValue {
                name: self.name.to_string(),
                value: self.value.to_string(),
                expected: "u16",
                message: e.to_string(),
            })?;
        visitor.visit_u16(n)
    }

    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let n = self
            .value
            .parse::<u32>()
            .map_err(|e| PathExtractError::InvalidValue {
                name: self.name.to_string(),
                value: self.value.to_string(),
                expected: "u32",
                message: e.to_string(),
            })?;
        visitor.visit_u32(n)
    }

    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let n = self
            .value
            .parse::<u64>()
            .map_err(|e| PathExtractError::InvalidValue {
                name: self.name.to_string(),
                value: self.value.to_string(),
                expected: "u64",
                message: e.to_string(),
            })?;
        visitor.visit_u64(n)
    }

    fn deserialize_u128<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let n = self
            .value
            .parse::<u128>()
            .map_err(|e| PathExtractError::InvalidValue {
                name: self.name.to_string(),
                value: self.value.to_string(),
                expected: "u128",
                message: e.to_string(),
            })?;
        visitor.visit_u128(n)
    }

    fn deserialize_f32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let n = self
            .value
            .parse::<f32>()
            .map_err(|e| PathExtractError::InvalidValue {
                name: self.name.to_string(),
                value: self.value.to_string(),
                expected: "f32",
                message: e.to_string(),
            })?;
        visitor.visit_f32(n)
    }

    fn deserialize_f64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let n = self
            .value
            .parse::<f64>()
            .map_err(|e| PathExtractError::InvalidValue {
                name: self.name.to_string(),
                value: self.value.to_string(),
                expected: "f64",
                message: e.to_string(),
            })?;
        visitor.visit_f64(n)
    }

    fn deserialize_char<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let mut chars = self.value.chars();
        let c = chars.next().ok_or_else(|| PathExtractError::InvalidValue {
            name: self.name.to_string(),
            value: self.value.to_string(),
            expected: "char",
            message: "empty string".to_string(),
        })?;
        if chars.next().is_some() {
            return Err(PathExtractError::InvalidValue {
                name: self.name.to_string(),
                value: self.value.to_string(),
                expected: "char",
                message: "expected single character".to_string(),
            });
        }
        visitor.visit_char(c)
    }

    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_str(self.value)
    }

    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_string(self.value.to_string())
    }

    fn deserialize_bytes<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(PathExtractError::DeserializeError {
            message: "bytes deserialization not supported for path parameters".to_string(),
        })
    }

    fn deserialize_byte_buf<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(PathExtractError::DeserializeError {
            message: "byte_buf deserialization not supported for path parameters".to_string(),
        })
    }

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_some(self)
    }

    fn deserialize_unit<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_unit()
    }

    fn deserialize_unit_struct<V>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_unit()
    }

    fn deserialize_newtype_struct<V>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(PathExtractError::DeserializeError {
            message: "sequence deserialization not supported for single path parameter".to_string(),
        })
    }

    fn deserialize_tuple<V>(self, _len: usize, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(PathExtractError::DeserializeError {
            message: "tuple deserialization not supported for single path parameter".to_string(),
        })
    }

    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        _len: usize,
        _visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(PathExtractError::DeserializeError {
            message: "tuple struct deserialization not supported for single path parameter"
                .to_string(),
        })
    }

    fn deserialize_map<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(PathExtractError::DeserializeError {
            message: "map deserialization not supported for single path parameter".to_string(),
        })
    }

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(PathExtractError::DeserializeError {
            message: "struct deserialization not supported for single path parameter".to_string(),
        })
    }

    fn deserialize_enum<V>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_enum(self.value.into_deserializer())
    }

    fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_str(self.value)
    }

    fn deserialize_ignored_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_unit()
    }
}

#[cfg(test)]
mod path_tests {
    use super::*;
    use crate::request::Method;
    use serde::Deserialize;

    // Helper to create a test context
    fn test_context() -> RequestContext {
        let cx = asupersync::Cx::for_testing();
        RequestContext::new(cx, 12345)
    }

    // Helper to create a request with path params
    fn request_with_params(params: Vec<(&str, &str)>) -> Request {
        let mut req = Request::new(Method::Get, "/test");
        let path_params = PathParams::from_pairs(
            params
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        );
        req.insert_extension(path_params);
        req
    }

    #[test]
    fn path_params_get() {
        let params = PathParams::from_pairs(vec![("id".to_string(), "42".to_string())]);
        assert_eq!(params.get("id"), Some("42"));
        assert_eq!(params.get("unknown"), None);
    }

    #[test]
    fn path_params_len() {
        let params = PathParams::new();
        assert!(params.is_empty());
        assert_eq!(params.len(), 0);

        let params = PathParams::from_pairs(vec![
            ("a".to_string(), "1".to_string()),
            ("b".to_string(), "2".to_string()),
        ]);
        assert!(!params.is_empty());
        assert_eq!(params.len(), 2);
    }

    #[test]
    fn path_extract_single_i64() {
        let ctx = test_context();
        let mut req = request_with_params(vec![("id", "42")]);

        let result = futures_executor::block_on(Path::<i64>::from_request(&ctx, &mut req));
        let Path(id) = result.unwrap();
        assert_eq!(id, 42);
    }

    #[test]
    fn path_extract_single_string() {
        let ctx = test_context();
        let mut req = request_with_params(vec![("name", "alice")]);

        let result = futures_executor::block_on(Path::<String>::from_request(&ctx, &mut req));
        let Path(name) = result.unwrap();
        assert_eq!(name, "alice");
    }

    #[test]
    fn path_extract_single_u32() {
        let ctx = test_context();
        let mut req = request_with_params(vec![("count", "100")]);

        let result = futures_executor::block_on(Path::<u32>::from_request(&ctx, &mut req));
        let Path(count) = result.unwrap();
        assert_eq!(count, 100);
    }

    #[test]
    fn path_extract_tuple() {
        let ctx = test_context();
        let mut req = request_with_params(vec![("user_id", "42"), ("post_id", "99")]);

        let result = futures_executor::block_on(Path::<(i64, i64)>::from_request(&ctx, &mut req));
        let Path((user_id, post_id)) = result.unwrap();
        assert_eq!(user_id, 42);
        assert_eq!(post_id, 99);
    }

    #[test]
    fn path_extract_tuple_mixed_types() {
        let ctx = test_context();
        let mut req = request_with_params(vec![("name", "alice"), ("id", "123")]);

        let result =
            futures_executor::block_on(Path::<(String, i64)>::from_request(&ctx, &mut req));
        let Path((name, id)) = result.unwrap();
        assert_eq!(name, "alice");
        assert_eq!(id, 123);
    }

    #[test]
    fn path_extract_struct() {
        #[derive(Deserialize, Debug, PartialEq)]
        struct UserPath {
            user_id: i64,
            post_id: i64,
        }

        let ctx = test_context();
        let mut req = request_with_params(vec![("user_id", "42"), ("post_id", "99")]);

        let result = futures_executor::block_on(Path::<UserPath>::from_request(&ctx, &mut req));
        let Path(path) = result.unwrap();
        assert_eq!(path.user_id, 42);
        assert_eq!(path.post_id, 99);
    }

    #[test]
    fn path_extract_missing_params() {
        let ctx = test_context();
        let mut req = Request::new(Method::Get, "/test");
        // No PathParams extension set

        let result = futures_executor::block_on(Path::<i64>::from_request(&ctx, &mut req));
        assert!(matches!(result, Err(PathExtractError::MissingPathParams)));
    }

    #[test]
    fn path_extract_invalid_type() {
        let ctx = test_context();
        let mut req = request_with_params(vec![("id", "not_a_number")]);

        let result = futures_executor::block_on(Path::<i64>::from_request(&ctx, &mut req));
        assert!(matches!(
            result,
            Err(PathExtractError::InvalidValue { name, .. }) if name == "id"
        ));
    }

    #[test]
    fn path_extract_negative_for_unsigned() {
        let ctx = test_context();
        let mut req = request_with_params(vec![("count", "-5")]);

        let result = futures_executor::block_on(Path::<u32>::from_request(&ctx, &mut req));
        assert!(matches!(result, Err(PathExtractError::InvalidValue { .. })));
    }

    #[test]
    fn path_extract_f64() {
        let ctx = test_context();
        let mut req = request_with_params(vec![("price", "19.99")]);

        let result = futures_executor::block_on(Path::<f64>::from_request(&ctx, &mut req));
        let Path(price) = result.unwrap();
        assert!((price - 19.99).abs() < 0.001);
    }

    #[test]
    fn path_deref() {
        let path = Path(42i64);
        assert_eq!(*path, 42);
    }

    #[test]
    fn path_into_inner() {
        let path = Path("hello".to_string());
        assert_eq!(path.into_inner(), "hello");
    }

    #[test]
    fn path_error_display() {
        let err = PathExtractError::MissingPathParams;
        assert!(err.to_string().contains("not available"));

        let err = PathExtractError::MissingParam {
            name: "user_id".to_string(),
        };
        assert!(err.to_string().contains("user_id"));

        let err = PathExtractError::InvalidValue {
            name: "id".to_string(),
            value: "abc".to_string(),
            expected: "i64",
            message: "invalid digit".to_string(),
        };
        assert!(err.to_string().contains("id"));
        assert!(err.to_string().contains("abc"));
        assert!(err.to_string().contains("i64"));
    }

    #[test]
    fn path_extract_bool() {
        let ctx = test_context();
        let mut req = request_with_params(vec![("active", "true")]);

        let result = futures_executor::block_on(Path::<bool>::from_request(&ctx, &mut req));
        let Path(active) = result.unwrap();
        assert!(active);
    }

    #[test]
    fn path_extract_char() {
        let ctx = test_context();
        let mut req = request_with_params(vec![("letter", "A")]);

        let result = futures_executor::block_on(Path::<char>::from_request(&ctx, &mut req));
        let Path(letter) = result.unwrap();
        assert_eq!(letter, 'A');
    }
}
