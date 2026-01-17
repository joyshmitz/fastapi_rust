//! Error types.

use crate::response::{IntoResponse, Response, ResponseBody, StatusCode};
use serde::Serialize;

/// HTTP error that produces a response.
#[derive(Debug)]
pub struct HttpError {
    /// Status code.
    pub status: StatusCode,
    /// Error detail message.
    pub detail: Option<String>,
    /// Additional headers.
    pub headers: Vec<(String, Vec<u8>)>,
}

impl HttpError {
    /// Create a new HTTP error.
    #[must_use]
    pub fn new(status: StatusCode) -> Self {
        Self {
            status,
            detail: None,
            headers: Vec::new(),
        }
    }

    /// Add a detail message.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Add a header.
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<Vec<u8>>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Create a 400 Bad Request error.
    #[must_use]
    pub fn bad_request() -> Self {
        Self::new(StatusCode::BAD_REQUEST)
    }

    /// Create a 401 Unauthorized error.
    #[must_use]
    pub fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED)
    }

    /// Create a 403 Forbidden error.
    #[must_use]
    pub fn forbidden() -> Self {
        Self::new(StatusCode::FORBIDDEN)
    }

    /// Create a 404 Not Found error.
    #[must_use]
    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND)
    }

    /// Create a 500 Internal Server Error.
    #[must_use]
    pub fn internal() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        #[derive(Serialize)]
        struct ErrorBody<'a> {
            detail: &'a str,
        }

        let detail = self
            .detail
            .as_deref()
            .unwrap_or_else(|| self.status.canonical_reason());

        let body = serde_json::to_vec(&ErrorBody { detail }).unwrap_or_default();

        let mut response = Response::with_status(self.status)
            .header("content-type", b"application/json".to_vec())
            .body(ResponseBody::Bytes(body));

        for (name, value) in self.headers {
            response = response.header(name, value);
        }

        response
    }
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.status.canonical_reason())?;
        if let Some(ref detail) = self.detail {
            write!(f, ": {detail}")?;
        }
        Ok(())
    }
}

impl std::error::Error for HttpError {}

/// A single validation error.
#[derive(Debug, Serialize)]
pub struct ValidationError {
    /// Error type identifier.
    #[serde(rename = "type")]
    pub error_type: &'static str,
    /// Location path (e.g., ["body", "email"]).
    pub loc: Vec<String>,
    /// Human-readable message.
    pub msg: String,
    /// The input value that failed validation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<serde_json::Value>,
    /// Additional context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ctx: Option<serde_json::Value>,
}

/// Collection of validation errors (422 response).
#[derive(Debug)]
pub struct ValidationErrors(pub Vec<ValidationError>);

impl ValidationErrors {
    /// Create empty validation errors.
    #[must_use]
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Add an error.
    pub fn push(&mut self, error: ValidationError) {
        self.0.push(error);
    }

    /// Check if there are any errors.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Default for ValidationErrors {
    fn default() -> Self {
        Self::new()
    }
}

impl IntoResponse for ValidationErrors {
    fn into_response(self) -> Response {
        #[derive(Serialize)]
        struct Body<'a> {
            detail: &'a [ValidationError],
        }

        let body = serde_json::to_vec(&Body { detail: &self.0 }).unwrap_or_default();

        Response::with_status(StatusCode::UNPROCESSABLE_ENTITY)
            .header("content-type", b"application/json".to_vec())
            .body(ResponseBody::Bytes(body))
    }
}
