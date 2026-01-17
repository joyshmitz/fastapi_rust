//! HTTP response types.

use serde::Serialize;

/// HTTP status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StatusCode(u16);

impl StatusCode {
    // Informational
    /// 100 Continue
    pub const CONTINUE: Self = Self(100);
    /// 101 Switching Protocols
    pub const SWITCHING_PROTOCOLS: Self = Self(101);

    // Success
    /// 200 OK
    pub const OK: Self = Self(200);
    /// 201 Created
    pub const CREATED: Self = Self(201);
    /// 202 Accepted
    pub const ACCEPTED: Self = Self(202);
    /// 204 No Content
    pub const NO_CONTENT: Self = Self(204);

    // Redirection
    /// 301 Moved Permanently
    pub const MOVED_PERMANENTLY: Self = Self(301);
    /// 302 Found
    pub const FOUND: Self = Self(302);
    /// 304 Not Modified
    pub const NOT_MODIFIED: Self = Self(304);
    /// 307 Temporary Redirect
    pub const TEMPORARY_REDIRECT: Self = Self(307);
    /// 308 Permanent Redirect
    pub const PERMANENT_REDIRECT: Self = Self(308);

    // Client Error
    /// 400 Bad Request
    pub const BAD_REQUEST: Self = Self(400);
    /// 401 Unauthorized
    pub const UNAUTHORIZED: Self = Self(401);
    /// 403 Forbidden
    pub const FORBIDDEN: Self = Self(403);
    /// 404 Not Found
    pub const NOT_FOUND: Self = Self(404);
    /// 405 Method Not Allowed
    pub const METHOD_NOT_ALLOWED: Self = Self(405);
    /// 422 Unprocessable Entity
    pub const UNPROCESSABLE_ENTITY: Self = Self(422);

    // Server Error
    /// 500 Internal Server Error
    pub const INTERNAL_SERVER_ERROR: Self = Self(500);

    /// Create a status code from a u16.
    #[must_use]
    pub const fn from_u16(code: u16) -> Self {
        Self(code)
    }

    /// Get the numeric value.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Check if status code allows a body.
    #[must_use]
    pub const fn allows_body(self) -> bool {
        !matches!(self.0, 100..=103 | 204 | 304)
    }

    /// Get the canonical reason phrase.
    #[must_use]
    pub const fn canonical_reason(self) -> &'static str {
        match self.0 {
            100 => "Continue",
            101 => "Switching Protocols",
            200 => "OK",
            201 => "Created",
            202 => "Accepted",
            204 => "No Content",
            301 => "Moved Permanently",
            302 => "Found",
            304 => "Not Modified",
            307 => "Temporary Redirect",
            308 => "Permanent Redirect",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            422 => "Unprocessable Entity",
            500 => "Internal Server Error",
            _ => "Unknown",
        }
    }
}

/// Response body.
#[derive(Debug)]
pub enum ResponseBody {
    /// Empty body.
    Empty,
    /// Bytes body.
    Bytes(Vec<u8>),
    // TODO: Stream variant for large responses
}

impl ResponseBody {
    /// Check if body is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Empty) || matches!(self, Self::Bytes(b) if b.is_empty())
    }

    /// Get body length.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::Empty => 0,
            Self::Bytes(b) => b.len(),
        }
    }
}

/// HTTP response.
#[derive(Debug)]
pub struct Response {
    status: StatusCode,
    headers: Vec<(String, Vec<u8>)>,
    body: ResponseBody,
}

impl Response {
    /// Create a response with the given status.
    #[must_use]
    pub fn with_status(status: StatusCode) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: ResponseBody::Empty,
        }
    }

    /// Create a 200 OK response.
    #[must_use]
    pub fn ok() -> Self {
        Self::with_status(StatusCode::OK)
    }

    /// Create a 201 Created response.
    #[must_use]
    pub fn created() -> Self {
        Self::with_status(StatusCode::CREATED)
    }

    /// Create a 204 No Content response.
    #[must_use]
    pub fn no_content() -> Self {
        Self::with_status(StatusCode::NO_CONTENT)
    }

    /// Create a 500 Internal Server Error response.
    #[must_use]
    pub fn internal_error() -> Self {
        Self::with_status(StatusCode::INTERNAL_SERVER_ERROR)
    }

    /// Add a header.
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<Vec<u8>>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Set the body.
    #[must_use]
    pub fn body(mut self, body: ResponseBody) -> Self {
        self.body = body;
        self
    }

    /// Create a JSON response.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn json<T: Serialize>(value: &T) -> Result<Self, serde_json::Error> {
        let bytes = serde_json::to_vec(value)?;
        Ok(Self::ok()
            .header("content-type", b"application/json".to_vec())
            .body(ResponseBody::Bytes(bytes)))
    }

    /// Get the status code.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Get the headers.
    #[must_use]
    pub fn headers(&self) -> &[(String, Vec<u8>)] {
        &self.headers
    }

    /// Get the body.
    #[must_use]
    pub fn body_ref(&self) -> &ResponseBody {
        &self.body
    }
}

/// Trait for types that can be converted into a response.
pub trait IntoResponse {
    /// Convert into a response.
    fn into_response(self) -> Response;
}

impl IntoResponse for Response {
    fn into_response(self) -> Response {
        self
    }
}

impl IntoResponse for () {
    fn into_response(self) -> Response {
        Response::no_content()
    }
}

impl IntoResponse for &'static str {
    fn into_response(self) -> Response {
        Response::ok()
            .header("content-type", b"text/plain; charset=utf-8".to_vec())
            .body(ResponseBody::Bytes(self.as_bytes().to_vec()))
    }
}

impl IntoResponse for String {
    fn into_response(self) -> Response {
        Response::ok()
            .header("content-type", b"text/plain; charset=utf-8".to_vec())
            .body(ResponseBody::Bytes(self.into_bytes()))
    }
}

impl<T: IntoResponse, E: IntoResponse> IntoResponse for Result<T, E> {
    fn into_response(self) -> Response {
        match self {
            Ok(v) => v.into_response(),
            Err(e) => e.into_response(),
        }
    }
}

impl IntoResponse for std::convert::Infallible {
    fn into_response(self) -> Response {
        match self {}
    }
}
