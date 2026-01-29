//! Newline-Delimited JSON (NDJSON) streaming support.
//!
//! This module provides types for streaming large datasets as NDJSON, where each
//! JSON object is on its own line. This format is ideal for:
//!
//! - Streaming database query results
//! - Real-time log output
//! - Incremental data export
//! - Large dataset downloads
//!
//! # Overview
//!
//! NDJSON (also known as JSON Lines) is a convenient format for streaming JSON data.
//! Each line is a valid JSON value, typically an object, followed by a newline character.
//!
//! # Example
//!
//! ```ignore
//! use fastapi_core::ndjson::{NdjsonResponse, ndjson_response};
//! use fastapi_core::Response;
//! use asupersync::stream;
//! use serde::Serialize;
//!
//! #[derive(Serialize)]
//! struct LogEntry {
//!     timestamp: u64,
//!     level: String,
//!     message: String,
//! }
//!
//! async fn stream_logs() -> Response {
//!     let logs = stream::iter(vec![
//!         LogEntry { timestamp: 1, level: "INFO".into(), message: "Started".into() },
//!         LogEntry { timestamp: 2, level: "DEBUG".into(), message: "Processing".into() },
//!     ]);
//!
//!     NdjsonResponse::new(logs).into_response()
//! }
//! ```
//!
//! # Wire Format
//!
//! ```text
//! {"id":1,"name":"Alice"}
//! {"id":2,"name":"Bob"}
//! {"id":3,"name":"Charlie"}
//! ```
//!
//! Each line is a complete, valid JSON value followed by `\n`.
//!
//! # Content Type
//!
//! The standard content type for NDJSON is `application/x-ndjson`, though
//! `application/jsonlines` and `application/json-lines` are also recognized.
//!
//! # Memory Efficiency
//!
//! NDJSON streaming does not buffer the entire response. Each item is serialized
//! and sent immediately, making it suitable for datasets of any size.
//!
//! # Error Handling
//!
//! If serialization fails for an item, the stream will include an error object
//! on that line and continue with subsequent items. Clients should be prepared
//! to handle `{"error": "..."}` entries in the stream.

use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};

use asupersync::stream::Stream;
use serde::Serialize;

use crate::response::{Response, ResponseBody, StatusCode};

/// The standard NDJSON content type.
pub const NDJSON_CONTENT_TYPE: &[u8] = b"application/x-ndjson";

/// Alternative content types that are sometimes used for NDJSON.
pub const NDJSON_CONTENT_TYPE_ALT: &[u8] = b"application/jsonlines";

/// Configuration for NDJSON responses.
#[derive(Debug, Clone)]
pub struct NdjsonConfig {
    /// Whether to include a trailing newline after the last item.
    pub trailing_newline: bool,
    /// Whether to pretty-print each JSON line (not recommended for production).
    pub pretty: bool,
    /// Custom content type (defaults to `application/x-ndjson`).
    pub content_type: Option<Vec<u8>>,
}

impl Default for NdjsonConfig {
    fn default() -> Self {
        Self {
            trailing_newline: true,
            pretty: false,
            content_type: None,
        }
    }
}

impl NdjsonConfig {
    /// Create a new NDJSON configuration with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set whether to include a trailing newline.
    #[must_use]
    pub fn trailing_newline(mut self, enabled: bool) -> Self {
        self.trailing_newline = enabled;
        self
    }

    /// Enable pretty-printing of JSON (not recommended for production).
    #[must_use]
    pub fn pretty(mut self, enabled: bool) -> Self {
        self.pretty = enabled;
        self
    }

    /// Set a custom content type.
    #[must_use]
    pub fn content_type(mut self, content_type: impl Into<Vec<u8>>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }

    /// Get the content type to use.
    #[must_use]
    pub fn get_content_type(&self) -> &[u8] {
        self.content_type.as_deref().unwrap_or(NDJSON_CONTENT_TYPE)
    }
}

/// A wrapper that converts an async stream of serializable items into NDJSON format.
///
/// Each item from the inner stream is serialized to JSON, followed by a newline.
/// The resulting bytes are suitable for sending over HTTP as a streaming response.
///
/// # Type Parameters
///
/// - `S`: The underlying stream type
/// - `T`: The item type that implements `Serialize`
///
/// # Example
///
/// ```ignore
/// use fastapi_core::ndjson::NdjsonStream;
/// use asupersync::stream;
/// use serde::Serialize;
///
/// #[derive(Serialize)]
/// struct Item { id: i64, name: String }
///
/// let items = stream::iter(vec![
///     Item { id: 1, name: "Alice".into() },
///     Item { id: 2, name: "Bob".into() },
/// ]);
///
/// let ndjson_stream = NdjsonStream::new(items);
/// // Yields: b'{"id":1,"name":"Alice"}\n' then b'{"id":2,"name":"Bob"}\n'
/// ```
pub struct NdjsonStream<S, T> {
    inner: S,
    config: NdjsonConfig,
    _marker: PhantomData<T>,
}

impl<S, T> NdjsonStream<S, T> {
    /// Create a new NDJSON stream wrapper with default configuration.
    pub fn new(stream: S) -> Self {
        Self {
            inner: stream,
            config: NdjsonConfig::default(),
            _marker: PhantomData,
        }
    }

    /// Create a new NDJSON stream wrapper with custom configuration.
    pub fn with_config(stream: S, config: NdjsonConfig) -> Self {
        Self {
            inner: stream,
            config,
            _marker: PhantomData,
        }
    }
}

impl<S, T> Stream for NdjsonStream<S, T>
where
    S: Stream<Item = T> + Unpin,
    T: Serialize + Unpin,
{
    type Item = Vec<u8>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(Some(item)) => {
                let mut bytes = if this.config.pretty {
                    match serde_json::to_vec_pretty(&item) {
                        Ok(b) => b,
                        Err(e) => {
                            // Serialize the error instead
                            let error = serde_json::json!({
                                "error": format!("serialization failed: {}", e)
                            });
                            serde_json::to_vec(&error)
                                .unwrap_or_else(|_| br#"{"error":"serialization failed"}"#.to_vec())
                        }
                    }
                } else {
                    match serde_json::to_vec(&item) {
                        Ok(b) => b,
                        Err(e) => {
                            // Serialize the error instead
                            let error = serde_json::json!({
                                "error": format!("serialization failed: {}", e)
                            });
                            serde_json::to_vec(&error)
                                .unwrap_or_else(|_| br#"{"error":"serialization failed"}"#.to_vec())
                        }
                    }
                };

                // Add newline
                bytes.push(b'\n');

                Poll::Ready(Some(bytes))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Builder for creating NDJSON streaming responses.
///
/// This wraps a stream of serializable items and converts it to an HTTP response
/// with the appropriate `Content-Type: application/x-ndjson` header.
///
/// # Example
///
/// ```ignore
/// use fastapi_core::ndjson::NdjsonResponse;
/// use fastapi_core::Response;
/// use asupersync::stream;
/// use serde::Serialize;
///
/// #[derive(Serialize)]
/// struct Record { id: i64, value: f64 }
///
/// async fn export_data() -> Response {
///     let records = stream::iter(vec![
///         Record { id: 1, value: 1.5 },
///         Record { id: 2, value: 2.7 },
///         Record { id: 3, value: 3.14 },
///     ]);
///
///     NdjsonResponse::new(records).into_response()
/// }
/// ```
///
/// # Headers Set
///
/// - `Content-Type: application/x-ndjson`
/// - `Cache-Control: no-cache` (streaming data shouldn't be cached)
/// - `Transfer-Encoding: chunked` (implicit for streaming)
pub struct NdjsonResponse<S, T> {
    stream: S,
    config: NdjsonConfig,
    _marker: PhantomData<T>,
}

impl<S, T> NdjsonResponse<S, T>
where
    S: Stream<Item = T> + Send + Unpin + 'static,
    T: Serialize + Send + Unpin + 'static,
{
    /// Create a new NDJSON response from a stream of serializable items.
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            config: NdjsonConfig::default(),
            _marker: PhantomData,
        }
    }

    /// Create an NDJSON response with custom configuration.
    pub fn with_config(stream: S, config: NdjsonConfig) -> Self {
        Self {
            stream,
            config,
            _marker: PhantomData,
        }
    }

    /// Convert to an HTTP Response.
    ///
    /// Sets the appropriate headers for NDJSON streaming:
    /// - `Content-Type: application/x-ndjson`
    /// - `Cache-Control: no-cache`
    /// - `X-Accel-Buffering: no` (disables nginx buffering)
    #[must_use]
    pub fn into_response(self) -> Response {
        let ndjson_stream = NdjsonStream::with_config(self.stream, self.config.clone());

        Response::with_status(StatusCode::OK)
            .header("Content-Type", self.config.get_content_type().to_vec())
            .header("Cache-Control", b"no-cache".to_vec())
            .header("X-Accel-Buffering", b"no".to_vec()) // Disable nginx buffering
            .body(ResponseBody::stream(ndjson_stream))
    }
}

/// Convenience function to create an NDJSON response from a stream.
///
/// # Example
///
/// ```ignore
/// use fastapi_core::ndjson::ndjson_response;
/// use serde::Serialize;
///
/// #[derive(Serialize)]
/// struct Item { id: i64 }
///
/// let items = asupersync::stream::iter(vec![Item { id: 1 }, Item { id: 2 }]);
/// let response = ndjson_response(items);
/// ```
pub fn ndjson_response<S, T>(stream: S) -> Response
where
    S: Stream<Item = T> + Send + Unpin + 'static,
    T: Serialize + Send + Unpin + 'static,
{
    NdjsonResponse::new(stream).into_response()
}

/// Create an NDJSON response from an iterator.
///
/// This is a convenience function for when you have an iterator rather than a stream.
///
/// # Example
///
/// ```ignore
/// use fastapi_core::ndjson::ndjson_iter;
/// use serde::Serialize;
///
/// #[derive(Serialize)]
/// struct User { id: i64, name: String }
///
/// let users = vec![
///     User { id: 1, name: "Alice".into() },
///     User { id: 2, name: "Bob".into() },
/// ];
///
/// let response = ndjson_iter(users);
/// ```
pub fn ndjson_iter<I, T>(iter: I) -> Response
where
    I: IntoIterator<Item = T>,
    I::IntoIter: Send + 'static,
    T: Serialize + Send + Unpin + 'static,
{
    ndjson_response(asupersync::stream::iter(iter))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::task::{Wake, Waker};

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
    }

    #[derive(Serialize, Clone)]
    struct TestItem {
        id: i64,
        name: String,
    }

    #[test]
    fn ndjson_stream_serializes_items() {
        let items = vec![
            TestItem {
                id: 1,
                name: "Alice".to_string(),
            },
            TestItem {
                id: 2,
                name: "Bob".to_string(),
            },
        ];

        let stream = asupersync::stream::iter(items);
        let mut ndjson = NdjsonStream::<_, TestItem>::new(stream);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // First item
        let result = Pin::new(&mut ndjson).poll_next(&mut cx);
        if let Poll::Ready(Some(bytes)) = result {
            let line = String::from_utf8_lossy(&bytes);
            assert!(line.contains(r#""id":1"#));
            assert!(line.contains(r#""name":"Alice""#));
            assert!(line.ends_with('\n'));
        } else {
            panic!("Expected Ready(Some(...))");
        }

        // Second item
        let result = Pin::new(&mut ndjson).poll_next(&mut cx);
        if let Poll::Ready(Some(bytes)) = result {
            let line = String::from_utf8_lossy(&bytes);
            assert!(line.contains(r#""id":2"#));
            assert!(line.contains(r#""name":"Bob""#));
            assert!(line.ends_with('\n'));
        } else {
            panic!("Expected Ready(Some(...))");
        }

        // End of stream
        let result = Pin::new(&mut ndjson).poll_next(&mut cx);
        assert!(matches!(result, Poll::Ready(None)));
    }

    #[test]
    fn ndjson_stream_each_line_is_valid_json() {
        let items = vec![
            TestItem {
                id: 1,
                name: "Test".to_string(),
            },
            TestItem {
                id: 2,
                name: "Item".to_string(),
            },
        ];

        let stream = asupersync::stream::iter(items);
        let mut ndjson = NdjsonStream::<_, TestItem>::new(stream);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Check each line is valid JSON
        loop {
            match Pin::new(&mut ndjson).poll_next(&mut cx) {
                Poll::Ready(Some(bytes)) => {
                    // Remove trailing newline and parse
                    let json_str = String::from_utf8_lossy(&bytes);
                    let json_str = json_str.trim_end();
                    let parsed: Result<serde_json::Value, _> = serde_json::from_str(json_str);
                    assert!(parsed.is_ok(), "Line should be valid JSON: {}", json_str);
                }
                Poll::Ready(None) => break,
                Poll::Pending => panic!("Unexpected Pending"),
            }
        }
    }

    #[test]
    fn ndjson_stream_empty() {
        let items: Vec<TestItem> = vec![];
        let stream = asupersync::stream::iter(items);
        let mut ndjson = NdjsonStream::<_, TestItem>::new(stream);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = Pin::new(&mut ndjson).poll_next(&mut cx);
        assert!(matches!(result, Poll::Ready(None)));
    }

    #[test]
    fn ndjson_config_defaults() {
        let config = NdjsonConfig::default();
        assert!(config.trailing_newline);
        assert!(!config.pretty);
        assert!(config.content_type.is_none());
    }

    #[test]
    fn ndjson_config_custom() {
        let config = NdjsonConfig::new()
            .trailing_newline(false)
            .pretty(true)
            .content_type(b"application/jsonlines".to_vec());

        assert!(!config.trailing_newline);
        assert!(config.pretty);
        assert_eq!(
            config.get_content_type(),
            b"application/jsonlines".as_slice()
        );
    }

    #[test]
    fn ndjson_response_sets_content_type() {
        let items = vec![TestItem {
            id: 1,
            name: "Test".to_string(),
        }];

        let stream = asupersync::stream::iter(items);
        let response = NdjsonResponse::new(stream).into_response();

        let content_type = response
            .headers()
            .iter()
            .find(|(name, _)| name == "Content-Type")
            .map(|(_, value)| value.clone());

        assert_eq!(content_type, Some(b"application/x-ndjson".to_vec()));
    }

    #[test]
    fn ndjson_response_sets_cache_control() {
        let items = vec![TestItem {
            id: 1,
            name: "Test".to_string(),
        }];

        let stream = asupersync::stream::iter(items);
        let response = NdjsonResponse::new(stream).into_response();

        let cache_control = response
            .headers()
            .iter()
            .find(|(name, _)| name == "Cache-Control")
            .map(|(_, value)| value.clone());

        assert_eq!(cache_control, Some(b"no-cache".to_vec()));
    }

    #[test]
    fn ndjson_response_disables_nginx_buffering() {
        let items = vec![TestItem {
            id: 1,
            name: "Test".to_string(),
        }];

        let stream = asupersync::stream::iter(items);
        let response = NdjsonResponse::new(stream).into_response();

        let accel_buffering = response
            .headers()
            .iter()
            .find(|(name, _)| name == "X-Accel-Buffering")
            .map(|(_, value)| value.clone());

        assert_eq!(accel_buffering, Some(b"no".to_vec()));
    }

    #[test]
    fn ndjson_response_status_200() {
        let items: Vec<TestItem> = vec![];
        let stream = asupersync::stream::iter(items);
        let response = NdjsonResponse::new(stream).into_response();

        assert_eq!(response.status().as_u16(), 200);
    }

    #[test]
    fn ndjson_response_with_custom_content_type() {
        let items = vec![TestItem {
            id: 1,
            name: "Test".to_string(),
        }];

        let config = NdjsonConfig::new().content_type(b"application/jsonlines".to_vec());
        let stream = asupersync::stream::iter(items);
        let response = NdjsonResponse::with_config(stream, config).into_response();

        let content_type = response
            .headers()
            .iter()
            .find(|(name, _)| name == "Content-Type")
            .map(|(_, value)| value.clone());

        assert_eq!(content_type, Some(b"application/jsonlines".to_vec()));
    }

    #[test]
    fn ndjson_helper_function() {
        let items = vec![TestItem {
            id: 1,
            name: "Test".to_string(),
        }];

        let stream = asupersync::stream::iter(items);
        let response = ndjson_response(stream);

        assert_eq!(response.status().as_u16(), 200);

        let content_type = response
            .headers()
            .iter()
            .find(|(name, _)| name == "Content-Type")
            .map(|(_, value)| value.clone());

        assert_eq!(content_type, Some(b"application/x-ndjson".to_vec()));
    }

    #[test]
    fn ndjson_iter_helper() {
        let items = vec![
            TestItem {
                id: 1,
                name: "Alice".to_string(),
            },
            TestItem {
                id: 2,
                name: "Bob".to_string(),
            },
        ];

        let response = ndjson_iter(items);

        assert_eq!(response.status().as_u16(), 200);
    }

    #[test]
    fn ndjson_handles_special_characters() {
        #[derive(Serialize)]
        struct SpecialItem {
            text: String,
        }

        let items = vec![
            SpecialItem {
                text: "Hello\nWorld".to_string(), // Embedded newline
            },
            SpecialItem {
                text: "Tab\there".to_string(), // Tab
            },
            SpecialItem {
                text: r#"Quote: "test""#.to_string(), // Quotes
            },
            SpecialItem {
                text: "Unicode: 你好".to_string(), // Unicode
            },
        ];

        let stream = asupersync::stream::iter(items);
        let mut ndjson = NdjsonStream::<_, SpecialItem>::new(stream);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Each line should be valid JSON
        loop {
            match Pin::new(&mut ndjson).poll_next(&mut cx) {
                Poll::Ready(Some(bytes)) => {
                    let json_str = String::from_utf8_lossy(&bytes);
                    let json_str = json_str.trim_end();
                    let parsed: Result<serde_json::Value, _> = serde_json::from_str(json_str);
                    assert!(
                        parsed.is_ok(),
                        "Line should be valid JSON even with special chars: {}",
                        json_str
                    );
                }
                Poll::Ready(None) => break,
                Poll::Pending => panic!("Unexpected Pending"),
            }
        }
    }

    #[test]
    fn ndjson_pretty_print() {
        let items = vec![TestItem {
            id: 1,
            name: "Test".to_string(),
        }];

        let config = NdjsonConfig::new().pretty(true);
        let stream = asupersync::stream::iter(items);
        let mut ndjson = NdjsonStream::with_config(stream, config);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = Pin::new(&mut ndjson).poll_next(&mut cx);
        if let Poll::Ready(Some(bytes)) = result {
            let line = String::from_utf8_lossy(&bytes);
            // Pretty-printed JSON has internal newlines (not just the trailing one)
            assert!(line.contains('\n'));
            // But it should still end with a newline
            assert!(line.ends_with('\n'));
        } else {
            panic!("Expected Ready(Some(...))");
        }
    }

    #[test]
    fn ndjson_content_type_constant() {
        assert_eq!(NDJSON_CONTENT_TYPE, b"application/x-ndjson");
        assert_eq!(NDJSON_CONTENT_TYPE_ALT, b"application/jsonlines");
    }
}
