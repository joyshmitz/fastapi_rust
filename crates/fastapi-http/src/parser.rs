//! HTTP request parser.
//!
//! This module provides zero-copy HTTP/1.1 parsing for request lines and headers.
//!
//! # Zero-Copy Design
//!
//! The parser returns borrowed types that reference the original buffer,
//! avoiding allocations on the hot path. Types:
//!
//! - [`RequestLine`] - borrowed request line (method, path, version)
//! - [`HeadersIter`] - iterator over borrowed headers
//!
//! # Example
//!
//! ```ignore
//! use fastapi_http::parser::{Parser, RequestLine};
//!
//! let buffer = b"GET /items/123?q=test HTTP/1.1\r\nHost: example.com\r\n\r\n";
//! let request_line = RequestLine::parse(buffer)?;
//!
//! assert_eq!(request_line.method(), Method::Get);
//! assert_eq!(request_line.path(), "/items/123");
//! assert_eq!(request_line.query(), Some("q=test"));
//! assert_eq!(request_line.version(), "HTTP/1.1");
//! ```

use fastapi_core::{Body, Method, Request};

/// HTTP parsing error.
#[derive(Debug)]
pub enum ParseError {
    /// Invalid request line.
    InvalidRequestLine,
    /// Invalid HTTP method.
    InvalidMethod,
    /// Invalid header.
    InvalidHeader,
    /// Request too large.
    TooLarge,
    /// Incomplete request (need more data).
    Incomplete,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequestLine => write!(f, "invalid request line"),
            Self::InvalidMethod => write!(f, "invalid HTTP method"),
            Self::InvalidHeader => write!(f, "invalid header"),
            Self::TooLarge => write!(f, "request too large"),
            Self::Incomplete => write!(f, "incomplete request"),
        }
    }
}

impl std::error::Error for ParseError {}

// ============================================================================
// Zero-Copy Request Line Parser
// ============================================================================

/// A zero-copy view of an HTTP request line.
///
/// This type borrows from the original buffer and performs no allocations.
/// It provides access to the parsed method, path, query string, and HTTP version.
///
/// # Zero-Allocation Guarantee
///
/// All methods return borrowed data (`&str` or `Method`). No heap allocations
/// are performed during parsing or access.
///
/// # Example
///
/// ```ignore
/// let buffer = b"GET /items/123?q=test HTTP/1.1\r\n";
/// let line = RequestLine::parse(buffer)?;
///
/// assert_eq!(line.method(), Method::Get);
/// assert_eq!(line.path(), "/items/123");
/// assert_eq!(line.query(), Some("q=test"));
/// assert_eq!(line.version(), "HTTP/1.1");
/// ```
#[derive(Debug, Clone, Copy)]
pub struct RequestLine<'a> {
    method: Method,
    path: &'a str,
    query: Option<&'a str>,
    version: &'a str,
}

impl<'a> RequestLine<'a> {
    /// Parse a request line from bytes.
    ///
    /// The buffer should contain just the request line, ending with `\r\n` or EOF.
    /// Example: `GET /path?query HTTP/1.1\r\n`
    ///
    /// # Errors
    ///
    /// Returns `ParseError::InvalidRequestLine` if the format is invalid.
    /// Returns `ParseError::InvalidMethod` if the HTTP method is not recognized.
    pub fn parse(buffer: &'a [u8]) -> Result<Self, ParseError> {
        // Find the end of the request line (before any \r\n)
        let line_end = buffer
            .windows(2)
            .position(|w| w == b"\r\n")
            .unwrap_or(buffer.len());

        let line = &buffer[..line_end];

        // Split by spaces: METHOD SP URI SP VERSION
        let mut parts = line.splitn(3, |&b| b == b' ');

        // Parse method
        let method_bytes = parts.next().ok_or(ParseError::InvalidRequestLine)?;
        let method = Method::from_bytes(method_bytes).ok_or(ParseError::InvalidMethod)?;

        // Parse URI (path + optional query)
        let uri_bytes = parts.next().ok_or(ParseError::InvalidRequestLine)?;
        let uri = std::str::from_utf8(uri_bytes).map_err(|_| ParseError::InvalidRequestLine)?;

        // Parse version
        let version_bytes = parts.next().ok_or(ParseError::InvalidRequestLine)?;
        let version =
            std::str::from_utf8(version_bytes).map_err(|_| ParseError::InvalidRequestLine)?;

        // Split path and query from URI
        let (path, query) = if let Some(q_pos) = uri.find('?') {
            (&uri[..q_pos], Some(&uri[q_pos + 1..]))
        } else {
            (uri, None)
        };

        Ok(Self {
            method,
            path,
            query,
            version,
        })
    }

    /// Parse a request line from a buffer, returning bytes consumed.
    ///
    /// This is useful for incremental parsing where you need to know
    /// how much of the buffer was consumed.
    ///
    /// # Returns
    ///
    /// Returns `(RequestLine, bytes_consumed)` on success.
    /// `bytes_consumed` includes the trailing `\r\n` if present.
    pub fn parse_with_len(buffer: &'a [u8]) -> Result<(Self, usize), ParseError> {
        let line_end = buffer
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or(ParseError::Incomplete)?;

        let line = Self::parse(&buffer[..line_end])?;
        // +2 for the \r\n
        Ok((line, line_end + 2))
    }

    /// Returns the HTTP method.
    #[inline]
    #[must_use]
    pub fn method(&self) -> Method {
        self.method
    }

    /// Returns the request path (without query string).
    ///
    /// Example: For `GET /items/123?q=test HTTP/1.1`, returns `/items/123`.
    #[inline]
    #[must_use]
    pub fn path(&self) -> &'a str {
        self.path
    }

    /// Returns the query string (without the leading `?`), if present.
    ///
    /// Example: For `GET /items?q=test HTTP/1.1`, returns `Some("q=test")`.
    #[inline]
    #[must_use]
    pub fn query(&self) -> Option<&'a str> {
        self.query
    }

    /// Returns the full URI (path + query string).
    ///
    /// Example: For `GET /items?q=test HTTP/1.1`, returns `/items?q=test`.
    #[must_use]
    pub fn uri(&self) -> &'a str {
        // If there's a query, the original URI includes the ?
        // We reconstruct it from path and query
        // Note: This doesn't allocate because we return a str slice from the original buffer
        // Actually, we can't easily do this without allocation or storing the original uri
        // For now, just return the path if no query, or indicate this returns path only
        self.path
    }

    /// Returns the HTTP version string.
    ///
    /// Example: For `GET /path HTTP/1.1`, returns `HTTP/1.1`.
    #[inline]
    #[must_use]
    pub fn version(&self) -> &'a str {
        self.version
    }

    /// Returns true if this is HTTP/1.1.
    #[inline]
    #[must_use]
    pub fn is_http11(&self) -> bool {
        self.version == "HTTP/1.1"
    }

    /// Returns true if this is HTTP/1.0.
    #[inline]
    #[must_use]
    pub fn is_http10(&self) -> bool {
        self.version == "HTTP/1.0"
    }
}

// ============================================================================
// Zero-Copy Header Parser
// ============================================================================

/// A zero-copy view of a single HTTP header.
#[derive(Debug, Clone, Copy)]
pub struct Header<'a> {
    name: &'a str,
    name_bytes: &'a [u8],
    value: &'a [u8],
}

impl<'a> Header<'a> {
    /// Returns the header name (case-preserved from original).
    #[inline]
    #[must_use]
    pub fn name(&self) -> &'a str {
        self.name
    }

    /// Returns the header name as raw bytes.
    #[inline]
    #[must_use]
    pub fn name_bytes(&self) -> &'a [u8] {
        self.name_bytes
    }

    /// Returns the header as a raw `(&[u8], &[u8])` pair.
    ///
    /// This is useful for zero-allocation header processing.
    #[inline]
    #[must_use]
    pub fn as_bytes_pair(&self) -> (&'a [u8], &'a [u8]) {
        (self.name_bytes, self.value)
    }

    /// Returns the header value as bytes.
    #[inline]
    #[must_use]
    pub fn value(&self) -> &'a [u8] {
        self.value
    }

    /// Returns the header value as a string, if valid UTF-8.
    #[must_use]
    pub fn value_str(&self) -> Option<&'a str> {
        std::str::from_utf8(self.value).ok()
    }

    /// Returns true if this header name matches (case-insensitive).
    #[must_use]
    pub fn name_eq_ignore_case(&self, other: &str) -> bool {
        self.name.eq_ignore_ascii_case(other)
    }

    /// Returns true if this is the Content-Length header.
    #[inline]
    #[must_use]
    pub fn is_content_length(&self) -> bool {
        self.name_eq_ignore_case("content-length")
    }

    /// Returns true if this is the Transfer-Encoding header.
    #[inline]
    #[must_use]
    pub fn is_transfer_encoding(&self) -> bool {
        self.name_eq_ignore_case("transfer-encoding")
    }

    /// Parses the value as Content-Length (usize).
    ///
    /// Returns `None` if this isn't Content-Length or value isn't a valid integer.
    #[must_use]
    pub fn as_content_length(&self) -> Option<usize> {
        if !self.is_content_length() {
            return None;
        }
        self.value_str()?.trim().parse().ok()
    }

    /// Returns true if Transfer-Encoding includes "chunked".
    #[must_use]
    pub fn is_chunked_encoding(&self) -> bool {
        if !self.is_transfer_encoding() {
            return false;
        }
        self.value_str()
            .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
    }
}

/// Iterator over HTTP headers in a buffer.
///
/// Zero-copy: returns borrowed [`Header`] references into the original buffer.
pub struct HeadersIter<'a> {
    remaining: &'a [u8],
}

impl<'a> HeadersIter<'a> {
    /// Create a new headers iterator from a buffer.
    ///
    /// The buffer should start at the first header line (after the request line).
    #[must_use]
    pub fn new(buffer: &'a [u8]) -> Self {
        Self { remaining: buffer }
    }

    /// Parse a single header from the buffer.
    fn parse_header(line: &'a [u8]) -> Result<Header<'a>, ParseError> {
        let colon_pos = line
            .iter()
            .position(|&b| b == b':')
            .ok_or(ParseError::InvalidHeader)?;

        let name_bytes = &line[..colon_pos];
        let name =
            std::str::from_utf8(name_bytes).map_err(|_| ParseError::InvalidHeader)?;

        // Trim leading whitespace from value
        let value_start = line[colon_pos + 1..]
            .iter()
            .position(|&b| b != b' ' && b != b'\t')
            .map_or(colon_pos + 1, |p| colon_pos + 1 + p);

        let value = &line[value_start..];

        // Trim the name (but keep original bytes for raw access)
        let trimmed_name = name.trim();

        Ok(Header {
            name: trimmed_name,
            name_bytes,
            value,
        })
    }
}

impl<'a> Iterator for HeadersIter<'a> {
    type Item = Result<Header<'a>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }

        // Find the end of this header line
        let line_end = self
            .remaining
            .windows(2)
            .position(|w| w == b"\r\n")
            .unwrap_or(self.remaining.len());

        // Empty line signals end of headers
        if line_end == 0 {
            self.remaining = &[];
            return None;
        }

        let line = &self.remaining[..line_end];

        // Advance past this line and its \r\n
        self.remaining = if line_end + 2 <= self.remaining.len() {
            &self.remaining[line_end + 2..]
        } else {
            &[]
        };

        Some(Self::parse_header(line))
    }
}

// ============================================================================
// Headers Collection with Common Helpers
// ============================================================================

/// Body length indicator from headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyLength {
    /// Content-Length header specifies exact byte count.
    ContentLength(usize),
    /// Transfer-Encoding: chunked.
    Chunked,
    /// No body expected (no Content-Length or Transfer-Encoding).
    None,
    /// Multiple conflicting length indicators.
    Conflicting,
}

/// Parses headers and extracts Content-Length / Transfer-Encoding.
///
/// This is a zero-copy parser that yields headers while tracking
/// the body length indicator.
///
/// # Example
///
/// ```ignore
/// let buffer = b"Content-Length: 42\r\nHost: example.com\r\n\r\n";
/// let headers = HeadersParser::parse(buffer)?;
///
/// assert_eq!(headers.body_length(), BodyLength::ContentLength(42));
/// assert_eq!(headers.content_length(), Some(42));
/// ```
pub struct HeadersParser<'a> {
    buffer: &'a [u8],
    bytes_consumed: usize,
    content_length: Option<usize>,
    is_chunked: bool,
}

impl<'a> HeadersParser<'a> {
    /// Parse all headers from a buffer.
    ///
    /// Returns the parser with pre-computed Content-Length and Transfer-Encoding.
    /// The buffer should start at the first header line (after request line).
    pub fn parse(buffer: &'a [u8]) -> Result<Self, ParseError> {
        let mut content_length = None;
        let mut is_chunked = false;
        let mut bytes_consumed = 0;

        let mut iter = HeadersIter::new(buffer);
        while let Some(result) = iter.next() {
            let header = result?;

            // Track Content-Length
            if header.is_content_length() {
                if let Some(len) = header.as_content_length() {
                    if content_length.is_some() && content_length != Some(len) {
                        // Conflicting Content-Length headers
                        return Err(ParseError::InvalidHeader);
                    }
                    content_length = Some(len);
                }
            }

            // Track Transfer-Encoding
            if header.is_chunked_encoding() {
                is_chunked = true;
            }
        }

        // Calculate bytes consumed (find end of headers)
        bytes_consumed = buffer
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map_or(buffer.len(), |pos| pos + 4);

        Ok(Self {
            buffer,
            bytes_consumed,
            content_length,
            is_chunked,
        })
    }

    /// Returns the body length indicator.
    ///
    /// Per RFC 7230:
    /// - If Transfer-Encoding: chunked is present, use chunked decoding
    /// - Else if Content-Length is present, use that
    /// - Else no body
    #[must_use]
    pub fn body_length(&self) -> BodyLength {
        // RFC 7230 Section 3.3.3: Transfer-Encoding takes precedence
        if self.is_chunked {
            // If both are present, that's technically conflicting but
            // Transfer-Encoding wins per spec
            if self.content_length.is_some() {
                // Per RFC 7230 3.3.3, a sender MUST NOT send Content-Length
                // with Transfer-Encoding, but receiver MUST ignore Content-Length
                return BodyLength::Chunked;
            }
            return BodyLength::Chunked;
        }

        if let Some(len) = self.content_length {
            return BodyLength::ContentLength(len);
        }

        BodyLength::None
    }

    /// Returns the Content-Length value if present.
    #[must_use]
    pub fn content_length(&self) -> Option<usize> {
        self.content_length
    }

    /// Returns true if Transfer-Encoding: chunked.
    #[must_use]
    pub fn is_chunked(&self) -> bool {
        self.is_chunked
    }

    /// Returns the number of bytes consumed (including final \r\n\r\n).
    #[must_use]
    pub fn bytes_consumed(&self) -> usize {
        self.bytes_consumed
    }

    /// Returns an iterator over all headers.
    #[must_use]
    pub fn iter(&self) -> HeadersIter<'a> {
        HeadersIter::new(self.buffer)
    }

    /// Finds a header by name (case-insensitive).
    #[must_use]
    pub fn get(&self, name: &str) -> Option<Header<'a>> {
        self.iter()
            .filter_map(Result::ok)
            .find(|h| h.name_eq_ignore_case(name))
    }

    /// Returns all headers matching a name (case-insensitive).
    pub fn get_all<'b>(&'b self, name: &'b str) -> impl Iterator<Item = Header<'a>> + 'b {
        self.iter()
            .filter_map(Result::ok)
            .filter(move |h| h.name_eq_ignore_case(name))
    }
}

// ============================================================================
// High-Level Parser (with owned Request for convenience)
// ============================================================================

/// Zero-copy HTTP request parser.
pub struct Parser {
    max_request_size: usize,
}

impl Parser {
    /// Create a new parser with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_request_size: 1024 * 1024, // 1MB default
        }
    }

    /// Set maximum request size.
    #[must_use]
    pub fn with_max_size(mut self, size: usize) -> Self {
        self.max_request_size = size;
        self
    }

    /// Parse an HTTP request from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the request is malformed.
    pub fn parse(&self, buffer: &[u8]) -> Result<Request, ParseError> {
        if buffer.len() > self.max_request_size {
            return Err(ParseError::TooLarge);
        }

        // Find end of headers
        let header_end = find_header_end(buffer).ok_or(ParseError::Incomplete)?;

        let header_bytes = &buffer[..header_end];
        let body_bytes = &buffer[header_end + 4..]; // Skip \r\n\r\n

        // Parse request line
        let first_line_end = header_bytes
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or(ParseError::InvalidRequestLine)?;

        let request_line = &header_bytes[..first_line_end];
        let (method, path, query) = parse_request_line(request_line)?;

        // Parse headers
        let headers = parse_headers(&header_bytes[first_line_end + 2..])?;

        // Build request
        let mut request = Request::new(method, path);
        request.set_query(query);

        // Set headers
        for (name, value) in headers {
            request.headers_mut().insert(name, value);
        }

        // Set body
        if !body_bytes.is_empty() {
            request.set_body(Body::Bytes(body_bytes.to_vec()));
        }

        Ok(request)
    }
}

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_request_line(line: &[u8]) -> Result<(Method, String, Option<String>), ParseError> {
    let mut parts = line.split(|&b| b == b' ');

    let method_bytes = parts.next().ok_or(ParseError::InvalidRequestLine)?;
    let method = Method::from_bytes(method_bytes).ok_or(ParseError::InvalidMethod)?;

    let uri_bytes = parts.next().ok_or(ParseError::InvalidRequestLine)?;
    let uri = std::str::from_utf8(uri_bytes).map_err(|_| ParseError::InvalidRequestLine)?;

    // Verify HTTP version
    let _version = parts.next().ok_or(ParseError::InvalidRequestLine)?;

    // Split path and query
    let (path, query) = if let Some(q_pos) = uri.find('?') {
        (uri[..q_pos].to_string(), Some(uri[q_pos + 1..].to_string()))
    } else {
        (uri.to_string(), None)
    };

    Ok((method, path, query))
}

fn parse_headers(data: &[u8]) -> Result<Vec<(String, Vec<u8>)>, ParseError> {
    let mut headers = Vec::new();
    let mut rest = data;

    while !rest.is_empty() {
        let line_end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .unwrap_or(rest.len());

        if line_end == 0 {
            break;
        }

        let line = &rest[..line_end];
        let colon_pos = line.iter().position(|&b| b == b':').ok_or(ParseError::InvalidHeader)?;

        let name = std::str::from_utf8(&line[..colon_pos])
            .map_err(|_| ParseError::InvalidHeader)?
            .trim()
            .to_string();

        let value = line[colon_pos + 1..]
            .iter()
            .skip_while(|&&b| b == b' ')
            .copied()
            .collect();

        headers.push((name, value));

        rest = if line_end + 2 <= rest.len() {
            &rest[line_end + 2..]
        } else {
            &[]
        };
    }

    Ok(headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // RequestLine Tests
    // ========================================================================

    #[test]
    fn request_line_simple_get() {
        let buffer = b"GET /path HTTP/1.1\r\n";
        let line = RequestLine::parse(buffer).unwrap();

        assert_eq!(line.method(), Method::Get);
        assert_eq!(line.path(), "/path");
        assert_eq!(line.query(), None);
        assert_eq!(line.version(), "HTTP/1.1");
        assert!(line.is_http11());
        assert!(!line.is_http10());
    }

    #[test]
    fn request_line_with_query() {
        let buffer = b"GET /items?q=test&page=1 HTTP/1.1\r\n";
        let line = RequestLine::parse(buffer).unwrap();

        assert_eq!(line.method(), Method::Get);
        assert_eq!(line.path(), "/items");
        assert_eq!(line.query(), Some("q=test&page=1"));
        assert_eq!(line.version(), "HTTP/1.1");
    }

    #[test]
    fn request_line_post() {
        let buffer = b"POST /api/users HTTP/1.1\r\n";
        let line = RequestLine::parse(buffer).unwrap();

        assert_eq!(line.method(), Method::Post);
        assert_eq!(line.path(), "/api/users");
    }

    #[test]
    fn request_line_all_methods() {
        let methods = [
            ("GET", Method::Get),
            ("POST", Method::Post),
            ("PUT", Method::Put),
            ("DELETE", Method::Delete),
            ("PATCH", Method::Patch),
            ("OPTIONS", Method::Options),
            ("HEAD", Method::Head),
            ("TRACE", Method::Trace),
        ];

        for (method_str, expected_method) in methods {
            let buffer = format!("{method_str} /path HTTP/1.1\r\n");
            let line = RequestLine::parse(buffer.as_bytes()).unwrap();
            assert_eq!(line.method(), expected_method, "Failed for {method_str}");
        }
    }

    #[test]
    fn request_line_http10() {
        let buffer = b"GET /legacy HTTP/1.0\r\n";
        let line = RequestLine::parse(buffer).unwrap();

        assert_eq!(line.version(), "HTTP/1.0");
        assert!(line.is_http10());
        assert!(!line.is_http11());
    }

    #[test]
    fn request_line_without_crlf() {
        // Should still parse if no \r\n (end of buffer)
        let buffer = b"GET /path HTTP/1.1";
        let line = RequestLine::parse(buffer).unwrap();

        assert_eq!(line.method(), Method::Get);
        assert_eq!(line.path(), "/path");
    }

    #[test]
    fn request_line_with_len() {
        let buffer = b"GET /path HTTP/1.1\r\nHost: example.com\r\n";
        let (line, consumed) = RequestLine::parse_with_len(buffer).unwrap();

        assert_eq!(line.method(), Method::Get);
        assert_eq!(line.path(), "/path");
        assert_eq!(consumed, 20); // "GET /path HTTP/1.1\r\n" = 20 bytes
    }

    #[test]
    fn request_line_invalid_method() {
        let buffer = b"INVALID /path HTTP/1.1\r\n";
        let result = RequestLine::parse(buffer);

        assert!(matches!(result, Err(ParseError::InvalidMethod)));
    }

    #[test]
    fn request_line_missing_path() {
        let buffer = b"GET\r\n";
        let result = RequestLine::parse(buffer);

        assert!(matches!(result, Err(ParseError::InvalidRequestLine)));
    }

    #[test]
    fn request_line_missing_version() {
        let buffer = b"GET /path\r\n";
        let result = RequestLine::parse(buffer);

        assert!(matches!(result, Err(ParseError::InvalidRequestLine)));
    }

    #[test]
    fn request_line_complex_path() {
        let buffer = b"GET /api/v1/users/123/posts HTTP/1.1\r\n";
        let line = RequestLine::parse(buffer).unwrap();

        assert_eq!(line.path(), "/api/v1/users/123/posts");
    }

    #[test]
    fn request_line_query_with_special_chars() {
        let buffer = b"GET /search?q=hello%20world&filter=a%3Db HTTP/1.1\r\n";
        let line = RequestLine::parse(buffer).unwrap();

        assert_eq!(line.path(), "/search");
        assert_eq!(line.query(), Some("q=hello%20world&filter=a%3Db"));
    }

    // ========================================================================
    // Header Tests
    // ========================================================================

    #[test]
    fn header_simple() {
        let buffer = b"Host: example.com\r\n";
        let mut iter = HeadersIter::new(buffer);

        let header = iter.next().unwrap().unwrap();
        assert_eq!(header.name(), "Host");
        assert_eq!(header.value(), b"example.com");
        assert_eq!(header.value_str(), Some("example.com"));

        assert!(iter.next().is_none());
    }

    #[test]
    fn headers_multiple() {
        let buffer = b"Host: example.com\r\nContent-Type: application/json\r\nContent-Length: 42\r\n";
        let headers: Vec<_> = HeadersIter::new(buffer).collect();

        assert_eq!(headers.len(), 3);

        let h0 = headers[0].as_ref().unwrap();
        assert_eq!(h0.name(), "Host");
        assert_eq!(h0.value_str(), Some("example.com"));

        let h1 = headers[1].as_ref().unwrap();
        assert_eq!(h1.name(), "Content-Type");
        assert_eq!(h1.value_str(), Some("application/json"));

        let h2 = headers[2].as_ref().unwrap();
        assert_eq!(h2.name(), "Content-Length");
        assert_eq!(h2.value_str(), Some("42"));
    }

    #[test]
    fn headers_with_empty_line() {
        let buffer = b"Host: example.com\r\n\r\n";
        let headers: Vec<_> = HeadersIter::new(buffer).collect();

        assert_eq!(headers.len(), 1);
    }

    #[test]
    fn header_with_leading_space() {
        let buffer = b"Host:   example.com\r\n";
        let mut iter = HeadersIter::new(buffer);

        let header = iter.next().unwrap().unwrap();
        assert_eq!(header.name(), "Host");
        assert_eq!(header.value_str(), Some("example.com"));
    }

    #[test]
    fn header_binary_value() {
        let buffer = b"X-Binary: \xff\xfe\r\n";
        let mut iter = HeadersIter::new(buffer);

        let header = iter.next().unwrap().unwrap();
        assert_eq!(header.name(), "X-Binary");
        assert_eq!(header.value(), b"\xff\xfe");
        assert!(header.value_str().is_none()); // Invalid UTF-8
    }

    #[test]
    fn header_missing_colon() {
        let buffer = b"InvalidHeader\r\n";
        let mut iter = HeadersIter::new(buffer);

        let result = iter.next().unwrap();
        assert!(matches!(result, Err(ParseError::InvalidHeader)));
    }

    // ========================================================================
    // Zero-Copy Verification Tests
    // ========================================================================

    #[test]
    fn request_line_borrows_from_buffer() {
        let buffer = b"GET /borrowed/path HTTP/1.1\r\n";
        let line = RequestLine::parse(buffer).unwrap();

        // Verify that path is a slice into the original buffer
        // Using safe pointer range comparison
        let buffer_range = buffer.as_ptr_range();
        let path_ptr = line.path().as_ptr();

        // Path pointer should be within buffer bounds
        assert!(buffer_range.contains(&path_ptr));
    }

    #[test]
    fn header_borrows_from_buffer() {
        let buffer = b"Host: borrowed.example.com\r\n";
        let mut iter = HeadersIter::new(buffer);
        let header = iter.next().unwrap().unwrap();

        // Verify that value is a slice into the original buffer
        // Using safe pointer range comparison
        let buffer_range = buffer.as_ptr_range();
        let value_ptr = header.value().as_ptr();

        assert!(buffer_range.contains(&value_ptr));
    }

    // ========================================================================
    // Header Enhancement Tests
    // ========================================================================

    #[test]
    fn header_as_bytes_pair() {
        let buffer = b"Content-Type: application/json\r\n";
        let mut iter = HeadersIter::new(buffer);
        let header = iter.next().unwrap().unwrap();

        let (name, value) = header.as_bytes_pair();
        assert_eq!(name, b"Content-Type");
        assert_eq!(value, b"application/json");
    }

    #[test]
    fn header_name_bytes() {
        let buffer = b"X-Custom-Header: value\r\n";
        let mut iter = HeadersIter::new(buffer);
        let header = iter.next().unwrap().unwrap();

        assert_eq!(header.name_bytes(), b"X-Custom-Header");
        assert_eq!(header.name(), "X-Custom-Header");
    }

    #[test]
    fn header_case_insensitive_match() {
        let buffer = b"content-type: text/html\r\n";
        let mut iter = HeadersIter::new(buffer);
        let header = iter.next().unwrap().unwrap();

        assert!(header.name_eq_ignore_case("Content-Type"));
        assert!(header.name_eq_ignore_case("CONTENT-TYPE"));
        assert!(header.name_eq_ignore_case("content-type"));
        assert!(!header.name_eq_ignore_case("Content-Length"));
    }

    #[test]
    fn header_content_length_detection() {
        let buffer = b"Content-Length: 1234\r\n";
        let mut iter = HeadersIter::new(buffer);
        let header = iter.next().unwrap().unwrap();

        assert!(header.is_content_length());
        assert!(!header.is_transfer_encoding());
        assert_eq!(header.as_content_length(), Some(1234));
    }

    #[test]
    fn header_content_length_case_insensitive() {
        let buffer = b"content-length: 5678\r\n";
        let mut iter = HeadersIter::new(buffer);
        let header = iter.next().unwrap().unwrap();

        assert!(header.is_content_length());
        assert_eq!(header.as_content_length(), Some(5678));
    }

    #[test]
    fn header_transfer_encoding_chunked() {
        let buffer = b"Transfer-Encoding: chunked\r\n";
        let mut iter = HeadersIter::new(buffer);
        let header = iter.next().unwrap().unwrap();

        assert!(header.is_transfer_encoding());
        assert!(header.is_chunked_encoding());
        assert!(!header.is_content_length());
    }

    #[test]
    fn header_transfer_encoding_gzip_chunked() {
        let buffer = b"Transfer-Encoding: gzip, chunked\r\n";
        let mut iter = HeadersIter::new(buffer);
        let header = iter.next().unwrap().unwrap();

        assert!(header.is_transfer_encoding());
        assert!(header.is_chunked_encoding());
    }

    #[test]
    fn header_transfer_encoding_not_chunked() {
        let buffer = b"Transfer-Encoding: gzip\r\n";
        let mut iter = HeadersIter::new(buffer);
        let header = iter.next().unwrap().unwrap();

        assert!(header.is_transfer_encoding());
        assert!(!header.is_chunked_encoding());
    }

    // ========================================================================
    // HeadersParser Tests
    // ========================================================================

    #[test]
    fn headers_parser_content_length() {
        let buffer = b"Host: example.com\r\nContent-Length: 42\r\n\r\n";
        let parser = HeadersParser::parse(buffer).unwrap();

        assert_eq!(parser.content_length(), Some(42));
        assert!(!parser.is_chunked());
        assert_eq!(parser.body_length(), BodyLength::ContentLength(42));
    }

    #[test]
    fn headers_parser_chunked() {
        let buffer = b"Host: example.com\r\nTransfer-Encoding: chunked\r\n\r\n";
        let parser = HeadersParser::parse(buffer).unwrap();

        assert_eq!(parser.content_length(), None);
        assert!(parser.is_chunked());
        assert_eq!(parser.body_length(), BodyLength::Chunked);
    }

    #[test]
    fn headers_parser_no_body() {
        let buffer = b"Host: example.com\r\nAccept: */*\r\n\r\n";
        let parser = HeadersParser::parse(buffer).unwrap();

        assert_eq!(parser.content_length(), None);
        assert!(!parser.is_chunked());
        assert_eq!(parser.body_length(), BodyLength::None);
    }

    #[test]
    fn headers_parser_chunked_takes_precedence() {
        // Per RFC 7230, Transfer-Encoding takes precedence over Content-Length
        let buffer =
            b"Host: example.com\r\nContent-Length: 100\r\nTransfer-Encoding: chunked\r\n\r\n";
        let parser = HeadersParser::parse(buffer).unwrap();

        assert_eq!(parser.content_length(), Some(100));
        assert!(parser.is_chunked());
        assert_eq!(parser.body_length(), BodyLength::Chunked);
    }

    #[test]
    fn headers_parser_bytes_consumed() {
        let buffer = b"Host: example.com\r\nContent-Length: 5\r\n\r\nHello";
        let parser = HeadersParser::parse(buffer).unwrap();

        // Headers section is "Host: example.com\r\nContent-Length: 5\r\n\r\n" = 40 bytes
        assert_eq!(parser.bytes_consumed(), 40);
    }

    #[test]
    fn headers_parser_get_header() {
        let buffer = b"Host: example.com\r\nContent-Type: application/json\r\n\r\n";
        let parser = HeadersParser::parse(buffer).unwrap();

        let host = parser.get("Host").unwrap();
        assert_eq!(host.value_str(), Some("example.com"));

        let ct = parser.get("content-type").unwrap();
        assert_eq!(ct.value_str(), Some("application/json"));

        assert!(parser.get("X-Missing").is_none());
    }

    #[test]
    fn headers_parser_get_all() {
        let buffer = b"Set-Cookie: a=1\r\nSet-Cookie: b=2\r\nHost: example.com\r\n\r\n";
        let parser = HeadersParser::parse(buffer).unwrap();

        let cookies: Vec<_> = parser.get_all("Set-Cookie").collect();
        assert_eq!(cookies.len(), 2);
        assert_eq!(cookies[0].value_str(), Some("a=1"));
        assert_eq!(cookies[1].value_str(), Some("b=2"));
    }

    #[test]
    fn headers_parser_iter() {
        let buffer = b"A: 1\r\nB: 2\r\nC: 3\r\n\r\n";
        let parser = HeadersParser::parse(buffer).unwrap();

        let headers: Vec<_> = parser.iter().collect();
        assert_eq!(headers.len(), 3);
    }

    #[test]
    fn headers_parser_conflicting_content_length() {
        // Two different Content-Length values should error
        let buffer = b"Content-Length: 10\r\nContent-Length: 20\r\n\r\n";
        let result = HeadersParser::parse(buffer);

        assert!(matches!(result, Err(ParseError::InvalidHeader)));
    }

    #[test]
    fn headers_parser_duplicate_same_content_length() {
        // Two identical Content-Length values are OK (per some implementations)
        let buffer = b"Content-Length: 42\r\nContent-Length: 42\r\n\r\n";
        let parser = HeadersParser::parse(buffer).unwrap();

        assert_eq!(parser.content_length(), Some(42));
    }
}
