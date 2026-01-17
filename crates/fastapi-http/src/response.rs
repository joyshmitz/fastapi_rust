//! HTTP response writer.

use fastapi_core::{Response, ResponseBody, StatusCode};

/// Writes HTTP responses to a buffer.
pub struct ResponseWriter {
    buffer: Vec<u8>,
}

impl ResponseWriter {
    /// Create a new response writer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(4096),
        }
    }

    /// Write a response to the internal buffer.
    pub fn write(&mut self, response: &Response) {
        self.buffer.clear();

        // Status line
        self.buffer.extend_from_slice(b"HTTP/1.1 ");
        self.write_status(response.status());
        self.buffer.extend_from_slice(b"\r\n");

        // Headers
        for (name, value) in response.headers() {
            self.buffer.extend_from_slice(name.as_bytes());
            self.buffer.extend_from_slice(b": ");
            self.buffer.extend_from_slice(value);
            self.buffer.extend_from_slice(b"\r\n");
        }

        // Content-Length
        let body_len = match response.body_ref() {
            ResponseBody::Empty => 0,
            ResponseBody::Bytes(b) => b.len(),
        };

        self.buffer.extend_from_slice(b"content-length: ");
        self.buffer.extend_from_slice(body_len.to_string().as_bytes());
        self.buffer.extend_from_slice(b"\r\n");

        // End of headers
        self.buffer.extend_from_slice(b"\r\n");

        // Body
        if let ResponseBody::Bytes(body) = response.body_ref() {
            self.buffer.extend_from_slice(body);
        }
    }

    fn write_status(&mut self, status: StatusCode) {
        let code = status.as_u16();
        self.buffer.extend_from_slice(code.to_string().as_bytes());
        self.buffer.extend_from_slice(b" ");
        self.buffer.extend_from_slice(status.canonical_reason().as_bytes());
    }

    /// Get the written bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }

    /// Take the buffer.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.buffer
    }
}

impl Default for ResponseWriter {
    fn default() -> Self {
        Self::new()
    }
}
