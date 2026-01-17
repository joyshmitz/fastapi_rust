//! HTTP server.
//!
//! Note: This module requires asupersync for async I/O.
//! Currently provides placeholder types.

use crate::parser::{ParseError, Parser};
use crate::response::ResponseWriter;
use fastapi_core::{Request, Response};

/// HTTP server configuration.
pub struct Server {
    parser: Parser,
}

impl Server {
    /// Create a new server.
    #[must_use]
    pub fn new() -> Self {
        Self {
            parser: Parser::new(),
        }
    }

    /// Parse a request from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the request is malformed.
    pub fn parse_request(&self, bytes: &[u8]) -> Result<Request, ParseError> {
        self.parser.parse(bytes)
    }

    /// Write a response to bytes.
    #[must_use]
    pub fn write_response(&self, response: &Response) -> Vec<u8> {
        let mut writer = ResponseWriter::new();
        writer.write(response);
        writer.into_bytes()
    }
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

// TODO: Async server implementation with asupersync
// When asupersync TCP support is ready:
//
// pub async fn serve(
//     cx: &Cx,
//     addr: &str,
//     handler: impl Fn(&Cx, Request) -> impl Future<Output = Response>,
// ) -> Outcome<(), Error> {
//     let listener = TcpListener::bind(cx, addr).await?;
//     loop {
//         let (stream, _) = listener.accept(cx).await?;
//         cx.spawn(handle_connection(cx, stream, &handler));
//     }
// }
