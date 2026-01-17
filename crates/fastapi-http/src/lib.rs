//! Zero-copy HTTP/1.1 parser.
//!
//! This crate provides a minimal, zero-copy HTTP parser optimized for
//! the fastapi_rust framework. It parses directly from byte buffers
//! without allocating for most operations.
//!
//! # Features
//!
//! - Zero-copy request parsing
//! - HTTP/1.1 compliance (subset)
//! - Response building with pre-allocated buffers
//!
//! # Example
//!
//! ```ignore
//! use fastapi_http::Parser;
//!
//! let bytes = b"GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n";
//! let request = Parser::parse(bytes)?;
//! ```

#![forbid(unsafe_code)]

mod parser;
mod response;
mod server;

pub use parser::{BodyLength, Header, HeadersIter, HeadersParser, ParseError, Parser, RequestLine};
pub use response::ResponseWriter;
pub use server::Server;
