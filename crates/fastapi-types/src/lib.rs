//! Shared types for the FastAPI Rust framework.
//!
//! This crate provides fundamental types used across multiple fastapi crates,
//! enabling clean dependency ordering without cycles.

#![forbid(unsafe_code)]

use std::fmt;

/// HTTP method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    /// GET method.
    Get,
    /// POST method.
    Post,
    /// PUT method.
    Put,
    /// DELETE method.
    Delete,
    /// PATCH method.
    Patch,
    /// OPTIONS method.
    Options,
    /// HEAD method.
    Head,
    /// TRACE method.
    Trace,
}

impl Method {
    /// Parse method from bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        match bytes {
            b"GET" => Some(Self::Get),
            b"POST" => Some(Self::Post),
            b"PUT" => Some(Self::Put),
            b"DELETE" => Some(Self::Delete),
            b"PATCH" => Some(Self::Patch),
            b"OPTIONS" => Some(Self::Options),
            b"HEAD" => Some(Self::Head),
            b"TRACE" => Some(Self::Trace),
            _ => None,
        }
    }

    /// Return the canonical uppercase method name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Patch => "PATCH",
            Self::Options => "OPTIONS",
            Self::Head => "HEAD",
            Self::Trace => "TRACE",
        }
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
