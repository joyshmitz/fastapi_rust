//! Core types and traits for fastapi_rust.
//!
//! This crate provides the fundamental building blocks:
//! - [`Request`] and [`Response`] types
//! - [`RequestContext`] wrapping asupersync's [`Cx`](asupersync::Cx)
//! - [`FromRequest`] trait for extractors
//! - Error types and [`IntoResponse`] trait
//!
//! # Design Principles
//!
//! - Zero-copy where possible
//! - No runtime reflection
//! - All types support `Send + Sync`
//! - Cancel-correct via asupersync integration
//!
//! # Asupersync Integration
//!
//! This crate uses [asupersync](https://github.com/user/asupersync) as its async
//! runtime foundation, providing:
//!
//! - **Structured concurrency**: Request handlers run in regions
//! - **Cancel-correctness**: Graceful cancellation via checkpoints
//! - **Budgeted timeouts**: Request timeouts via budget exhaustion
//! - **Deterministic testing**: Lab runtime for reproducible tests

#![forbid(unsafe_code)]

mod context;
mod error;
mod extract;
pub mod logging;
pub mod middleware;
mod request;
mod response;
pub mod testing;

pub use context::{CancelledError, IntoOutcome, RequestContext};
pub use error::{HttpError, ValidationError, ValidationErrors};
pub use extract::FromRequest;
pub use middleware::{
    AddResponseHeader, BoxFuture, ControlFlow, Handler, Layer, Layered, Middleware,
    MiddlewareStack, NoopMiddleware, PathPrefixFilter, RequireHeader,
};
pub use request::{Body, Headers, Method, Request};
pub use response::{IntoResponse, Response, ResponseBody, StatusCode};

// Re-export key asupersync types for convenience
pub use asupersync::{Budget, Cx, Outcome, RegionId, TaskId};

// Re-export testing utilities
pub use testing::{CookieJar, RequestBuilder, TestClient, TestResponse};

// Re-export logging utilities
pub use logging::{AutoSpan, LogConfig, LogEntry, LogLevel, Span};
