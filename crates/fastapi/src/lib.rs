//! Ultra-optimized Rust web framework inspired by FastAPI.
//!
//! fastapi_rust provides a type-safe, high-performance web framework with:
//!
//! - **Type-driven API design** — Route handlers declare types, framework extracts/validates automatically
//! - **Dependency injection** — Composable, testable request handling
//! - **Automatic OpenAPI** — Schema generation from type definitions
//! - **First-class async** — Built on asupersync for structured concurrency
//! - **Minimal dependencies** — Only asupersync + serde
//!
//! # Quick Start
//!
//! ```ignore
//! use fastapi::prelude::*;
//!
//! #[derive(Serialize, Deserialize, JsonSchema)]
//! struct Item {
//!     id: i64,
//!     name: String,
//! }
//!
//! #[get("/items/{id}")]
//! async fn get_item(cx: &Cx, id: Path<i64>) -> Json<Item> {
//!     Json(Item { id: id.0, name: "Example".into() })
//! }
//!
//! fn main() {
//!     let app = App::new()
//!         .title("My API")
//!         .route(get_item);
//!
//!     // Run with asupersync
//!     // asupersync::block_on(app.serve("0.0.0.0:8000"));
//! }
//! ```
//!
//! # Design Philosophy
//!
//! This framework is built with the following principles:
//!
//! 1. **Zero-cost abstractions** — No runtime reflection, everything at compile time
//! 2. **Cancel-correct** — Leverages asupersync's structured concurrency
//! 3. **Minimal allocations** — Zero-copy parsing where possible
//! 4. **Familiar API** — FastAPI users will recognize the patterns
//!
//! # Crate Structure
//!
//! - [`fastapi_core`] — Core types (Request, Response, Error)
//! - [`fastapi_http`] — Zero-copy HTTP/1.1 parser
//! - [`fastapi_router`] — Trie-based router
//! - [`fastapi_macros`] — Procedural macros (`#[get]`, `#[derive(Validate)]`)
//! - [`fastapi_openapi`] — OpenAPI 3.1 types and generation

#![forbid(unsafe_code)]
#![doc = include_str!("../../../PROPOSED_RUST_ARCHITECTURE.md")]

// Re-export crates
pub use fastapi_core as core;
pub use fastapi_http as http;
pub use fastapi_macros as macros;
pub use fastapi_openapi as openapi;
pub use fastapi_router as router;

// Re-export commonly used types
pub use fastapi_core::{
    FromRequest, HttpError, IntoResponse, Method, Request, Response, ResponseBody, StatusCode,
    ValidationError, ValidationErrors,
};
pub use fastapi_macros::{delete, get, patch, post, put, JsonSchema, Validate};
pub use fastapi_openapi::{OpenApi, OpenApiBuilder};
pub use fastapi_router::{Route, Router};

/// Prelude module for convenient imports.
pub mod prelude {
    pub use crate::{
        delete, get, patch, post, put, FromRequest, HttpError, IntoResponse, JsonSchema, Method,
        OpenApi, OpenApiBuilder, Request, Response, Route, Router, StatusCode, Validate,
        ValidationError, ValidationErrors,
    };
    pub use serde::{Deserialize, Serialize};
}

// TODO: Extractors module (Path, Query, Json, Header, Cookie)
// TODO: App builder
// TODO: Integration with asupersync Cx
