//! OpenAPI 3.1 types and schema generation.
//!
//! This crate provides:
//!
//! - OpenAPI 3.1 document types
//! - JSON Schema types
//! - `JsonSchema` trait for compile-time schema generation
//!
//! # Example
//!
//! ```ignore
//! use fastapi_openapi::{OpenApiBuilder, JsonSchema};
//!
//! #[derive(JsonSchema)]
//! struct Item {
//!     id: i64,
//!     name: String,
//! }
//!
//! let spec = OpenApiBuilder::new("My API", "1.0.0")
//!     .route(&get_items_route())
//!     .build();
//! ```

#![forbid(unsafe_code)]

mod schema;
mod spec;

pub use schema::{JsonSchema, ObjectSchema, Schema};
pub use spec::{Info, OpenApi, OpenApiBuilder, Operation, PathItem, Server};
