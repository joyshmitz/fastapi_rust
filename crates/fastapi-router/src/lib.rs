//! Trie-based HTTP router.
//!
//! This crate provides a high-performance radix trie router optimized
//! for the fastapi_rust framework.
//!
//! # Features
//!
//! - Radix trie for fast lookups
//! - Path parameter extraction (`/items/{id}`)
//! - Type-safe path converters
//! - Static route optimization

#![forbid(unsafe_code)]

mod r#match;
mod trie;

pub use r#match::RouteMatch;
pub use trie::{Converter, ParamInfo, Route, Router};
