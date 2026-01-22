//! Core output components for fastapi_rust.
//!
//! This module contains the primary visual components:
//! - [`banner`] - Startup banner with ASCII art and server info
//! - [`logging`] - Request/response logging with colors and timing
//! - [`errors`] - Error formatters for validation and HTTP errors
//! - [`routes`] - Route table display with method coloring

pub mod banner;
pub mod errors;
pub mod logging;
pub mod routes;

// Re-export main types
pub use banner::{Banner, BannerConfig, ServerInfo};
pub use errors::{ErrorFormatter, FormattedError};
pub use logging::{LogEntry, RequestLogger, ResponseTiming};
pub use routes::{RouteDisplay, RouteTableConfig};
