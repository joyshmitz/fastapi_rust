//! Agent-aware rich console output for fastapi_rust.
//!
//! This crate provides beautiful terminal output that automatically
//! detects whether it's running in an AI agent environment and switches
//! to plain text mode accordingly.
//!
//! # Features
//!
//! - Automatic agent detection (Claude Code, Codex, Cursor, etc.)
//! - Dual-mode output (Rich for humans, Plain for agents)
//! - FastAPI-themed color palette
//! - Tables, panels, progress bars, and more
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use fastapi_output::prelude::*;
//!
//! // Auto-detects mode based on environment
//! let output = RichOutput::auto();
//!
//! // Print styled text (rendered appropriately for mode)
//! output.success("Server started successfully");
//! output.error("Failed to bind to port 8000");
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod detection;
pub mod facade;
pub mod mode;
pub mod themes;

// Re-exports for convenience
pub use detection::is_agent_environment;
pub use facade::RichOutput;
pub use mode::OutputMode;
pub use themes::{FastApiTheme, ThemePreset};

/// Prelude module for convenient imports.
pub mod prelude {
    pub use crate::detection::is_agent_environment;
    pub use crate::facade::RichOutput;
    pub use crate::mode::OutputMode;
    pub use crate::themes::{FastApiTheme, ThemePreset};
}
