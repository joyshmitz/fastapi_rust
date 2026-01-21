//! Rich output facade.
//!
//! Provides a unified interface for console output that automatically
//! adapts to the current environment.

use crate::mode::OutputMode;
use crate::themes::FastApiTheme;
use std::sync::{LazyLock, RwLock};

/// Global instance of `RichOutput` for convenient access.
static GLOBAL_OUTPUT: LazyLock<RwLock<RichOutput>> =
    LazyLock::new(|| RwLock::new(RichOutput::auto()));

/// The main facade for rich console output.
///
/// Provides methods for printing styled text, tables, panels,
/// and other visual elements. Automatically adapts output based
/// on the detected environment.
#[derive(Debug, Clone)]
pub struct RichOutput {
    mode: OutputMode,
    theme: FastApiTheme,
}

impl RichOutput {
    /// Create a new `RichOutput` with the specified mode and default theme.
    #[must_use]
    pub fn new(mode: OutputMode) -> Self {
        Self {
            mode,
            theme: FastApiTheme::default(),
        }
    }

    /// Create a new `RichOutput` with auto-detected mode.
    #[must_use]
    pub fn auto() -> Self {
        Self::new(OutputMode::auto())
    }

    /// Create a new `RichOutput` with rich mode (for humans).
    #[must_use]
    pub fn rich() -> Self {
        Self::new(OutputMode::Rich)
    }

    /// Create a new `RichOutput` with plain mode (for agents).
    #[must_use]
    pub fn plain() -> Self {
        Self::new(OutputMode::Plain)
    }

    /// Get the current output mode.
    #[must_use]
    pub const fn mode(&self) -> OutputMode {
        self.mode
    }

    /// Set the output mode.
    pub fn set_mode(&mut self, mode: OutputMode) {
        self.mode = mode;
    }

    /// Get the current theme.
    #[must_use]
    pub const fn theme(&self) -> &FastApiTheme {
        &self.theme
    }

    /// Set the theme.
    pub fn set_theme(&mut self, theme: FastApiTheme) {
        self.theme = theme;
    }

    /// Print a success message.
    ///
    /// In rich mode: Green checkmark with styled text.
    /// In plain mode: "[OK] message"
    pub fn success(&self, message: &str) {
        match self.mode {
            OutputMode::Rich => {
                // Will use rich_rust when available
                println!("\x1b[32m✓\x1b[0m {message}");
            }
            OutputMode::Plain | OutputMode::Minimal => {
                println!("[OK] {message}");
            }
        }
    }

    /// Print an error message.
    ///
    /// In rich mode: Red X with styled text.
    /// In plain mode: "[ERROR] message"
    pub fn error(&self, message: &str) {
        match self.mode {
            OutputMode::Rich => {
                eprintln!("\x1b[31m✗\x1b[0m {message}");
            }
            OutputMode::Plain | OutputMode::Minimal => {
                eprintln!("[ERROR] {message}");
            }
        }
    }

    /// Print a warning message.
    ///
    /// In rich mode: Yellow warning symbol with styled text.
    /// In plain mode: "[WARN] message"
    pub fn warning(&self, message: &str) {
        match self.mode {
            OutputMode::Rich => {
                eprintln!("\x1b[33m⚠\x1b[0m {message}");
            }
            OutputMode::Plain | OutputMode::Minimal => {
                eprintln!("[WARN] {message}");
            }
        }
    }

    /// Print an info message.
    ///
    /// In rich mode: Blue info symbol with styled text.
    /// In plain mode: "[INFO] message"
    pub fn info(&self, message: &str) {
        match self.mode {
            OutputMode::Rich => {
                println!("\x1b[34mℹ\x1b[0m {message}");
            }
            OutputMode::Plain | OutputMode::Minimal => {
                println!("[INFO] {message}");
            }
        }
    }

    /// Print a debug message (only in non-minimal modes).
    ///
    /// In rich mode: Gray text.
    /// In plain mode: "[DEBUG] message"
    /// In minimal mode: Nothing printed.
    pub fn debug(&self, message: &str) {
        match self.mode {
            OutputMode::Rich => {
                println!("\x1b[90m[DEBUG] {message}\x1b[0m");
            }
            OutputMode::Plain => {
                println!("[DEBUG] {message}");
            }
            OutputMode::Minimal => {
                // Suppress debug output in minimal mode
            }
        }
    }

    /// Get the global `RichOutput` instance.
    ///
    /// # Panics
    ///
    /// Panics if the global lock is poisoned.
    pub fn global() -> std::sync::RwLockReadGuard<'static, RichOutput> {
        GLOBAL_OUTPUT.read().expect("global output lock poisoned")
    }

    /// Get mutable access to the global `RichOutput` instance.
    ///
    /// # Panics
    ///
    /// Panics if the global lock is poisoned.
    pub fn global_mut() -> std::sync::RwLockWriteGuard<'static, RichOutput> {
        GLOBAL_OUTPUT.write().expect("global output lock poisoned")
    }
}

impl Default for RichOutput {
    fn default() -> Self {
        Self::auto()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rich_output_new() {
        let output = RichOutput::new(OutputMode::Plain);
        assert_eq!(output.mode(), OutputMode::Plain);
    }

    #[test]
    fn test_rich_output_mode_setters() {
        let rich = RichOutput::rich();
        assert_eq!(rich.mode(), OutputMode::Rich);

        let plain = RichOutput::plain();
        assert_eq!(plain.mode(), OutputMode::Plain);
    }

    #[test]
    fn test_rich_output_set_mode() {
        let mut output = RichOutput::rich();
        output.set_mode(OutputMode::Plain);
        assert_eq!(output.mode(), OutputMode::Plain);
    }
}
