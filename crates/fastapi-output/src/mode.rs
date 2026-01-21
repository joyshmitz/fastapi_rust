//! Output mode selection.
//!
//! This module defines the output modes available for rendering
//! console output based on the execution environment.

/// The output rendering mode.
///
/// Determines how console output is formatted and styled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputMode {
    /// Rich output with colors, styling, and visual elements.
    ///
    /// Best for human users with capable terminals.
    #[default]
    Rich,

    /// Plain text output without ANSI escape codes.
    ///
    /// Best for AI agents, log files, and piped output.
    Plain,

    /// Minimal output - only essential information.
    ///
    /// Best for CI environments and automated testing.
    Minimal,
}

impl OutputMode {
    /// Auto-detect the appropriate output mode.
    ///
    /// Uses environment detection and terminal capabilities to
    /// select the best mode for the current context.
    #[must_use]
    pub fn auto() -> Self {
        if crate::detection::is_agent_environment() {
            Self::Plain
        } else if Self::terminal_supports_color() {
            Self::Rich
        } else {
            Self::Plain
        }
    }

    /// Check if the terminal supports color output.
    #[must_use]
    fn terminal_supports_color() -> bool {
        // Use crossterm for terminal detection
        crossterm::tty::IsTty::is_tty(&std::io::stdout())
    }

    /// Check if this mode uses ANSI escape codes.
    #[must_use]
    pub const fn uses_ansi(&self) -> bool {
        matches!(self, Self::Rich)
    }

    /// Check if this mode is minimal.
    #[must_use]
    pub const fn is_minimal(&self) -> bool {
        matches!(self, Self::Minimal)
    }
}

impl std::fmt::Display for OutputMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rich => write!(f, "rich"),
            Self::Plain => write!(f, "plain"),
            Self::Minimal => write!(f, "minimal"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_output_mode_default() {
        assert_eq!(OutputMode::default(), OutputMode::Rich);
    }

    #[test]
    fn test_output_mode_display() {
        assert_eq!(OutputMode::Rich.to_string(), "rich");
        assert_eq!(OutputMode::Plain.to_string(), "plain");
        assert_eq!(OutputMode::Minimal.to_string(), "minimal");
    }

    #[test]
    fn test_uses_ansi() {
        assert!(OutputMode::Rich.uses_ansi());
        assert!(!OutputMode::Plain.uses_ansi());
        assert!(!OutputMode::Minimal.uses_ansi());
    }

    #[test]
    fn test_is_minimal() {
        assert!(!OutputMode::Rich.is_minimal());
        assert!(!OutputMode::Plain.is_minimal());
        assert!(OutputMode::Minimal.is_minimal());
    }
}
