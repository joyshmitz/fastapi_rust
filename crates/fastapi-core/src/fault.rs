//! Fault injection for resilience testing.
//!
//! Provides configurable fault injection to test error handling and
//! system resilience under failure conditions.
//!
//! # Example
//!
//! ```
//! use fastapi_core::fault::{FaultConfig, FaultInjector, FaultType};
//!
//! let config = FaultConfig::new()
//!     .add(FaultType::Delay { ms: 100 }, 0.1)     // 10% chance of 100ms delay
//!     .add(FaultType::Error { status: 500 }, 0.05); // 5% chance of 500 error
//!
//! let injector = FaultInjector::new(config);
//! let fault = injector.check(42); // deterministic based on request ID
//! ```

use std::fmt;

/// Types of faults that can be injected.
#[derive(Debug, Clone, PartialEq)]
pub enum FaultType {
    /// Add latency to the response.
    Delay { ms: u64 },
    /// Return an error response.
    Error { status: u16 },
    /// Simulate a timeout (return 504).
    Timeout,
    /// Corrupt the response body (replace with garbage).
    Corrupt,
}

impl fmt::Display for FaultType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Delay { ms } => write!(f, "delay({ms}ms)"),
            Self::Error { status } => write!(f, "error({status})"),
            Self::Timeout => write!(f, "timeout"),
            Self::Corrupt => write!(f, "corrupt"),
        }
    }
}

/// A single fault rule: a fault type and the probability of it firing (0.0–1.0).
#[derive(Debug, Clone)]
pub struct FaultRule {
    pub fault_type: FaultType,
    /// Probability [0.0, 1.0] that this fault fires on a given request.
    pub rate: f64,
}

/// Configuration for fault injection.
#[derive(Debug, Clone, Default)]
pub struct FaultConfig {
    /// Fault rules evaluated in order.
    pub rules: Vec<FaultRule>,
    /// Whether fault injection is enabled.
    pub enabled: bool,
}

impl FaultConfig {
    /// Create a new fault config (enabled by default).
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            enabled: true,
        }
    }

    /// Add a fault rule.
    #[must_use]
    pub fn add(mut self, fault_type: FaultType, rate: f64) -> Self {
        self.rules.push(FaultRule {
            fault_type,
            rate: rate.clamp(0.0, 1.0),
        });
        self
    }

    /// Enable or disable fault injection.
    #[must_use]
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

/// Deterministic fault injector for testing.
///
/// Uses a simple hash of the request ID to decide whether to inject
/// a fault, making tests reproducible.
#[derive(Debug)]
pub struct FaultInjector {
    config: FaultConfig,
}

impl FaultInjector {
    /// Create a new injector with the given config.
    pub fn new(config: FaultConfig) -> Self {
        Self { config }
    }

    /// Check if a fault should be injected for the given request ID.
    ///
    /// Returns the first matching fault, or `None` if no fault fires.
    /// Uses deterministic hashing so the same request ID always produces
    /// the same result.
    pub fn check(&self, request_id: u64) -> Option<&FaultType> {
        if !self.config.enabled {
            return None;
        }
        for (i, rule) in self.config.rules.iter().enumerate() {
            let hash = Self::hash(request_id, i as u64);
            let threshold = (rule.rate * u64::MAX as f64) as u64;
            if hash < threshold {
                return Some(&rule.fault_type);
            }
        }
        None
    }

    /// Returns the config.
    pub fn config(&self) -> &FaultConfig {
        &self.config
    }

    /// Simple deterministic hash for fault decisions.
    fn hash(request_id: u64, rule_index: u64) -> u64 {
        // FNV-1a inspired mixing
        let mut h: u64 = 0xcbf29ce484222325;
        for byte in request_id.to_le_bytes() {
            h ^= byte as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        for byte in rule_index.to_le_bytes() {
            h ^= byte as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fault_config_builder() {
        let config = FaultConfig::new()
            .add(FaultType::Delay { ms: 100 }, 0.5)
            .add(FaultType::Error { status: 500 }, 0.1);
        assert!(config.enabled);
        assert_eq!(config.rules.len(), 2);
        assert_eq!(config.rules[0].rate, 0.5);
    }

    #[test]
    fn fault_injector_disabled() {
        let config = FaultConfig::new()
            .add(FaultType::Error { status: 500 }, 1.0) // 100% rate
            .enabled(false);
        let injector = FaultInjector::new(config);
        assert!(injector.check(1).is_none());
    }

    #[test]
    fn fault_injector_always_fires_at_rate_1() {
        let config = FaultConfig::new().add(FaultType::Timeout, 1.0);
        let injector = FaultInjector::new(config);
        // With rate 1.0, should fire for all request IDs
        for id in 0..100 {
            assert_eq!(injector.check(id), Some(&FaultType::Timeout));
        }
    }

    #[test]
    fn fault_injector_never_fires_at_rate_0() {
        let config = FaultConfig::new().add(FaultType::Timeout, 0.0);
        let injector = FaultInjector::new(config);
        for id in 0..100 {
            assert!(injector.check(id).is_none());
        }
    }

    #[test]
    fn fault_injector_deterministic() {
        let config = FaultConfig::new().add(FaultType::Error { status: 503 }, 0.5);
        let injector = FaultInjector::new(config);
        // Same request ID should always produce same result
        let result1 = injector.check(42);
        let result2 = injector.check(42);
        assert_eq!(result1, result2);
    }

    #[test]
    fn fault_injector_partial_rate() {
        let config = FaultConfig::new().add(FaultType::Delay { ms: 50 }, 0.5);
        let injector = FaultInjector::new(config);
        let mut fired = 0;
        for id in 0..1000 {
            if injector.check(id).is_some() {
                fired += 1;
            }
        }
        // With rate 0.5, expect roughly 500 fires out of 1000
        assert!(fired > 300 && fired < 700, "fired {fired} out of 1000");
    }

    #[test]
    fn fault_type_display() {
        assert_eq!(FaultType::Delay { ms: 100 }.to_string(), "delay(100ms)");
        assert_eq!(FaultType::Error { status: 500 }.to_string(), "error(500)");
        assert_eq!(FaultType::Timeout.to_string(), "timeout");
        assert_eq!(FaultType::Corrupt.to_string(), "corrupt");
    }

    #[test]
    fn fault_config_rate_clamped() {
        let config = FaultConfig::new().add(FaultType::Timeout, 2.0);
        assert_eq!(config.rules[0].rate, 1.0);
        let config = FaultConfig::new().add(FaultType::Timeout, -1.0);
        assert_eq!(config.rules[0].rate, 0.0);
    }
}
