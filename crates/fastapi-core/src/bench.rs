//! Latency measurement and benchmarking utilities.
//!
//! Provides tools for measuring request processing latency with
//! percentile tracking, histogram distribution, and reporting.
//!
//! # Example
//!
//! ```ignore
//! use fastapi_core::bench::{LatencyHistogram, BenchmarkRunner, BenchmarkConfig};
//!
//! let config = BenchmarkConfig::new("simple_get")
//!     .warmup_iterations(100)
//!     .iterations(10_000);
//!
//! let report = BenchmarkRunner::run(&config, || {
//!     // exercise some code path
//! });
//!
//! println!("{report}");
//! ```

use std::fmt;
use std::time::{Duration, Instant};

/// Collects latency samples and computes percentile statistics.
///
/// Samples are stored unsorted for fast insertion. Sorting happens
/// lazily when percentiles or reports are requested.
pub struct LatencyHistogram {
    samples: Vec<Duration>,
    sorted: bool,
}

impl Default for LatencyHistogram {
    fn default() -> Self {
        Self::new()
    }
}

impl LatencyHistogram {
    /// Create a new empty histogram.
    #[must_use]
    pub fn new() -> Self {
        Self {
            samples: Vec::new(),
            sorted: false,
        }
    }

    /// Create a histogram pre-allocated for the given capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            samples: Vec::with_capacity(capacity),
            sorted: false,
        }
    }

    /// Record a latency sample.
    pub fn record(&mut self, duration: Duration) {
        self.samples.push(duration);
        self.sorted = false;
    }

    /// Record latency by measuring the duration of a closure.
    pub fn measure<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let start = Instant::now();
        let result = f();
        self.record(start.elapsed());
        result
    }

    /// Number of recorded samples.
    #[must_use]
    pub fn count(&self) -> usize {
        self.samples.len()
    }

    /// Returns true if no samples have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// Ensure samples are sorted for percentile computation.
    fn ensure_sorted(&mut self) {
        if !self.sorted {
            self.samples.sort_unstable();
            self.sorted = true;
        }
    }

    /// Compute the value at the given percentile (0.0 to 100.0).
    ///
    /// Returns `None` if no samples have been recorded.
    /// Uses nearest-rank method for percentile computation.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    pub fn percentile(&mut self, p: f64) -> Option<Duration> {
        if self.samples.is_empty() {
            return None;
        }
        self.ensure_sorted();

        let clamped = p.clamp(0.0, 100.0);
        let rank = (clamped / 100.0 * self.samples.len() as f64).ceil() as usize;
        let index = rank.saturating_sub(1).min(self.samples.len() - 1);
        Some(self.samples[index])
    }

    /// Minimum recorded latency.
    pub fn min(&mut self) -> Option<Duration> {
        self.ensure_sorted();
        self.samples.first().copied()
    }

    /// Maximum recorded latency.
    pub fn max(&mut self) -> Option<Duration> {
        self.ensure_sorted();
        self.samples.last().copied()
    }

    /// Mean (average) latency.
    #[must_use]
    pub fn mean(&self) -> Option<Duration> {
        if self.samples.is_empty() {
            return None;
        }
        let total: Duration = self.samples.iter().sum();
        Some(total / self.samples.len() as u32)
    }

    /// Standard deviation of latency samples.
    #[must_use]
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    pub fn std_dev(&self) -> Option<Duration> {
        if self.samples.len() < 2 {
            return None;
        }
        let mean_nanos = self.mean()?.as_nanos() as f64;
        let variance: f64 = self
            .samples
            .iter()
            .map(|s| {
                let diff = s.as_nanos() as f64 - mean_nanos;
                diff * diff
            })
            .sum::<f64>()
            / (self.samples.len() - 1) as f64;

        Some(Duration::from_nanos(variance.sqrt() as u64))
    }

    /// Generate a full latency report with all standard percentiles.
    pub fn report(&mut self) -> Option<LatencyReport> {
        if self.samples.is_empty() {
            return None;
        }

        Some(LatencyReport {
            count: self.count(),
            min: self.min().unwrap_or_default(),
            max: self.max().unwrap_or_default(),
            mean: self.mean().unwrap_or_default(),
            std_dev: self.std_dev().unwrap_or_default(),
            p50: self.percentile(50.0).unwrap_or_default(),
            p90: self.percentile(90.0).unwrap_or_default(),
            p95: self.percentile(95.0).unwrap_or_default(),
            p99: self.percentile(99.0).unwrap_or_default(),
            p999: self.percentile(99.9).unwrap_or_default(),
            histogram_buckets: self.histogram_buckets(10),
        })
    }

    /// Build histogram buckets with the specified number of bins.
    ///
    /// Returns a list of `(bucket_start, bucket_end, count)` tuples.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    pub fn histogram_buckets(&mut self, num_buckets: usize) -> Vec<HistogramBucket> {
        if self.samples.is_empty() || num_buckets == 0 {
            return Vec::new();
        }
        self.ensure_sorted();

        let min_ns = self.samples.first().unwrap().as_nanos() as f64;
        let max_ns = self.samples.last().unwrap().as_nanos() as f64;

        if (max_ns - min_ns).abs() < f64::EPSILON {
            // All samples are the same value
            return vec![HistogramBucket {
                range_start: self.samples[0],
                range_end: self.samples[0],
                count: self.samples.len(),
            }];
        }

        let bucket_width = (max_ns - min_ns) / num_buckets as f64;
        let mut buckets = Vec::with_capacity(num_buckets);

        for i in 0..num_buckets {
            let start_ns = min_ns + (i as f64 * bucket_width);
            let end_ns = if i == num_buckets - 1 {
                max_ns + 1.0 // Include the maximum value
            } else {
                min_ns + ((i + 1) as f64 * bucket_width)
            };

            let count = self
                .samples
                .iter()
                .filter(|s| {
                    let ns = s.as_nanos() as f64;
                    ns >= start_ns && ns < end_ns
                })
                .count();

            buckets.push(HistogramBucket {
                range_start: Duration::from_nanos(start_ns as u64),
                range_end: Duration::from_nanos(end_ns as u64),
                count,
            });
        }

        buckets
    }

    /// Clear all recorded samples.
    pub fn clear(&mut self) {
        self.samples.clear();
        self.sorted = true;
    }
}

/// A single histogram bucket.
#[derive(Debug, Clone)]
pub struct HistogramBucket {
    /// Start of the bucket range (inclusive).
    pub range_start: Duration,
    /// End of the bucket range (exclusive).
    pub range_end: Duration,
    /// Number of samples in this bucket.
    pub count: usize,
}

/// Summary report of latency measurements.
#[derive(Debug, Clone)]
pub struct LatencyReport {
    /// Total number of samples.
    pub count: usize,
    /// Minimum latency.
    pub min: Duration,
    /// Maximum latency.
    pub max: Duration,
    /// Mean (average) latency.
    pub mean: Duration,
    /// Standard deviation.
    pub std_dev: Duration,
    /// 50th percentile (median).
    pub p50: Duration,
    /// 90th percentile.
    pub p90: Duration,
    /// 95th percentile.
    pub p95: Duration,
    /// 99th percentile.
    pub p99: Duration,
    /// 99.9th percentile.
    pub p999: Duration,
    /// Histogram distribution buckets.
    pub histogram_buckets: Vec<HistogramBucket>,
}

impl LatencyReport {
    /// Returns true if any percentile exceeds the given threshold.
    #[must_use]
    pub fn has_tail_latency_above(&self, threshold: Duration) -> bool {
        self.p99 > threshold || self.p999 > threshold
    }

    /// Compare against a baseline report and return the comparison.
    #[must_use]
    pub fn compare(&self, baseline: &Self) -> LatencyComparison {
        LatencyComparison {
            current: self.clone(),
            baseline: baseline.clone(),
        }
    }
}

impl fmt::Display for LatencyReport {
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Latency Report ({} samples)", self.count)?;
        writeln!(f, "  min:    {}", format_duration(self.min))?;
        writeln!(f, "  mean:   {}", format_duration(self.mean))?;
        writeln!(f, "  stddev: {}", format_duration(self.std_dev))?;
        writeln!(f, "  max:    {}", format_duration(self.max))?;
        writeln!(f)?;
        writeln!(f, "  Percentiles:")?;
        writeln!(f, "    p50:   {}", format_duration(self.p50))?;
        writeln!(f, "    p90:   {}", format_duration(self.p90))?;
        writeln!(f, "    p95:   {}", format_duration(self.p95))?;
        writeln!(f, "    p99:   {}", format_duration(self.p99))?;
        writeln!(f, "    p99.9: {}", format_duration(self.p999))?;

        if !self.histogram_buckets.is_empty() {
            writeln!(f)?;
            writeln!(f, "  Distribution:")?;
            let max_count = self
                .histogram_buckets
                .iter()
                .map(|b| b.count)
                .max()
                .unwrap_or(1);
            let bar_width: usize = 40;

            for bucket in &self.histogram_buckets {
                let bar_len = if max_count > 0 {
                    (bucket.count as f64 / max_count as f64 * bar_width as f64) as usize
                } else {
                    0
                };
                let bar: String = "#".repeat(bar_len);
                writeln!(
                    f,
                    "    [{:>8} - {:>8}] {:>6} |{bar}",
                    format_duration(bucket.range_start),
                    format_duration(bucket.range_end),
                    bucket.count,
                )?;
            }
        }

        Ok(())
    }
}

/// Comparison between current and baseline latency reports.
#[derive(Debug, Clone)]
pub struct LatencyComparison {
    /// Current measurement.
    pub current: LatencyReport,
    /// Baseline measurement to compare against.
    pub baseline: LatencyReport,
}

impl LatencyComparison {
    /// Returns true if any percentile regressed beyond the given factor.
    ///
    /// A factor of 1.1 means a 10% regression threshold.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn has_regression(&self, factor: f64) -> bool {
        let check = |current: Duration, baseline: Duration| -> bool {
            if baseline.is_zero() {
                return false;
            }
            let ratio = current.as_nanos() as f64 / baseline.as_nanos() as f64;
            ratio > factor
        };

        check(self.current.p50, self.baseline.p50)
            || check(self.current.p95, self.baseline.p95)
            || check(self.current.p99, self.baseline.p99)
            || check(self.current.p999, self.baseline.p999)
    }
}

impl fmt::Display for LatencyComparison {
    #[allow(clippy::cast_precision_loss)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Latency Comparison")?;
        writeln!(
            f,
            "  Samples: {} (current) vs {} (baseline)",
            self.current.count, self.baseline.count
        )?;
        writeln!(f)?;
        writeln!(
            f,
            "  {:>8}  {:>10}  {:>10}  {:>8}",
            "metric", "current", "baseline", "change"
        )?;
        writeln!(
            f,
            "  {:>8}  {:>10}  {:>10}  {:>8}",
            "------", "-------", "--------", "------"
        )?;

        for (label, cur, base) in [
            ("p50", self.current.p50, self.baseline.p50),
            ("p90", self.current.p90, self.baseline.p90),
            ("p95", self.current.p95, self.baseline.p95),
            ("p99", self.current.p99, self.baseline.p99),
            ("p99.9", self.current.p999, self.baseline.p999),
            ("mean", self.current.mean, self.baseline.mean),
        ] {
            let change = if base.is_zero() {
                "N/A".to_string()
            } else {
                let ratio = cur.as_nanos() as f64 / base.as_nanos() as f64;
                let pct = (ratio - 1.0) * 100.0;
                if pct >= 0.0 {
                    format!("+{pct:.1}%")
                } else {
                    format!("{pct:.1}%")
                }
            };

            writeln!(
                f,
                "  {:>8}  {:>10}  {:>10}  {:>8}",
                label,
                format_duration(cur),
                format_duration(base),
                change,
            )?;
        }

        Ok(())
    }
}

/// Configuration for a benchmark run.
#[derive(Debug, Clone)]
pub struct BenchmarkConfig {
    /// Name for this benchmark.
    pub name: String,
    /// Number of warmup iterations (discarded).
    pub warmup_iterations: usize,
    /// Number of measured iterations.
    pub iterations: usize,
}

impl BenchmarkConfig {
    /// Create a new benchmark configuration with the given name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            warmup_iterations: 100,
            iterations: 10_000,
        }
    }

    /// Set the number of warmup iterations.
    #[must_use]
    pub fn warmup_iterations(mut self, n: usize) -> Self {
        self.warmup_iterations = n;
        self
    }

    /// Set the number of measured iterations.
    #[must_use]
    pub fn iterations(mut self, n: usize) -> Self {
        self.iterations = n;
        self
    }
}

/// Runs benchmarks and collects latency data.
pub struct BenchmarkRunner;

impl BenchmarkRunner {
    /// Run a benchmark with the given configuration and return a latency report.
    ///
    /// The closure `f` is called `warmup + iterations` times.
    /// Only the last `iterations` calls are measured.
    pub fn run<F>(config: &BenchmarkConfig, mut f: F) -> LatencyReport
    where
        F: FnMut(),
    {
        // Warmup phase
        for _ in 0..config.warmup_iterations {
            f();
        }

        // Measurement phase
        let mut histogram = LatencyHistogram::with_capacity(config.iterations);
        for _ in 0..config.iterations {
            histogram.measure(|| f());
        }

        histogram.report().unwrap_or_else(|| LatencyReport {
            count: 0,
            min: Duration::ZERO,
            max: Duration::ZERO,
            mean: Duration::ZERO,
            std_dev: Duration::ZERO,
            p50: Duration::ZERO,
            p90: Duration::ZERO,
            p95: Duration::ZERO,
            p99: Duration::ZERO,
            p999: Duration::ZERO,
            histogram_buckets: Vec::new(),
        })
    }

    /// Run a benchmark that returns a value, discarding the return value.
    pub fn run_with_result<F, R>(config: &BenchmarkConfig, mut f: F) -> LatencyReport
    where
        F: FnMut() -> R,
    {
        Self::run(config, || {
            let _ = std::hint::black_box(f());
        })
    }

    /// Run multiple named benchmarks and return all reports.
    pub fn run_suite(
        suite: Vec<(BenchmarkConfig, Box<dyn FnMut()>)>,
    ) -> Vec<(String, LatencyReport)> {
        suite
            .into_iter()
            .map(|(config, mut f)| {
                let name = config.name.clone();
                let report = Self::run(&config, &mut *f);
                (name, report)
            })
            .collect()
    }
}

/// Format a duration in a human-readable way.
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn format_duration(d: Duration) -> String {
    let nanos = d.as_nanos();
    if nanos < 1_000 {
        format!("{nanos}ns")
    } else if nanos < 1_000_000 {
        format!("{:.1}us", nanos as f64 / 1_000.0)
    } else if nanos < 1_000_000_000 {
        format!("{:.2}ms", nanos as f64 / 1_000_000.0)
    } else {
        format!("{:.3}s", nanos as f64 / 1_000_000_000.0)
    }
}

// ============================================================================
// Memory Tracking
// ============================================================================

/// A snapshot of memory usage at a point in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemorySnapshot {
    /// Resident set size in bytes (physical memory used).
    pub rss_bytes: usize,
    /// Virtual memory size in bytes.
    pub vms_bytes: usize,
}

impl MemorySnapshot {
    /// Take a snapshot of current process memory usage.
    ///
    /// On Linux, reads `/proc/self/status` for `VmRSS` and `VmSize`.
    /// On other platforms, returns zero values.
    #[must_use]
    pub fn current() -> Self {
        read_proc_memory().unwrap_or(Self {
            rss_bytes: 0,
            vms_bytes: 0,
        })
    }

    /// Returns RSS formatted as a human-readable string.
    #[must_use]
    pub fn rss_display(&self) -> String {
        format_bytes_size(self.rss_bytes)
    }

    /// Returns VMS formatted as a human-readable string.
    #[must_use]
    pub fn vms_display(&self) -> String {
        format_bytes_size(self.vms_bytes)
    }
}

impl fmt::Display for MemorySnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RSS: {}, VMS: {}",
            self.rss_display(),
            self.vms_display()
        )
    }
}

/// Tracks memory usage over time with baseline, peak, and delta computation.
///
/// # Example
///
/// ```ignore
/// use fastapi_core::bench::MemoryTracker;
///
/// let mut tracker = MemoryTracker::new();
///
/// // ... do some work ...
/// tracker.sample();
///
/// // ... do more work ...
/// tracker.sample();
///
/// let report = tracker.report();
/// println!("{report}");
/// ```
pub struct MemoryTracker {
    baseline: MemorySnapshot,
    samples: Vec<MemorySnapshot>,
    peak_rss: usize,
}

impl Default for MemoryTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryTracker {
    /// Create a new memory tracker, recording the current RSS as baseline.
    #[must_use]
    pub fn new() -> Self {
        let baseline = MemorySnapshot::current();
        Self {
            baseline,
            samples: Vec::new(),
            peak_rss: baseline.rss_bytes,
        }
    }

    /// Take a memory sample at the current moment.
    pub fn sample(&mut self) {
        let snap = MemorySnapshot::current();
        if snap.rss_bytes > self.peak_rss {
            self.peak_rss = snap.rss_bytes;
        }
        self.samples.push(snap);
    }

    /// Record a sample while executing a closure, returning the closure's result.
    pub fn measure<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let result = f();
        self.sample();
        result
    }

    /// Record N iterations of a closure, sampling after each.
    pub fn measure_repeated<F>(&mut self, iterations: usize, mut f: F)
    where
        F: FnMut(),
    {
        for _ in 0..iterations {
            f();
            self.sample();
        }
    }

    /// Number of samples taken (excluding baseline).
    #[must_use]
    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }

    /// Get the baseline memory snapshot.
    #[must_use]
    pub fn baseline(&self) -> MemorySnapshot {
        self.baseline
    }

    /// Get the peak RSS observed.
    #[must_use]
    pub fn peak_rss(&self) -> usize {
        self.peak_rss
    }

    /// Generate a memory usage report.
    #[must_use]
    pub fn report(&self) -> MemoryReport {
        let current = self.samples.last().copied().unwrap_or(self.baseline);

        let delta_rss = current.rss_bytes.saturating_sub(self.baseline.rss_bytes);

        let per_operation_bytes = if self.samples.len() > 1 {
            Some(delta_rss / self.samples.len())
        } else {
            None
        };

        let leak_suspect = self.detect_leak_trend();

        MemoryReport {
            baseline_rss: self.baseline.rss_bytes,
            current_rss: current.rss_bytes,
            peak_rss: self.peak_rss,
            delta_rss,
            per_operation_bytes,
            sample_count: self.samples.len(),
            leak_suspect,
        }
    }

    /// Detect if memory is trending upward (potential leak).
    ///
    /// Uses simple linear regression on RSS samples. Returns `true` if
    /// the trend shows consistent growth exceeding 1 KB per sample.
    #[allow(clippy::cast_precision_loss)]
    fn detect_leak_trend(&self) -> bool {
        if self.samples.len() < 10 {
            return false;
        }

        // Split samples into two halves and compare means
        let mid = self.samples.len() / 2;
        let first_half_mean: f64 = self.samples[..mid]
            .iter()
            .map(|s| s.rss_bytes as f64)
            .sum::<f64>()
            / mid as f64;

        let second_half_mean: f64 = self.samples[mid..]
            .iter()
            .map(|s| s.rss_bytes as f64)
            .sum::<f64>()
            / (self.samples.len() - mid) as f64;

        // Suspect leak if second half is > 1KB higher than first half on average
        second_half_mean - first_half_mean > 1024.0
    }

    /// Reset the tracker with a new baseline.
    pub fn reset(&mut self) {
        self.baseline = MemorySnapshot::current();
        self.samples.clear();
        self.peak_rss = self.baseline.rss_bytes;
    }
}

/// Report summarizing memory usage measurements.
#[derive(Debug, Clone)]
pub struct MemoryReport {
    /// Baseline RSS at tracker creation.
    pub baseline_rss: usize,
    /// Most recent RSS measurement.
    pub current_rss: usize,
    /// Peak RSS observed during tracking.
    pub peak_rss: usize,
    /// RSS change from baseline to current.
    pub delta_rss: usize,
    /// Estimated bytes per operation (if multiple samples).
    pub per_operation_bytes: Option<usize>,
    /// Total number of samples taken.
    pub sample_count: usize,
    /// Whether a memory leak trend was detected.
    pub leak_suspect: bool,
}

impl MemoryReport {
    /// Compare against a baseline report.
    #[must_use]
    pub fn compare(&self, baseline: &Self) -> MemoryComparison {
        MemoryComparison {
            current: self.clone(),
            baseline: baseline.clone(),
        }
    }
}

impl fmt::Display for MemoryReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Memory Report ({} samples)", self.sample_count)?;
        writeln!(f, "  baseline: {}", format_bytes_size(self.baseline_rss))?;
        writeln!(f, "  current:  {}", format_bytes_size(self.current_rss))?;
        writeln!(f, "  peak:     {}", format_bytes_size(self.peak_rss))?;
        writeln!(f, "  delta:    {}", format_bytes_size(self.delta_rss))?;

        if let Some(per_op) = self.per_operation_bytes {
            writeln!(f, "  per-op:   {}", format_bytes_size(per_op))?;
        }

        if self.leak_suspect {
            writeln!(f, "  WARNING: Potential memory leak detected!")?;
        }

        Ok(())
    }
}

/// Comparison between two memory reports.
#[derive(Debug, Clone)]
pub struct MemoryComparison {
    /// Current measurement.
    pub current: MemoryReport,
    /// Baseline measurement.
    pub baseline: MemoryReport,
}

impl MemoryComparison {
    /// Returns true if current peak RSS exceeds baseline by the given factor.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn has_regression(&self, factor: f64) -> bool {
        if self.baseline.peak_rss == 0 {
            return false;
        }
        let ratio = self.current.peak_rss as f64 / self.baseline.peak_rss as f64;
        ratio > factor
    }
}

impl fmt::Display for MemoryComparison {
    #[allow(clippy::cast_precision_loss)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Memory Comparison")?;
        writeln!(f)?;
        writeln!(
            f,
            "  {:>10}  {:>10}  {:>10}  {:>8}",
            "metric", "current", "baseline", "change"
        )?;
        writeln!(
            f,
            "  {:>10}  {:>10}  {:>10}  {:>8}",
            "------", "-------", "--------", "------"
        )?;

        for (label, cur, base) in [
            ("peak RSS", self.current.peak_rss, self.baseline.peak_rss),
            ("delta RSS", self.current.delta_rss, self.baseline.delta_rss),
        ] {
            let change = if base == 0 {
                "N/A".to_string()
            } else {
                let ratio = cur as f64 / base as f64;
                let pct = (ratio - 1.0) * 100.0;
                if pct >= 0.0 {
                    format!("+{pct:.1}%")
                } else {
                    format!("{pct:.1}%")
                }
            };

            writeln!(
                f,
                "  {:>10}  {:>10}  {:>10}  {:>8}",
                label,
                format_bytes_size(cur),
                format_bytes_size(base),
                change,
            )?;
        }

        Ok(())
    }
}

/// Read memory info from `/proc/self/status` on Linux.
fn read_proc_memory() -> Option<MemorySnapshot> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;

    let mut rss_bytes = 0;
    let mut vms_bytes = 0;

    for line in status.lines() {
        if let Some(value) = line.strip_prefix("VmRSS:") {
            rss_bytes = parse_proc_kb(value)?;
        } else if let Some(value) = line.strip_prefix("VmSize:") {
            vms_bytes = parse_proc_kb(value)?;
        }
    }

    Some(MemorySnapshot {
        rss_bytes,
        vms_bytes,
    })
}

/// Parse a value like "  12345 kB" from /proc/self/status.
fn parse_proc_kb(value: &str) -> Option<usize> {
    let trimmed = value.trim();
    let num_str = trimmed
        .strip_suffix("kB")
        .or_else(|| trimmed.strip_suffix("KB"))?
        .trim();
    let kb: usize = num_str.parse().ok()?;
    Some(kb * 1024)
}

/// Format a byte count in human-readable form.
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn format_bytes_size(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{bytes}B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1}MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2}GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histogram_empty() {
        let mut h = LatencyHistogram::new();
        assert!(h.is_empty());
        assert_eq!(h.count(), 0);
        assert!(h.percentile(50.0).is_none());
        assert!(h.min().is_none());
        assert!(h.max().is_none());
        assert!(h.mean().is_none());
        assert!(h.std_dev().is_none());
        assert!(h.report().is_none());
    }

    #[test]
    fn histogram_single_sample() {
        let mut h = LatencyHistogram::new();
        h.record(Duration::from_micros(100));
        assert_eq!(h.count(), 1);
        assert!(!h.is_empty());
        assert_eq!(h.percentile(50.0), Some(Duration::from_micros(100)));
        assert_eq!(h.min(), Some(Duration::from_micros(100)));
        assert_eq!(h.max(), Some(Duration::from_micros(100)));
        assert_eq!(h.mean(), Some(Duration::from_micros(100)));
    }

    #[test]
    fn histogram_multiple_samples() {
        let mut h = LatencyHistogram::new();
        for i in 1..=100 {
            h.record(Duration::from_micros(i));
        }
        assert_eq!(h.count(), 100);
        assert_eq!(h.min(), Some(Duration::from_micros(1)));
        assert_eq!(h.max(), Some(Duration::from_micros(100)));

        // p50 should be around 50
        let p50 = h.percentile(50.0).unwrap();
        assert!(
            p50.as_micros() >= 49 && p50.as_micros() <= 51,
            "p50 = {p50:?}"
        );

        // p99 should be around 99
        let p99 = h.percentile(99.0).unwrap();
        assert!(
            p99.as_micros() >= 98 && p99.as_micros() <= 100,
            "p99 = {p99:?}"
        );
    }

    #[test]
    fn histogram_percentile_boundary_values() {
        let mut h = LatencyHistogram::new();
        for i in 1..=1000 {
            h.record(Duration::from_micros(i));
        }

        // p0 should return the min
        let p0 = h.percentile(0.0).unwrap();
        assert_eq!(p0, Duration::from_micros(1));

        // p100 should return the max
        let p100 = h.percentile(100.0).unwrap();
        assert_eq!(p100, Duration::from_millis(1));

        // p99.9 should be close to 999
        let p999 = h.percentile(99.9).unwrap();
        assert!(
            p999.as_micros() >= 998 && p999.as_micros() <= 1000,
            "p99.9 = {p999:?}"
        );
    }

    #[test]
    fn histogram_mean_calculation() {
        let mut h = LatencyHistogram::new();
        h.record(Duration::from_micros(10));
        h.record(Duration::from_micros(20));
        h.record(Duration::from_micros(30));
        assert_eq!(h.mean(), Some(Duration::from_micros(20)));
    }

    #[test]
    fn histogram_std_dev() {
        let mut h = LatencyHistogram::new();
        // All same values => zero std dev
        for _ in 0..10 {
            h.record(Duration::from_micros(100));
        }
        let sd = h.std_dev().unwrap();
        assert_eq!(sd, Duration::ZERO);

        // Different values
        let mut h2 = LatencyHistogram::new();
        h2.record(Duration::from_micros(10));
        h2.record(Duration::from_micros(20));
        let sd2 = h2.std_dev().unwrap();
        assert!(sd2 > Duration::ZERO);
    }

    #[test]
    fn histogram_measure_closure() {
        let mut h = LatencyHistogram::new();
        let result = h.measure(|| 42);
        assert_eq!(result, 42);
        assert_eq!(h.count(), 1);
        // Duration should be very small (just overhead)
        assert!(h.min().unwrap() < Duration::from_millis(10));
    }

    #[test]
    fn histogram_clear() {
        let mut h = LatencyHistogram::new();
        h.record(Duration::from_micros(100));
        assert_eq!(h.count(), 1);
        h.clear();
        assert!(h.is_empty());
        assert_eq!(h.count(), 0);
    }

    #[test]
    fn histogram_buckets_empty() {
        let mut h = LatencyHistogram::new();
        assert!(h.histogram_buckets(10).is_empty());
    }

    #[test]
    fn histogram_buckets_uniform() {
        let mut h = LatencyHistogram::new();
        for i in 1..=100 {
            h.record(Duration::from_micros(i));
        }
        let buckets = h.histogram_buckets(10);
        assert_eq!(buckets.len(), 10);

        // Total across all buckets should equal sample count
        let total: usize = buckets.iter().map(|b| b.count).sum();
        assert_eq!(total, 100);
    }

    #[test]
    fn histogram_buckets_same_value() {
        let mut h = LatencyHistogram::new();
        for _ in 0..50 {
            h.record(Duration::from_micros(100));
        }
        let buckets = h.histogram_buckets(10);
        // When all values are the same, we get a single bucket
        assert_eq!(buckets.len(), 1);
        assert_eq!(buckets[0].count, 50);
    }

    #[test]
    fn report_generation() {
        let mut h = LatencyHistogram::new();
        for i in 1..=1000 {
            h.record(Duration::from_micros(i));
        }
        let report = h.report().unwrap();
        assert_eq!(report.count, 1000);
        assert_eq!(report.min, Duration::from_micros(1));
        assert_eq!(report.max, Duration::from_millis(1));
        assert!(report.p50 <= report.p90);
        assert!(report.p90 <= report.p95);
        assert!(report.p95 <= report.p99);
        assert!(report.p99 <= report.p999);
    }

    #[test]
    fn report_display_format() {
        let mut h = LatencyHistogram::new();
        for i in 1..=100 {
            h.record(Duration::from_micros(i));
        }
        let report = h.report().unwrap();
        let output = format!("{report}");
        assert!(output.contains("Latency Report"));
        assert!(output.contains("p50:"));
        assert!(output.contains("p95:"));
        assert!(output.contains("p99:"));
        assert!(output.contains("p99.9:"));
        assert!(output.contains("Distribution:"));
    }

    #[test]
    fn report_tail_latency_detection() {
        let mut h = LatencyHistogram::new();
        for i in 1..=100 {
            h.record(Duration::from_micros(i));
        }
        let report = h.report().unwrap();

        // Threshold below max should detect tail latency
        assert!(report.has_tail_latency_above(Duration::from_micros(50)));
        // Threshold above max should not
        assert!(!report.has_tail_latency_above(Duration::from_micros(200)));
    }

    #[test]
    fn comparison_no_regression() {
        let mut h1 = LatencyHistogram::new();
        let mut h2 = LatencyHistogram::new();
        for i in 1..=100 {
            h1.record(Duration::from_micros(i));
            h2.record(Duration::from_micros(i));
        }
        let r1 = h1.report().unwrap();
        let r2 = h2.report().unwrap();
        let cmp = r1.compare(&r2);
        assert!(!cmp.has_regression(1.1)); // 10% threshold
    }

    #[test]
    fn comparison_with_regression() {
        let mut baseline = LatencyHistogram::new();
        let mut current = LatencyHistogram::new();
        for i in 1..=100 {
            baseline.record(Duration::from_micros(i));
            current.record(Duration::from_micros(i * 2)); // 2x slower
        }
        let r_base = baseline.report().unwrap();
        let r_curr = current.report().unwrap();
        let cmp = r_curr.compare(&r_base);
        assert!(cmp.has_regression(1.1)); // Expect regression detected
    }

    #[test]
    fn comparison_display_format() {
        let mut h1 = LatencyHistogram::new();
        let mut h2 = LatencyHistogram::new();
        for i in 1..=100 {
            h1.record(Duration::from_micros(i));
            h2.record(Duration::from_micros(i));
        }
        let r1 = h1.report().unwrap();
        let r2 = h2.report().unwrap();
        let cmp = r1.compare(&r2);
        let output = format!("{cmp}");
        assert!(output.contains("Latency Comparison"));
        assert!(output.contains("current"));
        assert!(output.contains("baseline"));
        assert!(output.contains("change"));
    }

    #[test]
    fn benchmark_runner_basic() {
        let config = BenchmarkConfig::new("test_bench")
            .warmup_iterations(10)
            .iterations(100);

        let mut counter = 0u64;
        let report = BenchmarkRunner::run(&config, || {
            counter += 1;
        });

        // Warmup + measured iterations
        assert_eq!(counter, 110);
        assert_eq!(report.count, 100);
        assert!(report.min <= report.max);
    }

    #[test]
    fn benchmark_runner_with_result() {
        let config = BenchmarkConfig::new("result_bench")
            .warmup_iterations(5)
            .iterations(50);

        let report = BenchmarkRunner::run_with_result(&config, || 42);
        assert_eq!(report.count, 50);
    }

    #[test]
    fn benchmark_config_defaults() {
        let config = BenchmarkConfig::new("default");
        assert_eq!(config.name, "default");
        assert_eq!(config.warmup_iterations, 100);
        assert_eq!(config.iterations, 10_000);
    }

    #[test]
    fn benchmark_config_builder() {
        let config = BenchmarkConfig::new("custom")
            .warmup_iterations(50)
            .iterations(500);
        assert_eq!(config.name, "custom");
        assert_eq!(config.warmup_iterations, 50);
        assert_eq!(config.iterations, 500);
    }

    #[test]
    fn format_duration_nanos() {
        assert_eq!(format_duration(Duration::from_nanos(42)), "42ns");
        assert_eq!(format_duration(Duration::from_nanos(999)), "999ns");
    }

    #[test]
    fn format_duration_micros() {
        assert_eq!(format_duration(Duration::from_micros(1)), "1.0us");
        assert_eq!(format_duration(Duration::from_micros(500)), "500.0us");
    }

    #[test]
    fn format_duration_millis() {
        assert_eq!(format_duration(Duration::from_millis(1)), "1.00ms");
        assert_eq!(format_duration(Duration::from_millis(42)), "42.00ms");
    }

    #[test]
    fn format_duration_seconds() {
        assert_eq!(format_duration(Duration::from_secs(1)), "1.000s");
        assert_eq!(format_duration(Duration::from_millis(1500)), "1.500s");
    }

    #[test]
    fn benchmark_suite_runs_all() {
        let suite: Vec<(BenchmarkConfig, Box<dyn FnMut()>)> = vec![
            (
                BenchmarkConfig::new("a")
                    .warmup_iterations(1)
                    .iterations(10),
                Box::new(|| {}),
            ),
            (
                BenchmarkConfig::new("b")
                    .warmup_iterations(1)
                    .iterations(10),
                Box::new(|| {}),
            ),
        ];
        let results = BenchmarkRunner::run_suite(suite);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, "a");
        assert_eq!(results[1].0, "b");
    }

    #[test]
    fn histogram_with_capacity() {
        let mut h = LatencyHistogram::with_capacity(1000);
        assert!(h.is_empty());
        h.record(Duration::from_micros(1));
        assert_eq!(h.count(), 1);
    }

    #[test]
    fn percentile_clamping() {
        let mut h = LatencyHistogram::new();
        h.record(Duration::from_micros(10));
        h.record(Duration::from_micros(20));

        // Negative percentile clamps to 0
        let p_neg = h.percentile(-10.0);
        assert!(p_neg.is_some());

        // Percentile > 100 clamps to 100
        let p_over = h.percentile(200.0);
        assert_eq!(p_over, Some(Duration::from_micros(20)));
    }

    // ================================================================
    // Memory tracking tests
    // ================================================================

    #[test]
    fn memory_snapshot_current() {
        let snap = MemorySnapshot::current();
        // On Linux, RSS should be non-zero for a running process
        #[cfg(target_os = "linux")]
        assert!(snap.rss_bytes > 0, "RSS should be positive on Linux");
        #[cfg(target_os = "linux")]
        assert!(snap.vms_bytes > 0, "VMS should be positive on Linux");
        // On other platforms, gracefully returns zero
        let _ = snap;
    }

    #[test]
    fn memory_snapshot_display() {
        let snap = MemorySnapshot {
            rss_bytes: 10 * 1024 * 1024,
            vms_bytes: 100 * 1024 * 1024,
        };
        let display = format!("{snap}");
        assert!(display.contains("RSS:"));
        assert!(display.contains("VMS:"));
        assert!(display.contains("10.0MB"));
        assert!(display.contains("100.0MB"));
    }

    #[test]
    fn memory_snapshot_display_methods() {
        let snap = MemorySnapshot {
            rss_bytes: 2048,
            vms_bytes: 4096,
        };
        assert_eq!(snap.rss_display(), "2.0KB");
        assert_eq!(snap.vms_display(), "4.0KB");
    }

    #[test]
    fn memory_tracker_new_has_baseline() {
        let tracker = MemoryTracker::new();
        assert_eq!(tracker.sample_count(), 0);
        #[cfg(target_os = "linux")]
        assert!(tracker.baseline().rss_bytes > 0);
    }

    #[test]
    fn memory_tracker_sample() {
        let mut tracker = MemoryTracker::new();
        tracker.sample();
        assert_eq!(tracker.sample_count(), 1);
        tracker.sample();
        assert_eq!(tracker.sample_count(), 2);
    }

    #[test]
    fn memory_tracker_measure() {
        let mut tracker = MemoryTracker::new();
        let result = tracker.measure(|| 42);
        assert_eq!(result, 42);
        assert_eq!(tracker.sample_count(), 1);
    }

    #[test]
    fn memory_tracker_measure_repeated() {
        let mut tracker = MemoryTracker::new();
        let mut counter = 0;
        tracker.measure_repeated(5, || {
            counter += 1;
        });
        assert_eq!(counter, 5);
        assert_eq!(tracker.sample_count(), 5);
    }

    #[test]
    fn memory_tracker_peak_rss() {
        let tracker = MemoryTracker::new();
        assert!(tracker.peak_rss() >= tracker.baseline().rss_bytes);
    }

    #[test]
    fn memory_tracker_reset() {
        let mut tracker = MemoryTracker::new();
        tracker.sample();
        tracker.sample();
        assert_eq!(tracker.sample_count(), 2);
        tracker.reset();
        assert_eq!(tracker.sample_count(), 0);
    }

    #[test]
    fn memory_tracker_default() {
        let tracker = MemoryTracker::default();
        assert_eq!(tracker.sample_count(), 0);
    }

    #[test]
    fn memory_report_generation() {
        let mut tracker = MemoryTracker::new();
        tracker.sample();
        tracker.sample();
        let report = tracker.report();
        assert_eq!(report.sample_count, 2);
        assert!(report.peak_rss >= report.baseline_rss);
    }

    #[test]
    fn memory_report_display() {
        let report = MemoryReport {
            baseline_rss: 10 * 1024 * 1024,
            current_rss: 12 * 1024 * 1024,
            peak_rss: 15 * 1024 * 1024,
            delta_rss: 2 * 1024 * 1024,
            per_operation_bytes: Some(1024),
            sample_count: 100,
            leak_suspect: false,
        };
        let output = format!("{report}");
        assert!(output.contains("Memory Report"));
        assert!(output.contains("baseline:"));
        assert!(output.contains("current:"));
        assert!(output.contains("peak:"));
        assert!(output.contains("delta:"));
        assert!(output.contains("per-op:"));
        assert!(!output.contains("leak"));
    }

    #[test]
    fn memory_report_display_with_leak() {
        let report = MemoryReport {
            baseline_rss: 10 * 1024 * 1024,
            current_rss: 20 * 1024 * 1024,
            peak_rss: 20 * 1024 * 1024,
            delta_rss: 10 * 1024 * 1024,
            per_operation_bytes: None,
            sample_count: 1,
            leak_suspect: true,
        };
        let output = format!("{report}");
        assert!(output.contains("leak"));
    }

    #[test]
    fn memory_report_comparison() {
        let current = MemoryReport {
            baseline_rss: 10_000,
            current_rss: 20_000,
            peak_rss: 25_000,
            delta_rss: 10_000,
            per_operation_bytes: Some(100),
            sample_count: 100,
            leak_suspect: false,
        };
        let baseline = MemoryReport {
            baseline_rss: 10_000,
            current_rss: 12_000,
            peak_rss: 15_000,
            delta_rss: 2_000,
            per_operation_bytes: Some(50),
            sample_count: 100,
            leak_suspect: false,
        };
        let cmp = current.compare(&baseline);
        assert!(cmp.has_regression(1.1)); // 25K/15K > 1.1
    }

    #[test]
    fn memory_comparison_no_regression() {
        let report = MemoryReport {
            baseline_rss: 10_000,
            current_rss: 10_000,
            peak_rss: 10_000,
            delta_rss: 0,
            per_operation_bytes: None,
            sample_count: 1,
            leak_suspect: false,
        };
        let cmp = report.compare(&report);
        assert!(!cmp.has_regression(1.1));
    }

    #[test]
    fn memory_comparison_display() {
        let current = MemoryReport {
            baseline_rss: 1024,
            current_rss: 2048,
            peak_rss: 3072,
            delta_rss: 1024,
            per_operation_bytes: None,
            sample_count: 1,
            leak_suspect: false,
        };
        let baseline = current.clone();
        let cmp = current.compare(&baseline);
        let output = format!("{cmp}");
        assert!(output.contains("Memory Comparison"));
        assert!(output.contains("peak RSS"));
    }

    #[test]
    fn memory_comparison_zero_baseline() {
        let current = MemoryReport {
            baseline_rss: 0,
            current_rss: 0,
            peak_rss: 1024,
            delta_rss: 0,
            per_operation_bytes: None,
            sample_count: 0,
            leak_suspect: false,
        };
        let baseline = MemoryReport {
            baseline_rss: 0,
            current_rss: 0,
            peak_rss: 0,
            delta_rss: 0,
            per_operation_bytes: None,
            sample_count: 0,
            leak_suspect: false,
        };
        let cmp = current.compare(&baseline);
        assert!(!cmp.has_regression(1.1)); // Zero baseline should not flag
    }

    #[test]
    fn format_bytes_size_units() {
        assert_eq!(format_bytes_size(0), "0B");
        assert_eq!(format_bytes_size(512), "512B");
        assert_eq!(format_bytes_size(1024), "1.0KB");
        assert_eq!(format_bytes_size(1536), "1.5KB");
        assert_eq!(format_bytes_size(1024 * 1024), "1.0MB");
        assert_eq!(format_bytes_size(1024 * 1024 * 1024), "1.00GB");
    }

    #[test]
    fn parse_proc_kb_valid() {
        assert_eq!(parse_proc_kb("   12345 kB"), Some(12345 * 1024));
        assert_eq!(parse_proc_kb("  100 kB"), Some(100 * 1024));
    }

    #[test]
    fn parse_proc_kb_invalid() {
        assert_eq!(parse_proc_kb("not a number kB"), None);
        assert_eq!(parse_proc_kb("12345 MB"), None);
        assert_eq!(parse_proc_kb(""), None);
    }

    #[test]
    fn leak_detection_too_few_samples() {
        let tracker = MemoryTracker::new();
        // With 0 samples, no leak detected
        assert!(!tracker.report().leak_suspect);
    }
}
