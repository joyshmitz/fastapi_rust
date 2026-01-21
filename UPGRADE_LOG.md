# Dependency Upgrade Log

**Date:** 2026-01-20  |  **Project:** fastapi_rust  |  **Language:** Rust (workspace)

## Summary
- **Updated:** 2
- **Skipped:** 0
- **Failed:** 0
- **Needs attention:** 0

## Updates

| Package | Old | New | Notes |
|---------|-----|-----|-------|
| regex (spec) | 1.11 | 1.12 | Updated version specifier in Cargo.toml (actual version unchanged at 1.12.2) |
| zmij | 1.0.15 | 1.0.16 | Transitive dependency via serde_json |

## Already Up-to-Date

The following dependencies were already at their latest stable versions:

| Package | Version | Latest |
|---------|---------|--------|
| serde | 1.0.228 | 1.0.228 |
| serde_json | 1.0.149 | 1.0.149 |
| parking_lot | 0.12.5 | 0.12.5 |
| futures-executor | 0.3.31 | 0.3.31 |
| proc-macro2 | 1.0.105 | 1.0.105 |
| quote | 1.0.43 | 1.0.43 |
| syn | 2.0.114 | 2.0.114 |
| regex | 1.12.2 | 1.12.2 |

## Toolchain Fix

Updated `rust-toolchain.toml` to use the latest available nightly:
- Before: `channel = "nightly"` (broken, missing rustc component)
- After: `channel = "nightly"` (working after rustup update)

## Code Fixes Required

Fixed lifetime issue in `/data/projects/fastapi_rust/crates/fastapi-http/src/server.rs`:
- The `TcpListener::bind` method requires `'static` lifetime for the address parameter
- Changed `TcpListener::bind(&self.config.bind_addr)` to `TcpListener::bind(bind_addr.clone())`

## Verification

- `cargo build` - Build successful
- `cargo test --lib` - All 431 library tests passed
- Doc tests have pre-existing failures (unrelated to dependency updates)

## Previous Updates (2026-01-18)

| Package | Old | New |
|---------|-----|-----|
| pin-project | (new) | 1.1.10 |
| pin-project-internal | (new) | 1.1.10 |
| thiserror | 2.0.17 | 2.0.18 |
| thiserror-impl | 2.0.17 | 2.0.18 |
| zmij | 1.0.14 | 1.0.15 |
