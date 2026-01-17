# AGENTS.md — fastapi_rust

> Guidelines for AI coding agents working on the FastAPI-to-Rust port.

---

## Project Overview

**fastapi_rust** is an ULTRA-OPTIMIZED Rust web framework inspired by FastAPI's developer experience. We're building this from scratch with minimal dependencies, co-developing with the [asupersync](file:///data/projects/asupersync) async runtime.

### Key Principles

1. **Extract spec from legacy → implement from spec → NEVER translate line-by-line**
2. **Minimal dependencies** — Only asupersync + serde
3. **Zero-copy where possible** — Parse directly from request buffers
4. **No runtime reflection** — Everything resolved at compile time via proc macros
5. **Cancel-correct** — Leverage asupersync's structured concurrency

### Related Projects

| Project | Location | Purpose |
|---------|----------|---------|
| fastapi_rust | `/data/projects/fastapi_rust` | **This project** — Rust web framework |
| asupersync | `/data/projects/asupersync` | Custom async runtime (co-developed) |
| legacy_fastapi | `./legacy_fastapi/` | Python FastAPI source (reference only) |

---

## RULE NUMBER 1: NO FILE DELETION

**YOU ARE NEVER ALLOWED TO DELETE A FILE WITHOUT EXPRESS PERMISSION.** Even a new file that you yourself created, such as a test code file.

**YOU MUST ALWAYS ASK AND RECEIVE CLEAR, WRITTEN PERMISSION BEFORE EVER DELETING A FILE OR FOLDER OF ANY KIND.**

---

## Irreversible Git & Filesystem Actions — DO NOT EVER BREAK GLASS

1. **Absolutely forbidden commands:** `git reset --hard`, `git clean -fd`, `rm -rf`, or any command that can delete or overwrite code/data must never be run unless the user explicitly provides the exact command and states, in the same message, that they understand and want the irreversible consequences.
2. **No guessing:** If there is any uncertainty about what a command might delete or overwrite, stop immediately and ask the user for specific approval.
3. **Safer alternatives first:** When cleanup or rollbacks are needed, request permission to use non-destructive options (`git status`, `git diff`, `git stash`, copying to backups) before ever considering a destructive command.
4. **Mandatory explicit plan:** Even after explicit user authorization, restate the command verbatim, list exactly what will be affected, and wait for a confirmation.
5. **Document the confirmation:** When running any approved destructive command, record the exact user text that authorized it, the command actually run, and the execution time.

---

## Porting Methodology

### The Three Documents

| Document | Purpose | Status |
|----------|---------|--------|
| `PLAN_TO_PORT_FASTAPI_TO_RUST.md` | Scope, exclusions, phases | ✅ Created |
| `EXISTING_FASTAPI_STRUCTURE.md` | **THE SPEC** — complete behavior extraction | 🔜 Next |
| `PROPOSED_RUST_ARCHITECTURE.md` | Rust design decisions | Pending |

### Critical Rules

1. **After reading the spec, you should NOT need legacy code**
2. **Never translate Python to Rust line-by-line**
3. **Extract behaviors and data structures, not implementation details**
4. **Consult ONLY the spec doc during implementation**

### Deep Dive Extraction Prompts

When extracting to the spec document:

```
Do a comprehensive deep dive into [SUBSYSTEM] at [EXACT PATH].

Extract EXACTLY:
- All data structures with all fields
- Validation rules with exact conditions
- Default values (not approximate)
- Error handling behaviors

EXCLUDE: [List of out-of-scope items per PLAN]

This is research only - do not write any code.
```

---

## Toolchain: Rust & Cargo

We only use **Cargo** in this project, NEVER any other package manager.

- **Edition:** Rust 2024 (nightly required)
- **Dependency versions:** Explicit versions for stability
- **Configuration:** Cargo.toml only
- **Unsafe code:** Minimize, document when necessary

### Minimal Dependency Stack

| Crate | Purpose | Why Essential |
|-------|---------|---------------|
| `asupersync` | Async runtime | **OUR OWN** — cancel-correct, capability-secure |
| `serde` | Serialization traits | Industry standard, zero-cost |
| `serde_json` | JSON parsing | Fast, well-optimized |

### Explicitly NOT Using

| Crate | Reason |
|-------|--------|
| tokio | Using asupersync instead |
| hyper | Building our own HTTP |
| Axum | Too many layers, hidden allocations |
| Tower | Service trait overhead unnecessary |
| utoipa | Runtime schema building |

---

## Co-Development with Asupersync

This project is developed in tandem with asupersync. Changes may need to be made in both repos.

### Asupersync Current State

| Component | Status |
|-----------|--------|
| Scheduler (3-lane) | ✅ Implemented |
| Capability context (Cx) | ✅ Implemented |
| Channels (oneshot, mpsc) | ✅ Implemented |
| **Future execution loop** | 🔜 Phase 0 |
| **I/O integration** | 🔜 Phase 2 |

### When Working on Both Projects

1. Check which components exist in asupersync before building in fastapi_rust
2. If asupersync needs a feature, implement it there first
3. Use asupersync's `Cx` pattern for request context
4. Leverage structured concurrency for request handling

---

## Code Editing Discipline

### No Script-Based Changes

**NEVER** run a script that processes/changes code files in this repo. Brittle regex-based transformations create far more problems than they solve.

### No File Proliferation

If you want to change something or add a feature, **revise existing code files in place**.

**NEVER** create variations like:
- `mainV2.rs`
- `main_improved.rs`
- `main_enhanced.rs`

---

## Backwards Compatibility

We do not care about backwards compatibility—we're in early development with no users. We want to do things the **RIGHT** way with **NO TECH DEBT**.

---

## Compiler Checks (CRITICAL)

**After any substantive code changes, you MUST verify no errors were introduced:**

```bash
# Check for compiler errors and warnings
cargo check --all-targets

# Check for clippy lints
cargo clippy --all-targets -- -D warnings

# Verify formatting
cargo fmt --check
```

---

## File Structure

```
fastapi_rust/
├── AGENTS.md                           # This file
├── PLAN_TO_PORT_FASTAPI_TO_RUST.md     # Porting plan with exclusions
├── EXISTING_FASTAPI_STRUCTURE.md       # THE SPEC (behavior extraction)
├── PROPOSED_RUST_ARCHITECTURE.md       # Rust design decisions
├── legacy_fastapi/                     # Python source (reference only)
│   ├── fastapi/
│   │   ├── applications.py             # Main FastAPI class
│   │   ├── routing.py                  # Route handling
│   │   ├── params.py                   # Parameter classes
│   │   ├── param_functions.py          # Parameter extraction
│   │   ├── dependencies/               # DI system
│   │   ├── openapi/                    # Schema generation
│   │   └── security/                   # Auth handlers
│   └── ...
├── src/                                # Rust implementation (future)
│   ├── lib.rs
│   ├── router/
│   ├── extractors/
│   ├── validation/
│   └── openapi/
└── Cargo.toml
```

---

## Third-Party Library Usage

If you aren't 100% sure how to use a third-party library, **SEARCH ONLINE** to find the latest documentation and 2025/2026 best practices.

---

## MCP Agent Mail — Multi-Agent Coordination

See main project AGENTS.md for MCP Agent Mail instructions. Use for:
- File reservations when editing
- Communication between agents working on fastapi_rust and asupersync

---

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** — Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) — Tests, linters, builds
3. **Update spec documents** — Ensure extraction/design docs are current
4. **PUSH TO REMOTE** — This is MANDATORY:
   ```bash
   git pull --rebase
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Verify** — All changes committed AND pushed
6. **Hand off** — Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing — that leaves work stranded locally
- If push fails, resolve and retry until it succeeds
