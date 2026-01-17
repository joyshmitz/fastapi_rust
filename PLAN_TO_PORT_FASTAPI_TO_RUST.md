# Plan to Port FastAPI to Rust

> **THE RULE:** Extract spec from legacy → implement from spec → never translate line-by-line.

## Project Overview

**Goal:** Create an ULTRA-OPTIMIZED Rust web framework inspired by FastAPI's developer experience—type-safe routing, automatic validation, dependency injection, and OpenAPI generation—built from scratch with minimal dependencies.

**Source:** FastAPI v0.128.0 (~32K lines Python)

**Target:** Native Rust library built directly on Tokio/Hyper with custom routing, zero-copy parsing, and compile-time code generation.

## Design Philosophy: ULTRA OPTIMIZED

1. **Minimal dependencies** — Only what we absolutely need (tokio, hyper, serde)
2. **Zero-copy where possible** — Parse directly from request buffers
3. **No runtime reflection** — Everything resolved at compile time via proc macros
4. **Custom router** — Trie-based routing optimized for our use case
5. **Inline everything** — Hot paths should be monomorphized and inlined
6. **No allocations on fast path** — Pre-allocated buffers, arena allocation

---

## Core Value Propositions to Preserve

1. **Type-driven API design** — Route handlers declare types, framework extracts/validates automatically
2. **Dependency injection** — `Depends()` pattern for composable, testable request handling
3. **Automatic OpenAPI** — Schema generation from type definitions
4. **First-class async** — Native async/await support
5. **Developer ergonomics** — Minimal boilerplate, intuitive decorators/attributes

---

## Architecture Overview (FastAPI Python)

```
FastAPI (extends Starlette)
├── applications.py (4669 lines) — Main FastAPI class, app config, middleware setup
├── routing.py (4508 lines) — APIRouter, route registration, path operations
├── params.py (755 lines) — Query, Path, Header, Cookie, Body parameter classes
├── param_functions.py (2369 lines) — Parameter extraction functions
├── dependencies/
│   ├── models.py — Dependant dataclass (DI graph node)
│   └── utils.py (1021 lines) — Dependency resolution, parameter binding
├── openapi/
│   ├── models.py — OpenAPI schema Pydantic models
│   ├── utils.py — Schema generation from routes
│   └── docs.py — Swagger UI / ReDoc HTML generation
├── security/
│   ├── oauth2.py — OAuth2 password/code flows
│   ├── http.py — HTTP Basic/Bearer
│   └── api_key.py — API key auth
├── encoders.py — JSON serialization (jsonable_encoder)
├── exceptions.py — HTTPException, validation errors
└── responses.py — Response types
```

**Key Dependencies:**
- **Starlette** — ASGI framework (routing, middleware, request/response)
- **Pydantic** — Data validation, serialization, JSON Schema

---

## EXPLICIT EXCLUSIONS

These features will NOT be ported:

### 1. Python Runtime Introspection
- Type hint analysis at runtime (`inspect.signature`, `get_type_hints`)
- Forward reference resolution
- **Rust alternative:** Procedural macros analyze types at compile time

### 2. Pydantic-Specific Integration
- Pydantic v1/v2 compatibility layers
- `ModelField` wrapper classes
- Pydantic-based JSON Schema generation
- **Rust alternative:** `serde` for serialization, `validator`/`garde` for validation, `schemars` for JSON Schema

### 3. Backward Compatibility
- Deprecated parameter aliases (`regex` → `pattern`, `example` → `examples`)
- Pydantic v1 migration helpers
- Legacy OpenAPI 3.0 support (target 3.1 only)

### 4. Built-in Documentation UIs
- Bundled Swagger UI HTML/JS
- Bundled ReDoc HTML/JS
- **Rust alternative:** Serve static assets from CDN or separate crate

### 5. CLI Tooling
- `fastapi dev` / `fastapi run` commands
- Cloud deployment integration
- **Rust alternative:** Separate binary crate if needed

### 6. TestClient
- HTTPX-based test client
- **Rust alternative:** Use `axum::test` or `tower::ServiceExt`

### 7. Multipart Form Handling
- python-multipart integration
- **Rust alternative:** `multer` crate (already in Axum ecosystem)

### 8. Background Tasks (Initial Phase)
- `BackgroundTasks` with Starlette's task queue
- **Rust alternative:** Tokio spawn, or defer to Phase 2

### 9. WebSocket Support (Initial Phase)
- WebSocket routing and handling
- **Rust alternative:** Axum's WebSocket extractor, defer to Phase 2

### 10. Middleware Stack
- ASGI middleware chain
- `BaseHTTPMiddleware` wrapper
- **Rust alternative:** Tower middleware (`tower::Layer`)

---

## Minimal Dependency Stack

### Core Dependencies (ONLY THESE)

| Crate | Purpose | Why Essential |
|-------|---------|---------------|
| `asupersync` | Async runtime | **OUR OWN** - co-developed, cancel-correct, capability-secure |
| `serde` | Serialization traits | Industry standard, zero-cost |
| `serde_json` | JSON parsing | Fast, well-optimized |

### Built From Scratch (in asupersync or fastapi_rust)

| Component | Location | Why Custom |
|-----------|----------|------------|
| **Async Runtime** | asupersync | Structured concurrency, cancel-correctness |
| **TCP/IO** | asupersync | Integrated with runtime, zero-copy |
| **HTTP Parser** | fastapi_rust | Zero-copy, minimal allocations |
| **Router** | fastapi_rust | Trie-based, compile-time route table |
| **Extractors** | fastapi_rust | Zero-copy parsing, no trait objects |
| **Validation** | fastapi_rust | Compile-time generated validators |
| **DI System** | fastapi_rust | Static dispatch, capability-based via Cx |
| **OpenAPI** | fastapi_rust | Compile-time schema generation |

### Explicitly NOT Using

| Crate | Reason |
|-------|--------|
| tokio | Using asupersync instead - cancel-correct, deterministic |
| hyper | Building our own HTTP - tighter integration |
| Axum | Too many layers, hidden allocations |
| Tower | Service trait overhead unnecessary |
| utoipa | Runtime schema building |
| validator | Runtime reflection |

---

## Co-Development with Asupersync

**Location:** `/data/projects/asupersync`

### Asupersync Current State

| Component | Status |
|-----------|--------|
| Scheduler (3-lane) | ✅ Implemented |
| Capability context (Cx) | ✅ Implemented |
| Channels (oneshot, mpsc) | ✅ Implemented |
| Combinators (join, race, timeout) | ✅ Implemented |
| Arena allocator | ✅ Implemented |
| Trace infrastructure | ✅ Implemented |
| Lab runtime structure | ✅ Implemented |
| **Future execution loop** | 🔜 Phase 0 |
| **I/O integration** | 🔜 Phase 2 |

### What Asupersync Needs for FastAPI

1. **Phase 0 completion**: Actual task polling/execution
2. **TCP listener/stream**: Accept connections, read/write bytes
3. **Timer integration**: Timeouts for HTTP requests
4. **Graceful shutdown**: Cancel-correct server shutdown

### Why This Pairing is Perfect

| Asupersync Feature | FastAPI Benefit |
|--------------------|-----------------|
| Structured concurrency | Request handlers can't orphan tasks |
| Cancel-correct shutdown | Graceful server stop, no dropped connections |
| Capability-based `Cx` | Request context flows naturally |
| Deterministic lab runtime | Test HTTP handlers deterministically |
| Budget-bounded cleanup | HTTP timeout guarantees |
| Two-phase channels | No lost responses during shutdown |

---

## Phased Implementation (Co-Development)

### Phase 0: Asupersync Foundation (PARALLEL)
**Goal:** Get asupersync executing tasks

**In asupersync:**
- [ ] Complete task polling loop
- [ ] Region close → quiescence
- [ ] Basic spawn + await working
- [ ] Lab runtime executing deterministically

### Phase 1: TCP + HTTP Parser
**Goal:** Accept HTTP requests, send responses

**In asupersync:**
- [ ] `TcpListener` type (wraps std::net with async)
- [ ] `TcpStream` type with read/write futures
- [ ] Non-blocking I/O via mio or raw epoll/kqueue

**In fastapi_rust:**
- [ ] Project structure (workspace)
- [ ] Zero-copy HTTP/1.1 request parser
- [ ] HTTP response builder
- [ ] Basic server loop: accept → parse → respond

### Phase 2: Router + Extractors
**Goal:** Type-safe routing with automatic parameter extraction

**In fastapi_rust:**
- [ ] Trie-based router (compile-time route table)
- [ ] `#[get]`, `#[post]`, etc. proc macros
- [ ] Path parameter extraction (`/items/{id}`)
- [ ] Query parameter extraction (`?q=...`)
- [ ] JSON body extraction via serde
- [ ] `Cx` integration (request context = capability token)

### Phase 3: Validation + Error Handling
**Goal:** Automatic validation with good errors

**In fastapi_rust:**
- [ ] Compile-time validator generation
- [ ] `#[validate]` derive macro
- [ ] HTTPException equivalent (enum-based)
- [ ] Validation error → JSON response
- [ ] Status code handling

### Phase 4: Dependency Injection
**Goal:** `Depends()` equivalent using Cx capabilities

**In fastapi_rust:**
- [ ] `#[depends]` attribute
- [ ] Request-scoped dependency caching
- [ ] Nested dependency resolution
- [ ] Dependencies as extractors

### Phase 5: OpenAPI Generation
**Goal:** Automatic schema from types

**In fastapi_rust:**
- [ ] Route metadata at compile time
- [ ] OpenAPI 3.1 schema generation
- [ ] JSON Schema for request/response
- [ ] `/openapi.json` endpoint

### Phase 6: Security + Advanced
**Goal:** Auth and production features

**In fastapi_rust:**
- [ ] HTTP Basic/Bearer auth extractors
- [ ] API key extraction
- [ ] Form data + file uploads
- [ ] Header/Cookie parameters
- [ ] Graceful shutdown (asupersync cancel-correct)

---

## Success Criteria

1. **10x smaller binary** than Python + dependencies
2. **10-50x faster cold start** (no interpreter)
3. **Compile-time route validation** — Invalid routes fail at build
4. **Zero runtime reflection** — All type analysis via macros
5. **Familiar API** — FastAPI users recognize the patterns

---

## Next Steps

1. **Create EXISTING_FASTAPI_STRUCTURE.md** — Deep dive extraction of all data structures, validation rules, and behaviors
2. **Create PROPOSED_RUST_ARCHITECTURE.md** — Detailed Rust design referencing Axum/utoipa patterns
3. **Implement Phase 1** — Basic routing proof-of-concept

---

## File Inventory (Legacy)

| File | Lines | Purpose | Port Priority |
|------|-------|---------|---------------|
| `applications.py` | 4669 | Main app class | High (extract config options) |
| `routing.py` | 4508 | Route handling | High (core logic) |
| `param_functions.py` | 2369 | Parameter functions | High |
| `params.py` | 755 | Parameter classes | High |
| `dependencies/utils.py` | 1021 | DI resolution | High |
| `dependencies/models.py` | 194 | Dependant class | High |
| `openapi/utils.py` | 567 | Schema generation | Medium |
| `openapi/models.py` | 438 | OpenAPI types | Medium |
| `security/oauth2.py` | 663 | OAuth2 | Medium |
| `security/http.py` | 423 | HTTP auth | Medium |
| `encoders.py` | 346 | JSON encoding | Low (serde handles) |
| `exceptions.py` | 246 | Error types | Medium |
| `_compat/` | ~600 | Pydantic compat | Skip |

---

## Anti-Patterns to Avoid

1. **Line-by-line translation** — Python idioms don't map to Rust
2. **Runtime type analysis** — Use compile-time macros
3. **Stringly-typed APIs** — Leverage Rust's type system
4. **Global mutable state** — Use Axum's State extractor pattern
5. **Exception-based flow** — Use Result types

---

*Document created: Phase 1 Planning*
*Last updated: 2026-01-17*
