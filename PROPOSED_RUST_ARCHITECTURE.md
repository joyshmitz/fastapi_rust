# Proposed Rust Architecture

> **Design from spec, not translation.** This document describes how to implement FastAPI's behaviors in idiomatic Rust.

**Reference:** `EXISTING_FASTAPI_STRUCTURE.md` (THE SPEC)
**Runtime:** asupersync (co-developed)
**Created:** 2026-01-17

---

## Table of Contents

1. [Design Principles](#1-design-principles)
2. [Crate Structure](#2-crate-structure)
3. [HTTP Layer](#3-http-layer)
4. [Router Design](#4-router-design)
5. [Extractor System](#5-extractor-system)
6. [Validation](#6-validation)
7. [Dependency Injection](#7-dependency-injection)
8. [Security Extractors](#8-security-extractors)
9. [OpenAPI Generation](#9-openapi-generation)
10. [Error Handling](#10-error-handling)
11. [Application Builder](#11-application-builder)

---

## 1. Design Principles

### 1.1 Zero-Cost Abstractions

| Principle | Implementation |
|-----------|----------------|
| No runtime reflection | Proc macros analyze types at compile time |
| No trait objects on hot path | Monomorphization via generics |
| No allocations on fast path | Pre-allocated buffers, arena allocation |
| Inline everything hot | `#[inline(always)]` on critical paths |

### 1.2 Compile-Time Guarantees

```rust
// Route type safety - invalid routes fail at compile time
#[get("/items/{item_id}")]
async fn get_item(
    cx: &Cx,
    item_id: Path<i64>,      // Type checked
    q: Query<Option<String>>, // Optional query
) -> Json<Item> { ... }
```

### 1.3 Capability-Based Request Context

Use asupersync's `Cx` as the request context carrier:

```rust
// Cx provides:
// - Cancellation token
// - Budget/timeout
// - Request-scoped values (dependencies)
async fn handler(cx: &Cx, ...) -> Response { ... }
```

---

## 2. Crate Structure

```
fastapi_rust/
├── Cargo.toml                    # Workspace root
├── crates/
│   ├── fastapi/                  # Main library (re-exports)
│   │   ├── Cargo.toml
│   │   └── src/lib.rs
│   ├── fastapi-core/             # Core types, traits
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── request.rs        # Request type
│   │       ├── response.rs       # Response types
│   │       ├── error.rs          # Error types
│   │       └── extract.rs        # FromRequest trait
│   ├── fastapi-http/             # HTTP/1.1 parser
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── parser.rs         # Zero-copy parser
│   │       ├── response.rs       # Response builder
│   │       └── server.rs         # Accept loop
│   ├── fastapi-router/           # Trie-based router
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── trie.rs           # Radix trie
│   │       └── match.rs          # Path matching
│   ├── fastapi-macros/           # Proc macros
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── route.rs          # #[get], #[post], etc.
│   │       ├── validate.rs       # #[validate]
│   │       └── openapi.rs        # Schema generation
│   └── fastapi-openapi/          # OpenAPI 3.1 types
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── schema.rs         # JSON Schema types
│           └── spec.rs           # OpenAPI document
```

### 2.1 Dependency Graph

```
fastapi (facade)
├── fastapi-core
├── fastapi-http
│   └── fastapi-core
├── fastapi-router
│   └── fastapi-core
├── fastapi-macros
│   └── fastapi-core (types only)
└── fastapi-openapi
    └── fastapi-core
```

### 2.2 External Dependencies

```toml
[workspace.dependencies]
# Runtime (our own)
asupersync = { path = "../asupersync" }

# Serialization (only these)
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

---

## 3. HTTP Layer

### 3.1 Request Type

```rust
/// Zero-copy HTTP request
pub struct Request<'a> {
    method: Method,
    path: &'a str,
    query: Option<&'a str>,
    headers: Headers<'a>,
    body: Body<'a>,

    // Extensions for extracted values
    extensions: Extensions,
}

pub enum Method {
    Get, Post, Put, Delete, Patch, Options, Head, Trace,
}

pub struct Headers<'a> {
    // Flat array of (name, value) pairs
    pairs: &'a [(HeaderName<'a>, &'a [u8])],
}

pub enum Body<'a> {
    Empty,
    Bytes(&'a [u8]),
    Stream(BodyStream),
}
```

### 3.2 Response Type

```rust
pub struct Response {
    status: StatusCode,
    headers: Vec<(HeaderName<'static>, HeaderValue)>,
    body: ResponseBody,
}

pub enum ResponseBody {
    Empty,
    Bytes(Vec<u8>),
    Json(Box<RawValue>),  // Pre-serialized JSON
    Stream(Box<dyn AsyncRead>),
}

impl Response {
    pub fn ok() -> Self { Self::with_status(StatusCode::OK) }
    pub fn created() -> Self { Self::with_status(StatusCode::CREATED) }
    pub fn no_content() -> Self { Self::with_status(StatusCode::NO_CONTENT) }

    pub fn json<T: Serialize>(value: T) -> Result<Self, Error> { ... }

    pub fn header(mut self, name: HeaderName<'static>, value: impl Into<HeaderValue>) -> Self { ... }
}
```

### 3.3 Status Codes

```rust
pub struct StatusCode(u16);

impl StatusCode {
    // Informational
    pub const CONTINUE: Self = Self(100);
    pub const SWITCHING_PROTOCOLS: Self = Self(101);

    // Success
    pub const OK: Self = Self(200);
    pub const CREATED: Self = Self(201);
    pub const ACCEPTED: Self = Self(202);
    pub const NO_CONTENT: Self = Self(204);

    // Redirection
    pub const MOVED_PERMANENTLY: Self = Self(301);
    pub const FOUND: Self = Self(302);
    pub const NOT_MODIFIED: Self = Self(304);
    pub const TEMPORARY_REDIRECT: Self = Self(307);
    pub const PERMANENT_REDIRECT: Self = Self(308);

    // Client Error
    pub const BAD_REQUEST: Self = Self(400);
    pub const UNAUTHORIZED: Self = Self(401);
    pub const FORBIDDEN: Self = Self(403);
    pub const NOT_FOUND: Self = Self(404);
    pub const METHOD_NOT_ALLOWED: Self = Self(405);
    pub const UNPROCESSABLE_ENTITY: Self = Self(422);

    // Server Error
    pub const INTERNAL_SERVER_ERROR: Self = Self(500);

    /// Status codes that must not have a body
    pub fn allows_body(self) -> bool {
        !matches!(self.0, 100..=103 | 204 | 304)
    }
}
```

---

## 4. Router Design

### 4.1 Radix Trie Router

```rust
/// Compile-time route table
pub struct Router {
    root: Node,
    routes: Vec<Route>,
}

struct Node {
    // Static segment
    segment: &'static str,

    // Children (sorted by segment for binary search)
    children: Vec<Node>,

    // Parameter capture
    param: Option<ParamInfo>,

    // Route index if this is a terminal node
    route_idx: Option<usize>,
}

struct ParamInfo {
    name: &'static str,
    converter: Converter,
}

enum Converter {
    Str,      // Default
    Int,      // :int
    Float,    // :float
    Uuid,     // :uuid
    Path,     // :path (matches /)
}
```

### 4.2 Route Matching

```rust
pub struct RouteMatch<'a> {
    route: &'a Route,
    params: SmallVec<[(&'static str, &'a str); 4]>,
}

impl Router {
    pub fn match_path<'a>(&'a self, path: &'a str) -> Option<RouteMatch<'a>> {
        let mut node = &self.root;
        let mut params = SmallVec::new();

        for segment in path.split('/').filter(|s| !s.is_empty()) {
            // Try static match first (binary search)
            if let Some(child) = node.find_static(segment) {
                node = child;
                continue;
            }

            // Try parameter match
            if let Some(child) = node.find_param() {
                if child.param.as_ref()?.converter.matches(segment) {
                    params.push((child.param.as_ref()?.name, segment));
                    node = child;
                    continue;
                }
            }

            return None;
        }

        node.route_idx.map(|idx| RouteMatch {
            route: &self.routes[idx],
            params,
        })
    }
}
```

### 4.3 Route Registration Macro

```rust
/// Generated at compile time
#[proc_macro_attribute]
pub fn get(attr: TokenStream, item: TokenStream) -> TokenStream {
    route_impl(Method::Get, attr, item)
}

// Usage:
#[get("/items/{item_id}")]
async fn get_item(cx: &Cx, item_id: Path<i64>) -> Json<Item> {
    // ...
}

// Expands to:
fn __route_get_item() -> Route {
    Route {
        path: "/items/{item_id}",
        method: Method::Get,
        handler: |cx, req| Box::pin(async move {
            let item_id = Path::<i64>::from_request(cx, &req).await?;
            get_item(cx, item_id).await.into_response()
        }),
        // OpenAPI metadata
        operation_id: "get_item",
        summary: None,
        // ...
    }
}
```

---

## 5. Extractor System

### 5.1 FromRequest Trait

```rust
/// Extract a value from an HTTP request
pub trait FromRequest: Sized {
    /// Error type when extraction fails
    type Error: IntoResponse;

    /// Extract from request
    async fn from_request(cx: &Cx, req: &Request<'_>) -> Result<Self, Self::Error>;

    /// OpenAPI parameter info (for schema generation)
    fn openapi_param() -> Option<Parameter> { None }

    /// OpenAPI request body info
    fn openapi_body() -> Option<RequestBody> { None }
}
```

### 5.2 Path Extractor

```rust
/// Extract path parameters
pub struct Path<T>(pub T);

impl<T: DeserializeOwned> FromRequest for Path<T> {
    type Error = PathError;

    async fn from_request(cx: &Cx, req: &Request<'_>) -> Result<Self, Self::Error> {
        let params = req.extensions().get::<PathParams>()
            .ok_or(PathError::NoParams)?;

        // For single value: deserialize directly
        // For struct: build map and deserialize
        let value = if TypeId::of::<T>() == TypeId::of::<String>() {
            // Single string param
            serde_json::from_str(&format!("\"{}\"", params.get(0)?.1))?
        } else {
            // Struct from params
            let map: HashMap<_, _> = params.iter().collect();
            serde_json::from_value(serde_json::to_value(&map)?)?
        };

        Ok(Path(value))
    }
}
```

### 5.3 Query Extractor

```rust
/// Extract query parameters
pub struct Query<T>(pub T);

impl<T: DeserializeOwned> FromRequest for Query<T> {
    type Error = QueryError;

    async fn from_request(cx: &Cx, req: &Request<'_>) -> Result<Self, Self::Error> {
        let query = req.query().unwrap_or("");
        let value = serde_urlencoded::from_str(query)?;
        Ok(Query(value))
    }
}

// Usage with Option for optional query params
#[get("/items")]
async fn list_items(
    cx: &Cx,
    Query(params): Query<ListParams>,
) -> Json<Vec<Item>> { ... }

#[derive(Deserialize)]
struct ListParams {
    #[serde(default)]
    skip: usize,
    #[serde(default = "default_limit")]
    limit: usize,
    q: Option<String>,
}
```

### 5.4 Header Extractor

```rust
/// Extract a single header
pub struct Header<T>(pub T);

impl<T: FromStr> FromRequest for Header<T>
where
    T::Err: std::error::Error,
{
    type Error = HeaderError;

    async fn from_request(cx: &Cx, req: &Request<'_>) -> Result<Self, Self::Error> {
        // Header name from type annotation via macro
        let name = T::HEADER_NAME; // Set by derive macro
        let value = req.headers()
            .get(name)
            .ok_or(HeaderError::Missing(name))?;
        let parsed = std::str::from_utf8(value)?
            .parse()
            .map_err(|e| HeaderError::Parse(name, e))?;
        Ok(Header(parsed))
    }
}

// Convert underscores to hyphens (like FastAPI)
// user_agent -> User-Agent
fn convert_header_name(rust_name: &str) -> String {
    rust_name
        .split('_')
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                None => String::new(),
                Some(c) => c.to_uppercase().chain(chars).collect(),
            }
        })
        .collect::<Vec<_>>()
        .join("-")
}
```

### 5.5 Cookie Extractor

```rust
/// Extract a cookie value
pub struct Cookie<T>(pub T);

impl<T: DeserializeOwned> FromRequest for Cookie<T> {
    type Error = CookieError;

    async fn from_request(cx: &Cx, req: &Request<'_>) -> Result<Self, Self::Error> {
        let cookie_header = req.headers()
            .get("cookie")
            .ok_or(CookieError::NoCookies)?;

        // Parse cookie header
        let cookies = parse_cookies(cookie_header)?;
        let value = serde_json::from_value(serde_json::to_value(&cookies)?)?;
        Ok(Cookie(value))
    }
}
```

### 5.6 JSON Body Extractor

```rust
/// Extract JSON body
pub struct Json<T>(pub T);

impl<T: DeserializeOwned> FromRequest for Json<T> {
    type Error = JsonError;

    async fn from_request(cx: &Cx, req: &Request<'_>) -> Result<Self, Self::Error> {
        // Check content-type
        let content_type = req.headers().get("content-type");
        if !is_json_content_type(content_type) {
            return Err(JsonError::WrongContentType);
        }

        // Read body
        let body = req.body().bytes().await?;

        // Parse JSON
        let value = serde_json::from_slice(&body)?;
        Ok(Json(value))
    }
}

// IntoResponse for Json
impl<T: Serialize> IntoResponse for Json<T> {
    fn into_response(self) -> Response {
        match serde_json::to_vec(&self.0) {
            Ok(bytes) => Response::ok()
                .header("content-type", "application/json")
                .body(ResponseBody::Bytes(bytes)),
            Err(e) => Response::internal_error()
                .body(ResponseBody::Bytes(e.to_string().into_bytes())),
        }
    }
}
```

---

## 6. Validation

### 6.1 Validate Derive Macro

```rust
/// Compile-time validation code generation
#[derive(Validate)]
pub struct CreateItem {
    #[validate(length(min = 1, max = 100))]
    pub name: String,

    #[validate(range(min = 0.0))]
    pub price: f64,

    #[validate(email)]
    pub owner_email: String,

    #[validate(regex = "^[A-Z]{3}$")]
    pub code: String,
}
```

### 6.2 Validation Constraints

```rust
/// Validation constraint trait
pub trait Constraint<T> {
    fn validate(&self, value: &T) -> Result<(), ValidationError>;
}

// String constraints
pub struct Length { pub min: Option<usize>, pub max: Option<usize> }
pub struct Pattern { pub regex: &'static str }

// Numeric constraints
pub struct Range<T> { pub min: Option<T>, pub max: Option<T> }
pub struct MultipleOf<T> { pub value: T }

// Generated validation
impl Validate for CreateItem {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = Vec::new();

        // name: length(min = 1, max = 100)
        if self.name.len() < 1 {
            errors.push(ValidationError {
                loc: vec!["name".into()],
                msg: "String too short".into(),
                error_type: "string_too_short",
                ctx: json!({"min_length": 1}),
            });
        }
        if self.name.len() > 100 {
            errors.push(ValidationError {
                loc: vec!["name".into()],
                msg: "String too long".into(),
                error_type: "string_too_long",
                ctx: json!({"max_length": 100}),
            });
        }

        // price: range(min = 0.0)
        if self.price < 0.0 {
            errors.push(ValidationError {
                loc: vec!["price".into()],
                msg: "Value too small".into(),
                error_type: "greater_than_equal",
                ctx: json!({"ge": 0.0}),
            });
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ValidationErrors(errors))
        }
    }
}
```

### 6.3 Validating Extractor

```rust
/// JSON body with validation
pub struct ValidJson<T>(pub T);

impl<T: DeserializeOwned + Validate> FromRequest for ValidJson<T> {
    type Error = ValidationError;

    async fn from_request(cx: &Cx, req: &Request<'_>) -> Result<Self, Self::Error> {
        let Json(value) = Json::<T>::from_request(cx, req).await?;
        value.validate()?;
        Ok(ValidJson(value))
    }
}
```

---

## 7. Dependency Injection

### 7.1 Depends Pattern via Cx

```rust
/// Request-scoped dependency storage in Cx
impl Cx {
    /// Get or compute a dependency
    pub async fn get_or_insert<T: Send + Sync + 'static>(
        &self,
        key: TypeId,
        f: impl FnOnce() -> impl Future<Output = T>,
    ) -> &T {
        // Check cache first
        if let Some(value) = self.extensions().get::<T>() {
            return value;
        }

        // Compute and cache
        let value = f().await;
        self.extensions_mut().insert(value);
        self.extensions().get::<T>().unwrap()
    }
}
```

### 7.2 Dependency Extractor

```rust
/// Dependency injection extractor
pub struct Depends<T>(pub T);

impl<T: FromDependency> FromRequest for Depends<T> {
    type Error = T::Error;

    async fn from_request(cx: &Cx, req: &Request<'_>) -> Result<Self, Self::Error> {
        // Check for dependency override (testing)
        if let Some(override_fn) = cx.get_override::<T>() {
            return Ok(Depends(override_fn().await));
        }

        // Use cached or compute
        let value = cx.get_or_insert(
            TypeId::of::<T>(),
            || T::from_dependency(cx, req)
        ).await;

        Ok(Depends(value.clone()))
    }
}

/// Trait for types that can be injected as dependencies
pub trait FromDependency: Clone + Send + Sync + 'static {
    type Error: IntoResponse;

    async fn from_dependency(cx: &Cx, req: &Request<'_>) -> Result<Self, Self::Error>;
}
```

### 7.3 Database Connection Example

```rust
/// Database connection pool (app-level state)
#[derive(Clone)]
pub struct DbPool(/* ... */);

/// Request-scoped database connection
#[derive(Clone)]
pub struct DbConn(/* ... */);

impl FromDependency for DbConn {
    type Error = DbError;

    async fn from_dependency(cx: &Cx, req: &Request<'_>) -> Result<Self, Self::Error> {
        let pool = cx.state::<DbPool>()?;
        let conn = pool.get().await?;
        Ok(DbConn(conn))
    }
}

// Usage in handler
#[get("/users/{id}")]
async fn get_user(
    cx: &Cx,
    id: Path<i64>,
    Depends(db): Depends<DbConn>,
) -> Result<Json<User>, Error> {
    let user = db.query_one("SELECT * FROM users WHERE id = $1", &[&id.0]).await?;
    Ok(Json(user))
}
```

### 7.4 Chained Dependencies

```rust
/// Current user (depends on auth token)
#[derive(Clone)]
pub struct CurrentUser(pub User);

impl FromDependency for CurrentUser {
    type Error = AuthError;

    async fn from_dependency(cx: &Cx, req: &Request<'_>) -> Result<Self, Self::Error> {
        // Get auth token (another dependency)
        let Depends(token) = Depends::<AuthToken>::from_request(cx, req).await?;

        // Get db connection (another dependency)
        let Depends(db) = Depends::<DbConn>::from_request(cx, req).await?;

        // Look up user
        let user = db.query_one(
            "SELECT * FROM users WHERE token = $1",
            &[&token.0]
        ).await?;

        Ok(CurrentUser(user))
    }
}
```

---

## 8. Security Extractors

### 8.1 Bearer Token

```rust
/// Extract bearer token from Authorization header
pub struct BearerToken(pub String);

impl FromRequest for BearerToken {
    type Error = AuthError;

    async fn from_request(cx: &Cx, req: &Request<'_>) -> Result<Self, Self::Error> {
        let auth = req.headers()
            .get("authorization")
            .ok_or(AuthError::Missing)?;

        let auth_str = std::str::from_utf8(auth)?;
        let (scheme, token) = auth_str.split_once(' ')
            .ok_or(AuthError::InvalidFormat)?;

        if !scheme.eq_ignore_ascii_case("bearer") {
            return Err(AuthError::WrongScheme);
        }

        Ok(BearerToken(token.to_string()))
    }
}
```

### 8.2 HTTP Basic Auth

```rust
/// HTTP Basic authentication credentials
pub struct BasicAuth {
    pub username: String,
    pub password: String,
}

impl FromRequest for BasicAuth {
    type Error = AuthError;

    async fn from_request(cx: &Cx, req: &Request<'_>) -> Result<Self, Self::Error> {
        let auth = req.headers()
            .get("authorization")
            .ok_or_else(|| AuthError::missing_with_challenge("Basic"))?;

        let auth_str = std::str::from_utf8(auth)?;
        let (scheme, encoded) = auth_str.split_once(' ')
            .ok_or(AuthError::InvalidFormat)?;

        if !scheme.eq_ignore_ascii_case("basic") {
            return Err(AuthError::wrong_scheme_with_challenge("Basic"));
        }

        let decoded = base64::decode(encoded)?;
        let decoded_str = String::from_utf8(decoded)?;
        let (username, password) = decoded_str.split_once(':')
            .ok_or(AuthError::InvalidFormat)?;

        Ok(BasicAuth {
            username: username.to_string(),
            password: password.to_string(),
        })
    }
}
```

### 8.3 API Key

```rust
/// API key from query parameter
pub struct ApiKeyQuery<const NAME: &'static str>(pub String);

impl<const NAME: &'static str> FromRequest for ApiKeyQuery<NAME> {
    type Error = AuthError;

    async fn from_request(cx: &Cx, req: &Request<'_>) -> Result<Self, Self::Error> {
        let query = req.query().unwrap_or("");
        let params: HashMap<&str, &str> = serde_urlencoded::from_str(query)?;

        let key = params.get(NAME)
            .ok_or(AuthError::MissingApiKey)?;

        Ok(ApiKeyQuery(key.to_string()))
    }
}

/// API key from header
pub struct ApiKeyHeader<const NAME: &'static str>(pub String);

impl<const NAME: &'static str> FromRequest for ApiKeyHeader<NAME> {
    type Error = AuthError;

    async fn from_request(cx: &Cx, req: &Request<'_>) -> Result<Self, Self::Error> {
        let key = req.headers()
            .get(NAME)
            .ok_or(AuthError::MissingApiKey)?;

        Ok(ApiKeyHeader(std::str::from_utf8(key)?.to_string()))
    }
}

// Usage
#[get("/protected")]
async fn protected(
    cx: &Cx,
    ApiKeyHeader::<"X-API-Key">(key): ApiKeyHeader<"X-API-Key">,
) -> &'static str {
    "secret data"
}
```

### 8.4 Optional Authentication

```rust
/// Make any auth extractor optional
impl<T: FromRequest> FromRequest for Option<T> {
    type Error = Infallible;

    async fn from_request(cx: &Cx, req: &Request<'_>) -> Result<Self, Self::Error> {
        Ok(T::from_request(cx, req).await.ok())
    }
}

// Usage - optional bearer token
#[get("/maybe-auth")]
async fn maybe_auth(
    cx: &Cx,
    token: Option<BearerToken>,
) -> Json<Response> {
    match token {
        Some(t) => Json(Response::authenticated(&t.0)),
        None => Json(Response::anonymous()),
    }
}
```

---

## 9. OpenAPI Generation

### 9.1 Schema Trait

```rust
/// Generate JSON Schema for a type
pub trait JsonSchema {
    fn schema() -> Schema;
    fn schema_name() -> Option<&'static str> { None }
}

// Derive macro generates implementation
#[derive(JsonSchema)]
pub struct Item {
    pub id: i64,
    pub name: String,
    #[schema(nullable)]
    pub description: Option<String>,
}

// Generates:
impl JsonSchema for Item {
    fn schema() -> Schema {
        Schema::Object(ObjectSchema {
            properties: vec![
                ("id".into(), Schema::Integer),
                ("name".into(), Schema::String),
                ("description".into(), Schema::Nullable(Box::new(Schema::String))),
            ].into_iter().collect(),
            required: vec!["id".into(), "name".into()],
        })
    }

    fn schema_name() -> Option<&'static str> {
        Some("Item")
    }
}
```

### 9.2 OpenAPI Document Builder

```rust
pub struct OpenApiBuilder {
    info: Info,
    servers: Vec<Server>,
    paths: IndexMap<String, PathItem>,
    components: Components,
    tags: Vec<Tag>,
}

impl OpenApiBuilder {
    pub fn new(title: &str, version: &str) -> Self { ... }

    pub fn server(mut self, url: &str, description: Option<&str>) -> Self { ... }

    pub fn tag(mut self, name: &str, description: Option<&str>) -> Self { ... }

    /// Add route from macro-generated metadata
    pub fn route(mut self, route: &Route) -> Self {
        let path_item = self.paths
            .entry(route.path.to_string())
            .or_default();

        let operation = Operation {
            operation_id: Some(route.operation_id.to_string()),
            summary: route.summary.map(|s| s.to_string()),
            description: route.description.map(|s| s.to_string()),
            tags: route.tags.iter().map(|t| t.to_string()).collect(),
            parameters: route.collect_parameters(),
            request_body: route.request_body(),
            responses: route.responses(),
            deprecated: route.deprecated,
            security: route.security_requirements(),
        };

        match route.method {
            Method::Get => path_item.get = Some(operation),
            Method::Post => path_item.post = Some(operation),
            Method::Put => path_item.put = Some(operation),
            Method::Delete => path_item.delete = Some(operation),
            Method::Patch => path_item.patch = Some(operation),
            // ...
        }

        self
    }

    pub fn build(self) -> OpenApi { ... }
}
```

### 9.3 Route Metadata from Macros

```rust
/// Metadata extracted at compile time
pub struct Route {
    pub path: &'static str,
    pub method: Method,
    pub handler: Handler,

    // OpenAPI metadata
    pub operation_id: &'static str,
    pub summary: Option<&'static str>,
    pub description: Option<&'static str>,
    pub tags: &'static [&'static str],
    pub deprecated: bool,

    // Parameter schemas (generated from extractors)
    pub path_params: &'static [ParamSchema],
    pub query_params: &'static [ParamSchema],
    pub header_params: &'static [ParamSchema],

    // Body schema
    pub request_body: Option<BodySchema>,

    // Response schemas
    pub responses: &'static [ResponseSchema],

    // Security requirements
    pub security: &'static [SecurityRequirement],
}
```

---

## 10. Error Handling

### 10.1 Error Types

```rust
/// HTTP error that produces a response
pub struct HttpError {
    pub status: StatusCode,
    pub detail: Option<String>,
    pub headers: Vec<(HeaderName<'static>, HeaderValue)>,
}

impl HttpError {
    pub fn new(status: StatusCode) -> Self {
        Self { status, detail: None, headers: Vec::new() }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn with_header(mut self, name: HeaderName<'static>, value: HeaderValue) -> Self {
        self.headers.push((name, value));
        self
    }

    // Convenience constructors
    pub fn bad_request() -> Self { Self::new(StatusCode::BAD_REQUEST) }
    pub fn unauthorized() -> Self { Self::new(StatusCode::UNAUTHORIZED) }
    pub fn forbidden() -> Self { Self::new(StatusCode::FORBIDDEN) }
    pub fn not_found() -> Self { Self::new(StatusCode::NOT_FOUND) }
    pub fn internal() -> Self { Self::new(StatusCode::INTERNAL_SERVER_ERROR) }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let body = match self.detail {
            Some(detail) => serde_json::json!({ "detail": detail }),
            None => serde_json::json!({ "detail": self.status.canonical_reason() }),
        };

        let mut response = Response::with_status(self.status)
            .header("content-type", "application/json")
            .body(ResponseBody::Bytes(serde_json::to_vec(&body).unwrap()));

        for (name, value) in self.headers {
            response = response.header(name, value);
        }

        response
    }
}
```

### 10.2 Validation Error Response

```rust
/// Validation error (422 Unprocessable Entity)
pub struct ValidationErrors(pub Vec<ValidationError>);

#[derive(Serialize)]
pub struct ValidationError {
    #[serde(rename = "type")]
    pub error_type: &'static str,
    pub loc: Vec<String>,
    pub msg: String,
    pub input: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ctx: Option<serde_json::Value>,
}

impl IntoResponse for ValidationErrors {
    fn into_response(self) -> Response {
        Response::with_status(StatusCode::UNPROCESSABLE_ENTITY)
            .header("content-type", "application/json")
            .body(ResponseBody::Bytes(
                serde_json::to_vec(&json!({ "detail": self.0 })).unwrap()
            ))
    }
}
```

### 10.3 Result Return Type

```rust
/// Handler can return Result<T, E> where both T and E implement IntoResponse
impl<T: IntoResponse, E: IntoResponse> IntoResponse for Result<T, E> {
    fn into_response(self) -> Response {
        match self {
            Ok(v) => v.into_response(),
            Err(e) => e.into_response(),
        }
    }
}

// Usage
#[get("/items/{id}")]
async fn get_item(
    cx: &Cx,
    Path(id): Path<i64>,
    Depends(db): Depends<DbConn>,
) -> Result<Json<Item>, HttpError> {
    let item = db.find_item(id).await
        .map_err(|_| HttpError::not_found().with_detail("Item not found"))?;
    Ok(Json(item))
}
```

---

## 11. Application Builder

### 11.1 App Configuration

```rust
pub struct App {
    // Routing
    router: Router,

    // OpenAPI
    title: String,
    version: String,
    description: Option<String>,
    openapi_url: Option<String>,

    // State
    state: Extensions,

    // Middleware
    middleware: Vec<Box<dyn Middleware>>,

    // Error handlers
    exception_handlers: HashMap<TypeId, Box<dyn ExceptionHandler>>,
}

impl App {
    pub fn new() -> Self {
        Self {
            router: Router::new(),
            title: "FastAPI".to_string(),
            version: "0.1.0".to_string(),
            description: None,
            openapi_url: Some("/openapi.json".to_string()),
            state: Extensions::new(),
            middleware: Vec::new(),
            exception_handlers: HashMap::new(),
        }
    }

    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = title.into();
        self
    }

    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }

    pub fn state<T: Send + Sync + 'static>(mut self, state: T) -> Self {
        self.state.insert(state);
        self
    }

    pub fn route(mut self, route: Route) -> Self {
        self.router.add(route);
        self
    }

    pub fn include_router(mut self, router: impl IntoIterator<Item = Route>, prefix: &str) -> Self {
        for mut route in router {
            route.path = format!("{}{}", prefix, route.path).leak();
            self.router.add(route);
        }
        self
    }

    /// Serve the application
    pub async fn serve(self, addr: &str) -> Result<(), Error> {
        let listener = asupersync::net::TcpListener::bind(addr).await?;

        loop {
            let (stream, _addr) = listener.accept().await?;
            let app = self.clone();

            asupersync::spawn(async move {
                if let Err(e) = app.handle_connection(stream).await {
                    eprintln!("Connection error: {}", e);
                }
            });
        }
    }
}
```

### 11.2 Router Builder

```rust
pub struct RouterBuilder {
    prefix: String,
    tags: Vec<String>,
    dependencies: Vec<Box<dyn Dependency>>,
    routes: Vec<Route>,
}

impl RouterBuilder {
    pub fn new() -> Self {
        Self {
            prefix: String::new(),
            tags: Vec::new(),
            dependencies: Vec::new(),
            routes: Vec::new(),
        }
    }

    pub fn prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    pub fn tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    pub fn route(mut self, route: Route) -> Self {
        self.routes.push(route);
        self
    }

    pub fn build(self) -> Vec<Route> {
        self.routes.into_iter().map(|mut route| {
            route.path = format!("{}{}", self.prefix, route.path).leak();
            for tag in &self.tags {
                route.tags = Box::leak(
                    [route.tags, &[tag.as_str()]].concat().into_boxed_slice()
                );
            }
            route
        }).collect()
    }
}
```

---

## Implementation Phases

### Phase 1: Core Infrastructure
- [ ] fastapi-core types (Request, Response, Error)
- [ ] fastapi-http zero-copy parser
- [ ] Basic server loop with asupersync

### Phase 2: Routing & Extractors
- [ ] Radix trie router
- [ ] FromRequest trait and basic extractors (Path, Query, Json)
- [ ] Route macros (#[get], #[post], etc.)

### Phase 3: Validation
- [ ] Validate derive macro
- [ ] ValidJson extractor
- [ ] Error formatting (422 responses)

### Phase 4: Dependency Injection
- [ ] Cx-based dependency storage
- [ ] Depends extractor
- [ ] Dependency overrides for testing

### Phase 5: OpenAPI
- [ ] JsonSchema derive macro
- [ ] OpenAPI document builder
- [ ] /openapi.json endpoint

### Phase 6: Security
- [ ] Auth extractors (Bearer, Basic, ApiKey)
- [ ] Security scheme metadata for OpenAPI

---

*Document version: 1.0*
*Created: 2026-01-17*
