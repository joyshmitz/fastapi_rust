//! Radix trie router implementation.

use crate::r#match::RouteMatch;
use fastapi_core::Method;
use std::collections::HashMap;

/// Path parameter type converter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Converter {
    /// String (default).
    Str,
    /// Integer (i64).
    Int,
    /// Float (f64).
    Float,
    /// UUID.
    Uuid,
    /// Path segment (can contain /).
    Path,
}

impl Converter {
    /// Check if a value matches this converter.
    #[must_use]
    pub fn matches(&self, value: &str) -> bool {
        match self {
            Self::Str => true,
            Self::Int => value.parse::<i64>().is_ok(),
            Self::Float => value.parse::<f64>().is_ok(),
            Self::Uuid => is_uuid(value),
            Self::Path => true,
        }
    }
}

fn is_uuid(s: &str) -> bool {
    // Simple UUID check: 8-4-4-4-12 hex digits
    if s.len() != 36 {
        return false;
    }
    let parts: Vec<_> = s.split('-').collect();
    if parts.len() != 5 {
        return false;
    }
    parts[0].len() == 8
        && parts[1].len() == 4
        && parts[2].len() == 4
        && parts[3].len() == 4
        && parts[4].len() == 12
        && parts.iter().all(|p| p.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Path parameter information.
#[derive(Debug, Clone)]
pub struct ParamInfo {
    /// Parameter name.
    pub name: String,
    /// Type converter.
    pub converter: Converter,
}

/// A route definition.
pub struct Route {
    /// Route path pattern.
    pub path: String,
    /// HTTP method.
    pub method: Method,
    /// Operation ID for OpenAPI.
    pub operation_id: String,
    // TODO: Handler function pointer
    // TODO: OpenAPI metadata
}

impl Route {
    /// Create a new route.
    #[must_use]
    pub fn new(method: Method, path: impl Into<String>) -> Self {
        let path = path.into();
        let operation_id = path.replace('/', "_").replace(['{', '}'], "");
        Self {
            path,
            method,
            operation_id,
        }
    }
}

/// Trie node.
struct Node {
    segment: String,
    children: Vec<Node>,
    param: Option<ParamInfo>,
    routes: HashMap<Method, usize>,
}

impl Node {
    fn new(segment: impl Into<String>) -> Self {
        Self {
            segment: segment.into(),
            children: Vec::new(),
            param: None,
            routes: HashMap::new(),
        }
    }

    fn find_static(&self, segment: &str) -> Option<&Node> {
        self.children
            .iter()
            .find(|c| c.param.is_none() && c.segment == segment)
    }

    fn find_param(&self) -> Option<&Node> {
        self.children.iter().find(|c| c.param.is_some())
    }
}

/// Radix trie router.
pub struct Router {
    root: Node,
    routes: Vec<Route>,
}

impl Router {
    /// Create an empty router.
    #[must_use]
    pub fn new() -> Self {
        Self {
            root: Node::new(""),
            routes: Vec::new(),
        }
    }

    /// Add a route.
    pub fn add(&mut self, route: Route) {
        let route_idx = self.routes.len();
        let path = route.path.clone();
        let method = route.method;
        self.routes.push(route);

        let segments = parse_path(&path);
        let mut node = &mut self.root;

        for seg in segments {
            let (segment, param) = match seg {
                PathSegment::Static(s) => (s.to_string(), None),
                PathSegment::Param { name, converter } => {
                    let info = ParamInfo {
                        name: name.to_string(),
                        converter,
                    };
                    (format!("{{{name}}}"), Some(info))
                }
            };

            // Find or create child
            let child_idx = node
                .children
                .iter()
                .position(|c| c.segment == segment);

            if let Some(idx) = child_idx {
                node = &mut node.children[idx];
            } else {
                let mut new_node = Node::new(&segment);
                new_node.param = param;
                node.children.push(new_node);
                node = node.children.last_mut().unwrap();
            }
        }

        node.routes.insert(method, route_idx);
    }

    /// Match a path and method.
    #[must_use]
    pub fn match_path<'a>(&'a self, path: &'a str, method: Method) -> Option<RouteMatch<'a>> {
        let segments: Vec<_> = path.split('/').filter(|s| !s.is_empty()).collect();
        let mut params = Vec::new();
        let mut node = &self.root;

        for segment in segments {
            // Try static match first
            if let Some(child) = node.find_static(segment) {
                node = child;
                continue;
            }

            // Try parameter match
            if let Some(child) = node.find_param() {
                if let Some(ref info) = child.param {
                    if info.converter.matches(segment) {
                        params.push((info.name.as_str(), segment));
                        node = child;
                        continue;
                    }
                }
            }

            return None;
        }

        node.routes.get(&method).map(|&idx| RouteMatch {
            route: &self.routes[idx],
            params,
        })
    }

    /// Get all routes.
    #[must_use]
    pub fn routes(&self) -> &[Route] {
        &self.routes
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

enum PathSegment<'a> {
    Static(&'a str),
    Param { name: &'a str, converter: Converter },
}

fn parse_path(path: &str) -> Vec<PathSegment<'_>> {
    path.split('/')
        .filter(|s| !s.is_empty())
        .map(|s| {
            if s.starts_with('{') && s.ends_with('}') {
                let inner = &s[1..s.len() - 1];
                let (name, converter) = if let Some(pos) = inner.find(':') {
                    let conv = match &inner[pos + 1..] {
                        "int" => Converter::Int,
                        "float" => Converter::Float,
                        "uuid" => Converter::Uuid,
                        "path" => Converter::Path,
                        _ => Converter::Str,
                    };
                    (&inner[..pos], conv)
                } else {
                    (inner, Converter::Str)
                };
                PathSegment::Param { name, converter }
            } else {
                PathSegment::Static(s)
            }
        })
        .collect()
}
