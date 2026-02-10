//! Route matching result.

use crate::trie::Route;
use crate::trie::{Converter, ParamInfo};
use fastapi_types::Method;

/// A matched route with extracted parameters.
#[derive(Debug)]
pub struct RouteMatch<'a> {
    /// The matched route.
    pub route: &'a Route,
    /// Extracted path parameters.
    pub params: Vec<(&'a str, &'a str)>,
}

impl<'a> RouteMatch<'a> {
    /// Get a parameter value by name.
    #[must_use]
    pub fn get_param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| *v)
    }

    /// Number of extracted parameters.
    #[must_use]
    pub fn param_count(&self) -> usize {
        self.params.len()
    }

    /// Returns true if there are no extracted parameters.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.params.is_empty()
    }

    /// Iterate over extracted parameters as `(name, value)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> + '_ {
        self.params.iter().map(|(k, v)| (*k, *v))
    }

    /// Returns true if the route declares the given param as a UUID converter.
    #[must_use]
    pub fn is_param_uuid(&self, name: &str) -> Option<bool> {
        self.route
            .path_params
            .iter()
            .find(|p: &&ParamInfo| p.name == name)
            .map(|p| p.converter == Converter::Uuid)
    }

    /// Parse a parameter as i64.
    pub fn get_param_int(&self, name: &str) -> Option<Result<i64, std::num::ParseIntError>> {
        self.get_param(name).map(str::parse::<i64>)
    }

    /// Parse a parameter as i32.
    pub fn get_param_i32(&self, name: &str) -> Option<Result<i32, std::num::ParseIntError>> {
        self.get_param(name).map(str::parse::<i32>)
    }

    /// Parse a parameter as u64.
    pub fn get_param_u64(&self, name: &str) -> Option<Result<u64, std::num::ParseIntError>> {
        self.get_param(name).map(str::parse::<u64>)
    }

    /// Parse a parameter as u32.
    pub fn get_param_u32(&self, name: &str) -> Option<Result<u32, std::num::ParseIntError>> {
        self.get_param(name).map(str::parse::<u32>)
    }

    /// Parse a parameter as f64.
    pub fn get_param_float(&self, name: &str) -> Option<Result<f64, std::num::ParseFloatError>> {
        self.get_param(name).map(str::parse::<f64>)
    }

    /// Parse a parameter as f32.
    pub fn get_param_f32(&self, name: &str) -> Option<Result<f32, std::num::ParseFloatError>> {
        self.get_param(name).map(str::parse::<f32>)
    }
}

/// Result of attempting to locate a route by path and method.
#[derive(Debug)]
pub enum RouteLookup<'a> {
    /// A route matched by path and method.
    Match(RouteMatch<'a>),
    /// Path matched, but method is not allowed.
    MethodNotAllowed { allowed: AllowedMethods },
    /// No route matched the path.
    NotFound,
}

/// Allowed methods for a matched path.
#[derive(Debug, Clone)]
pub struct AllowedMethods {
    methods: Vec<Method>,
}

impl AllowedMethods {
    /// Create a normalized allow list.
    ///
    /// - Adds `HEAD` if `GET` is present.
    /// - Sorts and de-duplicates for stable output.
    #[must_use]
    pub fn new(mut methods: Vec<Method>) -> Self {
        if methods.contains(&Method::Get) && !methods.contains(&Method::Head) {
            methods.push(Method::Head);
        }
        methods.sort_by_key(method_order);
        methods.dedup();
        Self { methods }
    }

    /// Access the normalized methods.
    #[must_use]
    pub fn methods(&self) -> &[Method] {
        &self.methods
    }

    /// Check whether a method is allowed.
    #[must_use]
    pub fn contains(&self, method: Method) -> bool {
        self.methods.contains(&method)
    }

    /// Format as an HTTP Allow header value.
    #[must_use]
    pub fn header_value(&self) -> String {
        let mut out = String::new();
        for (idx, method) in self.methods.iter().enumerate() {
            if idx > 0 {
                out.push_str(", ");
            }
            out.push_str(method.as_str());
        }
        out
    }
}

fn method_order(method: &Method) -> u8 {
    match *method {
        Method::Get => 0,
        Method::Head => 1,
        Method::Post => 2,
        Method::Put => 3,
        Method::Delete => 4,
        Method::Patch => 5,
        Method::Options => 6,
        Method::Trace => 7,
    }
}
