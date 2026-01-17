//! Route matching result.

use crate::trie::Route;

/// A matched route with extracted parameters.
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
}
