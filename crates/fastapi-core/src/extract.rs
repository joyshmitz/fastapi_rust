//! Request extraction traits.

use crate::context::RequestContext;
use crate::request::Request;
use crate::response::IntoResponse;
use std::future::Future;

/// Trait for types that can be extracted from a request.
///
/// This is the core abstraction for request handlers. Each parameter
/// in a handler function implements this trait.
///
/// The `ctx` parameter provides access to the request context, including
/// asupersync's capability context for cancellation checkpoints and
/// budget-aware operations.
///
/// # Example
///
/// ```ignore
/// use fastapi_core::{FromRequest, Request, RequestContext};
///
/// struct MyExtractor(String);
///
/// impl FromRequest for MyExtractor {
///     type Error = std::convert::Infallible;
///
///     async fn from_request(
///         ctx: &RequestContext,
///         req: &mut Request,
///     ) -> Result<Self, Self::Error> {
///         // Check for cancellation before expensive work
///         let _ = ctx.checkpoint();
///         Ok(MyExtractor("extracted".to_string()))
///     }
/// }
/// ```
pub trait FromRequest: Sized {
    /// Error type when extraction fails.
    type Error: IntoResponse;

    /// Extract a value from the request.
    ///
    /// # Parameters
    ///
    /// - `ctx`: The request context providing access to asupersync capabilities
    /// - `req`: The HTTP request to extract from
    fn from_request(
        ctx: &RequestContext,
        req: &mut Request,
    ) -> impl Future<Output = Result<Self, Self::Error>> + Send;
}

// Implement for Option to make extractors optional
impl<T: FromRequest> FromRequest for Option<T> {
    type Error = std::convert::Infallible;

    async fn from_request(ctx: &RequestContext, req: &mut Request) -> Result<Self, Self::Error> {
        Ok(T::from_request(ctx, req).await.ok())
    }
}

// Implement for RequestContext itself - allows handlers to receive the context
impl FromRequest for RequestContext {
    type Error = std::convert::Infallible;

    async fn from_request(ctx: &RequestContext, _req: &mut Request) -> Result<Self, Self::Error> {
        Ok(ctx.clone())
    }
}
