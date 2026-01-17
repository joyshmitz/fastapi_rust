//! Route attribute macro implementation.

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn, LitStr};

pub fn route_impl(method: &str, attr: TokenStream, item: TokenStream) -> TokenStream {
    let path = parse_macro_input!(attr as LitStr);
    let input_fn = parse_macro_input!(item as ItemFn);

    let fn_name = &input_fn.sig.ident;
    let fn_vis = &input_fn.vis;
    let fn_block = &input_fn.block;
    let fn_inputs = &input_fn.sig.inputs;
    let fn_output = &input_fn.sig.output;
    let fn_asyncness = &input_fn.sig.asyncness;

    let route_fn_name = syn::Ident::new(
        &format!("__route_{fn_name}"),
        fn_name.span(),
    );

    let method_ident = syn::Ident::new(method, proc_macro2::Span::call_site());
    let path_str = path.value();

    // For now, just wrap the function and generate metadata
    // Full implementation would analyze parameters and generate extraction code
    let expanded = quote! {
        #fn_vis #fn_asyncness fn #fn_name(#fn_inputs) #fn_output #fn_block

        #[doc(hidden)]
        #[allow(non_snake_case)]
        pub fn #route_fn_name() -> fastapi_router::Route {
            fastapi_router::Route::new(
                fastapi_core::Method::#method_ident,
                #path_str,
            )
        }
    };

    TokenStream::from(expanded)
}
