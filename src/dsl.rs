//! A declarative DSL for building requests.
//!
//! Generated models mirror Cybersource's deeply nested JSON, with every field
//! optional. [`build!`](crate::build!) lets you write just the fields you
//! need, in the same shape as the JSON, and works for **every** generated
//! model:
//!
//! ```
//! use cybersource::{amount, build, models::CreatePaymentRequest};
//!
//! let req = build!(CreatePaymentRequest {
//!     client_reference_information: { code: "TC50171_3" },
//!     processing_information: { capture: true },
//!     payment_information: {
//!         card: { number: "4111111111111111", expiration_month: "12", expiration_year: "2031" },
//!     },
//!     order_information: {
//!         amount_details: { total_amount: amount!("102.21"), currency: "USD" },
//!         line_items: [ { product_name: "Widget", unit_price: "51.10", quantity: 2 } ],
//!     },
//! });
//! assert_eq!(req.processing_information.unwrap().capture, Some(true));
//! ```
//!
//! Field syntax:
//!
//! | Syntax | Meaning |
//! |---|---|
//! | `field: { … }` | Nested object, created if absent. |
//! | `field: [ { … }, … ]` | List of objects. |
//! | `field: [ a, b ]` | List of values, each converted with `Into`. |
//! | `field: value` | `Some(value.into())`. |
//! | `field = expr` | Assigns `expr` as is (an `Option`). |
//! | `..base` (first) | Start from an existing value. |
//!
//! Field names are the Rust (snake_case) names; a typo is a compile error
//! pointing at it. [`patch!`](crate::patch!) applies the same syntax to an
//! existing value, and the flow macros ([`payment!`](crate::payment!),
//! [`capture!`](crate::capture!), [`refund!`](crate::refund!),
//! [`reversal!`](crate::reversal!), [`void!`](crate::void!)) add
//! shorthands for common payment fields.
//!
//! Large requests nest macros deeply; if the compiler reports a recursion
//! limit, add `#![recursion_limit = "256"]` to your crate.

/// Builds a model from nested fields. See the [module docs](crate::dsl).
#[macro_export]
macro_rules! build {
    ($ty:path { ..$base:expr $(, $($body:tt)*)? }) => {{
        let mut __cybs_value: $ty = $base;
        $( $crate::__cybs_fields!(__cybs_value; $($body)*); )?
        __cybs_value
    }};
    ($ty:path { $($body:tt)* }) => {{
        let mut __cybs_value: $ty = ::core::default::Default::default();
        $crate::__cybs_fields!(__cybs_value; $($body)*);
        __cybs_value
    }};
}

/// Sets nested fields on an existing value: `patch!(req, { a: { b: 1 } })`.
/// See the [module docs](crate::dsl).
#[macro_export]
macro_rules! patch {
    ($target:expr, { $($body:tt)* }) => {{
        let __cybs_target = &mut $target;
        $crate::__cybs_fields!(__cybs_target; $($body)*);
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! __cybs_fields {
    ($t:ident;) => {};
    // Nested object.
    ($t:ident; $f:ident : { $($inner:tt)* } $(, $($rest:tt)*)?) => {
        {
            let __cybs_n = $t.$f.get_or_insert_with(::core::default::Default::default);
            $crate::__cybs_fields!(__cybs_n; $($inner)*);
        }
        $( $crate::__cybs_fields!($t; $($rest)*); )?
    };
    // List of objects.
    ($t:ident; $f:ident : [ $( { $($item:tt)* } ),* $(,)? ] $(, $($rest:tt)*)?) => {
        {
            let __cybs_list = $t.$f.get_or_insert_with(::std::vec::Vec::new);
            $(
                __cybs_list.push(::core::default::Default::default());
                let __cybs_e = __cybs_list.last_mut().expect("an element was just pushed");
                $crate::__cybs_fields!(__cybs_e; $($item)*);
            )*
        }
        $( $crate::__cybs_fields!($t; $($rest)*); )?
    };
    // List of values.
    ($t:ident; $f:ident : [ $($v:expr),* $(,)? ] $(, $($rest:tt)*)?) => {
        $t.$f = ::core::option::Option::Some(::std::vec![$(::core::convert::Into::into($v)),*]);
        $( $crate::__cybs_fields!($t; $($rest)*); )?
    };
    // Raw assignment.
    ($t:ident; $f:ident = $v:expr $(, $($rest:tt)*)?) => {
        $t.$f = $v;
        $( $crate::__cybs_fields!($t; $($rest)*); )?
    };
    // Value.
    ($t:ident; $f:ident : $v:expr $(, $($rest:tt)*)?) => {
        $t.$f = ::core::option::Option::Some(::core::convert::Into::into($v));
        $( $crate::__cybs_fields!($t; $($rest)*); )?
    };
}

/// Builds a [`CreatePaymentRequest`](crate::models::CreatePaymentRequest)
/// (authorization, or sale with `capture: true`). Needs the `payments`
/// feature.
///
/// Shorthands, mixed freely with ordinary [`build!`](crate::build!) fields:
///
/// | Shorthand | Sets |
/// |---|---|
/// | `code: "…"` | `client_reference_information.code` |
/// | `amount: "10.00" USD` | `order_information.amount_details` (checked at compile time) |
/// | `amount: (total, currency)` | the same, from runtime values |
/// | `card: { … }` | `payment_information.card` |
/// | `bill_to: { … }` / `ship_to: { … }` | `order_information.bill_to` / `ship_to` |
/// | `capture: bool` | `processing_information.capture` |
///
/// ```
/// let req = cybersource::payment! {
///     code: "order-42",
///     amount: "100.00" USD,
///     card: { number: "4111111111111111", expiration_month: "12", expiration_year: "2031" },
///     bill_to: { first_name: "Jane", last_name: "Doe", country: "US" },
///     capture: true,
///     device_information: { ip_address: "192.0.2.1" },
/// };
/// assert_eq!(req.order_information.unwrap().amount_details.unwrap().currency.as_deref(), Some("USD"));
/// ```
#[macro_export]
macro_rules! payment {
    ($($body:tt)*) => {
        $crate::__cybs_flow_build!($crate::models::CreatePaymentRequest; order; $($body)*)
    };
}

/// Builds a [`CapturePaymentRequest`](crate::models::CapturePaymentRequest);
/// shorthands as in [`payment!`](crate::payment!). Needs `payments`.
#[macro_export]
macro_rules! capture {
    ($($body:tt)*) => {
        $crate::__cybs_flow_build!($crate::models::CapturePaymentRequest; order; $($body)*)
    };
}

/// Builds a [`RefundPaymentRequest`](crate::models::RefundPaymentRequest)
/// (for a payment or a capture); shorthands as in [`payment!`](crate::payment!).
/// Needs `payments`.
#[macro_export]
macro_rules! refund {
    ($($body:tt)*) => {
        $crate::__cybs_flow_build!($crate::models::RefundPaymentRequest; order; $($body)*)
    };
}

/// Builds an [`AuthReversalRequest`](crate::models::AuthReversalRequest);
/// `amount:` sets `reversal_information.amount_details`. Needs `payments`.
#[macro_export]
macro_rules! reversal {
    ($($body:tt)*) => {
        $crate::__cybs_flow_build!($crate::models::AuthReversalRequest; reversal; $($body)*)
    };
}

/// Builds a [`VoidPaymentRequest`](crate::models::VoidPaymentRequest);
/// `code:` sets the reference. Needs `payments`.
#[macro_export]
macro_rules! void {
    ($($body:tt)*) => {
        $crate::__cybs_flow_build!($crate::models::VoidPaymentRequest; order; $($body)*)
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __cybs_flow_build {
    ($ty:path; $mode:ident; $($body:tt)*) => {{
        let mut __cybs_flow: $ty = ::core::default::Default::default();
        $crate::__cybs_flow!($mode __cybs_flow; $($body)*);
        __cybs_flow
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! __cybs_flow {
    ($m:ident $p:ident;) => {};

    // `amount:` for orders (payments, captures, refunds).
    (order $p:ident; amount: $a:literal $c:ident $(, $($r:tt)*)?) => {
        $crate::patch!($p, { order_information: { amount_details: {
            total_amount: $crate::amount!($a), currency: $crate::currency!($c),
        } } });
        $( $crate::__cybs_flow!(order $p; $($r)*); )?
    };
    (order $p:ident; amount: ($a:expr, $c:expr) $(, $($r:tt)*)?) => {
        $crate::patch!($p, { order_information: { amount_details: { total_amount: $a, currency: $c } } });
        $( $crate::__cybs_flow!(order $p; $($r)*); )?
    };
    // `amount:` for reversals.
    (reversal $p:ident; amount: $a:literal $c:ident $(, $($r:tt)*)?) => {
        $crate::patch!($p, { reversal_information: { amount_details: {
            total_amount: $crate::amount!($a), currency: $crate::currency!($c),
        } } });
        $( $crate::__cybs_flow!(reversal $p; $($r)*); )?
    };
    (reversal $p:ident; amount: ($a:expr, $c:expr) $(, $($r:tt)*)?) => {
        $crate::patch!($p, { reversal_information: { amount_details: { total_amount: $a, currency: $c } } });
        $( $crate::__cybs_flow!(reversal $p; $($r)*); )?
    };

    ($m:ident $p:ident; code: $v:expr $(, $($r:tt)*)?) => {
        $crate::patch!($p, { client_reference_information: { code: $v } });
        $( $crate::__cybs_flow!($m $p; $($r)*); )?
    };
    ($m:ident $p:ident; card: { $($c:tt)* } $(, $($r:tt)*)?) => {
        $crate::patch!($p, { payment_information: { card: { $($c)* } } });
        $( $crate::__cybs_flow!($m $p; $($r)*); )?
    };
    ($m:ident $p:ident; bill_to: { $($c:tt)* } $(, $($r:tt)*)?) => {
        $crate::patch!($p, { order_information: { bill_to: { $($c)* } } });
        $( $crate::__cybs_flow!($m $p; $($r)*); )?
    };
    ($m:ident $p:ident; ship_to: { $($c:tt)* } $(, $($r:tt)*)?) => {
        $crate::patch!($p, { order_information: { ship_to: { $($c)* } } });
        $( $crate::__cybs_flow!($m $p; $($r)*); )?
    };
    ($m:ident $p:ident; capture: $v:expr $(, $($r:tt)*)?) => {
        $crate::patch!($p, { processing_information: { capture: $v } });
        $( $crate::__cybs_flow!($m $p; $($r)*); )?
    };

    // Anything else is an ordinary `build!` field.
    ($m:ident $p:ident; $f:ident : { $($i:tt)* } $(, $($r:tt)*)?) => {
        $crate::__cybs_fields!($p; $f: { $($i)* });
        $( $crate::__cybs_flow!($m $p; $($r)*); )?
    };
    ($m:ident $p:ident; $f:ident : [ $($i:tt)* ] $(, $($r:tt)*)?) => {
        $crate::__cybs_fields!($p; $f: [ $($i)* ]);
        $( $crate::__cybs_flow!($m $p; $($r)*); )?
    };
    ($m:ident $p:ident; $f:ident = $v:expr $(, $($r:tt)*)?) => {
        $crate::__cybs_fields!($p; $f = $v);
        $( $crate::__cybs_flow!($m $p; $($r)*); )?
    };
    ($m:ident $p:ident; $f:ident : $v:expr $(, $($r:tt)*)?) => {
        $crate::__cybs_fields!($p; $f: $v);
        $( $crate::__cybs_flow!($m $p; $($r)*); )?
    };
}
