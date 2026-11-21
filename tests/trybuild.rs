//! The DSL's compile errors point at the user's code.
//!
//! Expected compiler output lives in `tests/ui/*.stderr`; regenerate with
//! `TRYBUILD=overwrite cargo test --test trybuild` after a toolchain update.

#![cfg(all(not(target_family = "wasm"), feature = "payments"))]

#[test]
fn dsl_compile_errors() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
}
