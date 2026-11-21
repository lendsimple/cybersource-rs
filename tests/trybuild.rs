//! The DSL's compile errors point at the user's code.
//!
//! Expected compiler output lives in `tests/ui/*.stderr`; regenerate with
//! `TRYBUILD=overwrite cargo test --test trybuild` after a toolchain update.
//! It follows one rustc's wording, so this only runs in the repository, where
//! `.cargo/config.toml` sets `CYBERSOURCE_UI_TESTS`. From the published crate
//! (crater, distributions) it skips.

#![cfg(all(not(target_family = "wasm"), feature = "payments"))]

#[test]
fn dsl_compile_errors() {
    if std::env::var_os("CYBERSOURCE_UI_TESTS").is_none() {
        eprintln!("skipping: compile-error snapshots run only in the repository");
        return;
    }
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
}
