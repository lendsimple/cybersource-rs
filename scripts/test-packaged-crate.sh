#!/usr/bin/env bash
# Runs the cybersource test suite from the packaged crate, outside the repository,
# as crater and Linux distributions do: everything the tests need must be in the
# package. Extra arguments go to `cargo test`.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
version=$(cargo metadata --manifest-path "$root/Cargo.toml" --no-deps --format-version 1 \
  | jq -r '.packages[] | select(.name == "cybersource") | .version')

cargo package --manifest-path "$root/Cargo.toml" --package cybersource --no-verify --allow-dirty

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tar -xzf "$root/target/package/cybersource-$version.crate" -C "$work"

cd "$work/cybersource-$version"
cat >> Cargo.toml <<TOML

# Test this crate on its own, as if it had been downloaded from crates.io.
[workspace]
TOML

cargo test --all-features "$@"
