# List the available recipes.
default:
    @just --list

# Format the workspace (rustfmt.toml needs nightly-only options).
fmt:
    cargo +nightly fmt --all

# Lint everything with clippy, treating warnings as errors.
clippy:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

# Run the tests, with and without the optional `ebpf` feature.
test:
    cargo test --workspace --all-features
    cargo test --workspace

# Build the docs, failing on broken intra-doc links.
doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps

# Audit dependencies and licenses (needs `cargo install cargo-deny`).
deny:
    cargo deny check

# Check against the MSRV (needs `rustup toolchain install 1.85.0`).
msrv:
    cargo +1.85.0 check --workspace --all-features

# The everyday pre-push gate: format check, lints, tests, docs.
pre: fmt clippy test doc

# The full CI mirror, including the supply-chain and MSRV jobs.
ci: pre deny msrv

# Run the CLI, e.g. `just run -- -e trace=write echo hi`.
run *args:
    cargo run -p syren-cli -- {{ args }}
