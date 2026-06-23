# Contributing to syren

Thanks for your interest in syren! This guide covers the development loop, the
checks CI runs (so you can run them locally first), and the project's
conventions. For the design behind the code, read
[`ARCHITECTURE.md`](ARCHITECTURE.md).

## Prerequisites

- **Rust ≥ 1.85** (the MSRV). A stable toolchain is pinned in
  [`rust-toolchain.toml`](rust-toolchain.toml), so `rustup` will install the
  right components automatically.
- **Linux on x86-64.** syren traces the Linux syscall ABI directly; the tracing
  tests spawn real processes under `ptrace`, which needs a Linux host. They run
  unprivileged — no root required.

## The development loop

```console
$ cargo build             # debug build of the whole workspace
$ cargo run -- echo hi    # run the CLI without installing
$ cargo test --workspace  # run every test
```

`cargo run -p syren-cli -- <args>` is the quickest way to try a change; the
binary is `syren`, so `-- echo hi` traces `echo hi`.

## Before you push: the local CI checklist

With [`just`](https://just.systems) installed, `just pre` runs the everyday gate
(format check, lints, tests, docs) and `just ci` mirrors the server exactly,
supply-chain and MSRV jobs included. Run `just` on its own to list every recipe.

CI additionally builds against the MSRV (`cargo +1.85.0 check --workspace
--all-features`) to make sure nothing newer than 1.85 sneaks in.

## Code style and lints

- **Formatting** is enforced by `rustfmt` using [`rustfmt.toml`](rustfmt.toml)
  (max width 100). Don't hand-format; run `cargo fmt --all`.
- **Lints**: the workspace turns on `rust_2018_idioms`, `unreachable_pub`,
  `missing_debug_implementations` and `clippy::all` (see the `[workspace.lints]`
  section of the root `Cargo.toml`). CI compiles with `-D warnings`, so a warning
  is a failure. In particular, items in the binary crate should be `pub(crate)`,
  not `pub`.
- **Comments explain *why*, not *what*.** Match the density and idiom of the
  surrounding code. The tricky, non-obvious mechanics (the ptrace
  resume-deferral, the fd zero-extension) carry comments because they'd bite the
  next reader otherwise.

## Adding or refining syscall coverage

syren's syscall table is **generated at build time**, not hand-written — this is
the core of its design.
Every syscall in `crates/syren-common/data/syscall_64.tbl` already has a number,
name and category. To improve how a syscall's *arguments* are decoded:

1. Add (or edit) a row in `crates/syren-gen/src/meta.rs`, naming each argument
   and giving it an `ArgKind` (`Fd`, `Path`, `Flags`, `Size`, `Offset`, …):

   ```rust
   syscall_meta!("openat" => [
       ("dfd", Fd), ("filename", Path), ("flags", Flags), ("mode", Int),
   ]),
   ```

2. To move a syscall to a different category, edit the explicit table or the
   prefix heuristics in `crates/syren-gen/src/category.rs`.
3. Rebuild (`cargo build`) — `syren-common`'s `build.rs` regenerates the table —
   and verify with `cargo run -p syren-cli -- --list-syscalls` and a real trace.

Add or extend a unit test in `syren-gen` (for the generation) or `syren-decode`
(for the rendering) to lock in the behaviour.

## Tests

- Put **unit tests** in a `#[cfg(test)] mod tests` next to the code. Decoder
  tests use the in-memory mock `MemoryReader`, so they need no real process.
- Put **end-to-end tests** in a crate's `tests/` directory. The CLI and trace
  tests spawn real programs (`true`, `false`, `echo`, `ls`) and assert on the
  result; prefer small, deterministic targets.
- **A bug fix should come with a test that fails without it.** Several existing
  tests exist precisely because a bug was found (see the zero-extended-fd and
  broken-pipe regression tests).

## Commit messages and PRs

- Commits follow **[Conventional Commits](https://www.conventionalcommits.org)**:
  `type(scope): summary`, e.g. `feat(decode): …`, `fix(cli): …`,
  `docs: …`, `ci: …`. Keep the summary imperative and under ~72 chars; use the
  body to explain *why*.
- Keep commits **atomic** — one logical change each — so history stays bisectable.
- Make sure the local checklist above is green before opening or updating a PR.
  CI must pass before merge.

## License

By contributing, you agree that your contributions will be dual-licensed under
[MIT](LICENSE-MIT) and [Apache-2.0](LICENSE-APACHE), matching the project. You
don't need to add a license header to new files.
