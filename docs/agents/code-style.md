# Code style

Read this before changing Rust code, as `AGENTS.md` directs. rustfmt, run on
every tracked Rust file with the edition in `rustfmt.toml`, and
`cargo clippy -- -D warnings` enforce formatting and lints; `AGENTS.md` holds
the commands. For everything this file does not state, follow the
[Rust API Guidelines](https://rust-lang.github.io/api-guidelines/) and the
[Google Rust style guide](https://google.github.io/styleguide/rustguide.html).

Project conventions:

- Protocol and identity values are newtypes (`Epoch(u32)`) so distinct
  concepts cannot be swapped.
- Library code returns `Result<T, E>` with a domain error enum. `panic!` and
  `unreachable!` mark invariants that correct code cannot violate; document the
  invariant at the site.
- Every module file opens with a `//!` comment stating its purpose and the
  invariants it owns. Protocol code names the invariant it upholds and cites
  the paper where the mapping is not obvious. `///` comments follow
  [the comment rules](comments.md).
- A new module with submodules uses `name/mod.rs`; extend an existing module in
  its current layout. [Design principles](design.md#module-organization) say
  what a `mod.rs` holds.
- Unit tests live in `#[cfg(test)]` modules: inline, in a sibling
  `<module>_tests.rs`, or in `<module>_tests/<case>/tests.rs`. Cross-module and
  multi-process tests live in `crates/<crate>/tests/`.
- A test is named for the property it asserts, with no `test_` prefix, and
  asserts that property directly. [`REVIEW.md`](../../REVIEW.md#tests-and-evidence)
  states what a test must reject to count as evidence.
