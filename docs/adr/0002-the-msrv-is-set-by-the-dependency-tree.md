# ADR-0002: the MSRV is 1.86, and it is verified by a build

- **Status:** accepted
- **Date:** 2026-08-14

## Context

`Cargo.toml` originally declared `rust-version = "1.74"`. Nothing checked it.

1.74 could not build this crate at all. `endpoint` pulls
`ureq → url → idna → idna_adapter`, and a transitive dependency is edition 2024,
which a Cargo older than 1.85 cannot even parse — the failure is a manifest parse
error, before any of this crate's own code is reached.

A declared-but-unverified MSRV is not a weak promise. It is a **false** one: every
check in this repository stays green, and the failure lands on a downstream who
cannot tell it from their own mistake.

## Decision

Set `rust-version = "1.86"` and make `checks.msrv` in `flake.nix` build
`-p squelch --all-features` with exactly that compiler, on every run, using a
second toolchain pin in `.msrv/rust-toolchain.toml`.

Every other check is off in that project. Running clippy or the test suite on an
old compiler measures the compiler rather than the crate, and a lint that did not
exist yet failing there would say nothing about whether a consumer pinned there
can build this.

The number is set by the **dependency tree, not by this crate's source**, which
uses nothing newer than the 2021 edition. A consumer on
`default-features = false` almost certainly builds on something much older — but
the crate does not promise what it does not verify, and there is one lockfile here,
so there is one number.

## Alternatives considered

**Lower the MSRV by removing the offending dependency.** Rejected: the blocking
dependency is transitive, and pinning around it would mean carrying a fork or a
patch section forever. The `endpoint` feature is worth far more than the ability to
claim 1.74.

**Verify by pinning the oldest toolchain that happens to work today, and revisit
later.** That is what was done, and it is the same unverified promise in a nicer
coat.

**Drop the `rust-version` field entirely.** Rejected: it is a real signal, and
`cargo` will refuse to build a dependency that requires a newer compiler — which
turns a downstream's confusing build failure into a clear message. Removing it
makes the promise invisible rather than false, which is worse.

## Consequences

- `checks.msrv` earns its place. It failed on its first run, which is how the
  original `1.74` was found to be fiction rather than merely optimistic.
- **Raising the MSRV is a breaking change for consumers.** The two pins
  (`rust-version` and `.msrv/rust-toolchain.toml`) must move together, and the
  comment beside `rust-version` says so.
- The MSRV project needs the same `extraSrcFiles` as the main one. It is a *second*
  `mkRustProject` call, which means a *second* source filter — so a fixture passed
  to the main project does not reach it. Both calls now inherit one binding, which
  is the only version of this that cannot drift. This is recorded because it has
  already broken the x86_64-linux run once; see `docs/testing.md`.
- A consumer on an older compiler gets a clear "requires rustc 1.86" instead of a
  manifest parse error three dependencies deep.
