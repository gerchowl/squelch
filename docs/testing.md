# How squelch is tested

The crate's failure mode is silent: by the time a leak is noticed, the report is
already on a public tracker. So the test suite is built to answer one question —
**what actually left the machine?** — rather than to check that the builder
returns the right struct.

## Three layers

| layer | where | what it can catch |
| --- | --- | --- |
| unit | `src/**` inline `mod tests` | rule-level behaviour: a regex, a parser, a cap |
| end-to-end | `apps/squelch-demo/tests/` | what a receiver got, across a crate and a process boundary |
| build matrix | `nix flake check` | what a *consumer* gets: feature combinations, both platforms |

## Why the demo app is a workspace member

`apps/squelch-demo` is a real binary crate, not an example. The e2e tests drive
it as a subprocess, so they exercise the public API a consumer actually has: a
missing `pub` is a compile error rather than something no test can see, and the
report is inspected after it has crossed a process boundary.

It also keeps the tests honest about surfaces. `docs/stories.md` claims one
composition serves a CLI, a GUI and an agent; the demo exposes the CLI and the
agent surface over the same `Form`, and the agent surface found a schema no
agent could satisfy on its first run.

## The fake receivers

Every route that transmits has something standing in for the far end, so the
assertion is on the payload rather than on the intent to send.

| route | receiver | why this shape |
| --- | --- | --- |
| `Browser` | `open`/`xdg-open` shim on the child's `PATH` | captures the exact URL a browser would get, which is where the "no diagnostics in the query string" promise lives |
| `GhCli` | a fake `gh` recording its argv | squelch never calls the GitHub API on this route — it spawns `gh`, which holds the credential. Mocking the API would test `gh` |
| `Endpoint` | a loopback `TcpListener` | captures the real POST including headers, since a credential in a header leaks as thoroughly as one in a body |
| `File`, `Mailto` | the artefact itself | the mailto URL is percent-decoded before asserting, or a leaked path hides behind `%2F` |

No new dependencies and no container: the HTTP receiver is about forty lines of
`std::net`, and the shims are `sh` scripts. That is what lets the whole suite
run inside the `nix flake check` sandbox, which has loopback but no network and
no container runtime.

`PATH` is set on the **child**, never with `set_var`. Tests in one binary run on
parallel threads, and a racing `set_var` corrupts the environment badly enough
that the panic machinery itself fails — turning an ordinary assertion failure
into an unreadable abort.

## The canary corpus

`common/mod.rs` holds values that must never reach a receiver — a token, another
account's home, an email, a private IPv4, a compressed IPv6, an internal FQDN, a
private org, a labelled secret, an AWS session key, a Stripe key, a bearer
token, a zero-width-split credential — planted in log fields *and* in
provenance, then asserted absent from every payload.

Two properties keep it from going vacuous:

- `the_canary_corpus_is_actually_dangerous` asserts every canary really is in
  the raw material. A corpus that lost a canary would make every leak assertion
  pass for the wrong reason.
- `SURVIVORS` pins text that must **survive**. Over-masking makes the block
  worthless just as surely as under-masking makes it dangerous.

## Feature matrix

`checks.feature-powerset` runs `cargo hack check -p squelch --feature-powerset
--no-dev-deps`. `--no-dev-deps` is the load-bearing flag: dev-dependencies list
`serde_json` unconditionally, so anything built with tests links it anyway and a
missing feature dependency stays invisible. That is exactly how `endpoint`
shipped unable to compile without `logs` while every other check was green.

## Running it

```sh
cargo test --workspace --all-features    # fast loop
nix flake check                          # what CI runs: 7 checks
```

### On macOS, failures may be unreadable

On a host whose linker produces Mach-O binaries without usable unwind
information, a failing Rust test aborts with `fatal runtime error: failed to
initiate panic, error 5` instead of printing the assertion. It reproduces on an
empty crate, so it is a toolchain/linker property, not a squelch one:

```sh
export CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER=/usr/bin/cc
```

The `nix flake check` sandbox is unaffected — failures there print normally.

## Second platform

`nix flake check` is run on x86_64-linux as well as aarch64-darwin. That is not
ceremony: it is the only place the Linux-only paths execute — `mold` as the
linker, `xdg-open` instead of `open`, and the `libc` `getpwuid` fallback that
keeps the redactor working when a service manager strips `HOME` and `USER`.

```sh
rsync -az --delete --exclude target/ ./ <linux-host>:~/squelch-ci/
ssh <linux-host> 'cd ~/squelch-ci && nix flake check'
```
