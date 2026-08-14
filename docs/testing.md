# How squelch is tested

The crate's failure mode is silent: by the time a leak is noticed, the report is
already on a public tracker. So the test suite is built to answer one question —
**what actually left the machine?** — rather than to check that the builder
returns the right struct.

## Four layers

| layer | where | what it can catch |
| --- | --- | --- |
| unit | `src/**` inline `mod tests` | rule-level behaviour: a regex, a parser, a cap |
| property | `tests/observability_closure.rs` | the *shape* of a defect, not an instance of it |
| end-to-end | `apps/squelch-demo/tests/` | what a receiver got, across a crate and a process boundary |
| build matrix | `nix flake check` | what a *consumer* gets: feature combinations, both platforms, the MSRV, the supply chain |

`tests/issue_form.rs` sits outside that table because it asserts a property of
the **repository** rather than of the crate: that the field ids this repo's own
examples prefill are declared by the issue form this repo ships. It is excluded
from the published crate for that reason — unpacked from a `.crate` it would
only panic on a missing file.

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
token, a zero-width-split credential, private-key armour, a forge URL with no
`.git`, Google/Slack/Telegram tokens, a driveless Windows path, a UNC share, a
MAC address — planted in log fields *and* in provenance, then asserted absent
from every payload.

Two properties keep it from going vacuous:

- `the_canary_corpus_is_actually_dangerous` asserts every canary really is in
  the raw material. A corpus that lost a canary would make every leak assertion
  pass for the wrong reason.
- `SURVIVORS` pins text that must **survive**. Over-masking makes the block
  worthless just as surely as under-masking makes it dangerous — and the
  clearest case is a stack frame, which is the single most useful line in a bug
  report. `django.contrib.auth.models` has exactly the shape of a hostname, and
  the FQDN rule was eating every Python, Java and Kotlin frame until the corpus
  said it must not.

A leak assertion on a route that carries nothing passes for the wrong reason, so
each e2e test asserts **presence before absence**. The mailto route spent a
while sending an empty draft while `the_mailto_url_carries_no_canary` stayed
green: a route that transmits nothing leaks nothing.

## Properties, where examples run out

Every defect the first two review rounds found was found by a person reading
code. The tests added alongside each fix pin the input that broke; none of them
would catch the *next* value of the same shape. `tests/observability_closure.rs`
asserts the shape instead, over generated sequences of builder operations:

| property | what it forbids |
| --- | --- |
| idempotence | adopt-style state (`field`, `label`, `require`, `form`, `provenance`) stored in an append-only `Vec`, so applying an operation twice is observable |
| conservation | a lossy encoder reporting less loss than it caused — everything absent or truncated in the URL is named in `shortened`/`dropped`, and nothing named survived intact |
| round-trip | `skeleton` → `parse_skeleton` losing an answer because the reporter's own text imitated a delimiter |

### A property can pass while asserting nothing

The first version of this suite was reviewed by an agent that instrumented it
and counted branch hits. The result was worth more than any finding: over 447
generated cases, the assertion the whole property exists for — *a field vanished
from the URL and nothing named it* — **ran zero times**. Arbitrary builder
operations almost never produce values that compete for a 7 500-character
budget, so the branch was unreachable in practice while the test reported
success.

That is worse than having no test, because it is counted as coverage.

Two things fix it, and both are needed:

- The generated sequence always ends with two to four fields whose combined
  length straddles the budget, so truncation and dropping are the common case
  rather than the vanishing one. The drop branch now runs about 140 times a run.
- A **coverage assertion** fails the suite if answers plainly exceeding the
  budget produce a manifest reporting no loss at all — so the generators cannot
  quietly drift back to producing values too small to reach it.

The same review found the property was reading only the URL, despite a docstring
promising closure between body, URL and manifest. A `render_body` regression
that dropped a section would have passed.

Three rules keep it honest:

- **The oracle is written from the contract, not from `url::build`.** A shadow
  model that reimplements the code agrees with the code's bugs, so
  `carries_whole_value` percent-decodes the parameter back rather than calling
  the encoder.
- **`diagnostics` is excluded from the idempotence property**, because it
  genuinely is not idempotent — two independent sources of the same warning must
  both survive. Encoding which operations are adopt-style is the point; if the
  property had been weakened instead, it would have stopped asserting anything.
- **Generators are biased toward the 7 500-character URL budget** rather than
  sampled uniformly, or the boundary where truncation and dropping happen is
  essentially never reached.

It found three defects on its first run, all silent: a markdown heading in an
answer read as structure, an HTML comment in an answer deleted as guidance, and
an empty `Provenance` overwriting the reporter's own words with nothing.

Verified load-bearing by mutation, in a *copy* of the repo: reinstating the
append-only `require`, the empty overwrite, an unreported dropped field and the
blanket comment strip fails four different properties.

## The MSRV is built, not asserted

`checks.msrv` builds `-p squelch --all-features` with exactly the compiler
`rust-version` names, using a second toolchain pin in `.msrv/rust-toolchain.toml`.
Every other check is off there: running clippy or the test suite on an old
compiler measures the compiler, not the crate, and a lint that did not exist yet
says nothing about whether a consumer pinned there can build this.

It earned its place on its first run. `rust-version` said `1.74`, verified by
nothing, and 1.74 cannot build this crate at all — a transitive dependency is
edition 2024, which that Cargo cannot parse. A declared-but-unverified MSRV is a
*false* promise rather than a weak one: the suite stays green and the failure
lands on a downstream who cannot tell it from their own mistake.

## No git-hook layer, deliberately

Two org tooling systems want to own the hook layer, and the concern was that
adopting both means two hook managers fighting with the loser's hooks silently
not running. Checked rather than assumed: **there is no collision, and there is
no hook layer here at all.**

devkit's hooks are opt-in — `mkRustProject` takes `hooks ? null`, and with the
default the whole branch is dead code. Even when a consumer opts in, devkit
passes `install.enable = false` to git-hooks.nix specifically so it does *not*
rewrite `.git/hooks` or `core.hooksPath`; it only maintains a config symlink.
`.githooks/` belongs to devkit's workspace-scaffold template, not to
`mkRustProject`. So nothing in squelch installs a hook today, and nothing would
fight if something did.

The one gate that looked genuinely additive — guardrails' `no-raw-trace-fields`,
which stops raw `?`/`%` `tracing` formatters putting secrets into an audit trail
— **matches nothing in this repo**. squelch has no `tracing` or `log`
dependency and emits no logs of its own; it consumes an application's. Adopting
it would be adding a gate that asserts nothing, which is the failure this
document already spends a section on. It belongs in the README as advice to
consumers, and that is where it is.

What a hook layer would add over the nine flake checks is faster local feedback
on checks that already run, plus commit-message and branch-name shape. Neither
is worth a second config to keep in sync for a crate this size. Enabling
devkit's set later is a one-line `hooks = { … }` if that changes.

## Supply chain

`deny.toml` turns on `cargo deny check` — advisories, licences, bans, sources.
`openssl`, `openssl-sys` and `native-tls` are banned outright rather than merely
not selected: `ureq` is configured for rustls, and if those feature flags ever
drift, a C TLS stack lands in every consumer's binary. Policy fails the build;
a line in `Cargo.toml` only fails to prevent it.

## Feature matrix

`checks.feature-powerset` runs `cargo hack check -p squelch --feature-powerset
--no-dev-deps`. `--no-dev-deps` is the load-bearing flag: dev-dependencies list
`serde_json` unconditionally, so anything built with tests links it anyway and a
missing feature dependency stays invisible. That is exactly how `endpoint`
shipped unable to compile without `logs` while every other check was green.

## Running it

```sh
cargo test --workspace --all-features    # fast loop
nix flake check                          # what CI runs: 9 checks
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
ssh <linux-host> 'rm -rf ~/ci/squelch/.git'          # see below
rsync -az --delete --exclude 'target/' --exclude '.git/' ./ <linux-host>:~/ci/squelch/
ssh <linux-host> 'cd ~/ci/squelch && nix flake check'
```

**Delete `.git` on the far side, and mean it.** `--exclude '.git/'` tells rsync
to ignore that directory on *both* ends, so `--delete` will not remove a stale
one left by an earlier sync — and nix, finding a git repository, then builds
from its **index** rather than from the files on disk. The check runs against
whatever was tracked whenever that `.git` was copied, and says nothing about
what you just wrote.

**A second `mkRustProject` call is a second source filter.** The MSRV check is
its own project, with its own `cleanSrc` — so `extraSrcFiles` passed to the main
one does not reach it, and crane's `buildPackage` runs `cargo test` in its check
phase regardless of `nextest = false`. The result was a suite that compiled
locally and failed to compile in the sandbox, on a file the *other* project had
been told about. Both calls now `inherit extraSrcFiles` from one binding, which
is the only version of this that cannot drift.

**A fixture read at run time is not a fixture.** `std::fs` plus
`CARGO_MANIFEST_DIR` looks equivalent to `include_str!` and is not: it needs the
source tree to still be where it was when the binary was built, which under
`nix flake check` it is not. `tests/issue_form.rs` failed on Linux and passed on
macOS for exactly this reason, and the failure read as a broken test rather than
as an environment difference. `include_str!` also makes a missing fixture a
*compile* error, so a test cannot quietly stop asserting anything.

`nix flake check | tail` is the same class of mistake in one line: the pipe
reports `tail`'s exit status, so a failing check reads as a passing one. Redirect
to a file and check `$?`.
