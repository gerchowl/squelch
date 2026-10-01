# ADR-0003: no git-hook layer, and no `no-raw-trace-fields` gate

- **Status:** accepted
- **Date:** 2026-08-14

## Context

Two org tooling systems want to own the git hook layer, and the concern raised
during the governance review was that adopting both means two hook managers
fighting with the loser's hooks silently not running.

The question was referred as "to be settled before either is adopted".

It was **checked rather than assumed**, and the answer is that the collision does
not exist and neither system is in play.

## Decision

No git-hook layer, in this repository, from either system.

**devkit's hooks are opt-in.** `mkRustProject` takes `hooks ? null`, so with the
default the entire branch is dead code. And even when a consumer opts in, devkit
passes `install.enable = false` to git-hooks.nix specifically so it does *not*
rewrite `.git/hooks` or `core.hooksPath` — it maintains a config symlink only.
`.githooks/` belongs to devkit's workspace-scaffold template, not to
`mkRustProject`.

So there is no collision to avoid, and nothing here installs a hook today.

The one gate that looked genuinely additive is
[gerchowl/guardrails](https://github.com/gerchowl/guardrails)' `no-raw-trace-fields`,
which stops raw `?`/`%` `tracing` formatters putting secrets into an audit trail
(`info!(user = ?user)`). It **matches nothing in this repository**, and adopting it
would mean adding a gate that asserts nothing — the exact failure
`docs/testing.md` already spends a section on.

It is in the README as advice to consumers, which is the honest form of the
cross-reference.

## Alternatives considered

**Adopt one of the hook layers now.** Rejected: nothing is installed today, so
there is nothing to coordinate, and the flake checks already cover the same ground
with better error messages. A hook layer adds faster *local* feedback on checks
that already run in CI, plus commit-message and branch-name shape. That is not
worth a second config to keep in sync for a crate this size.

**Adopt `no-raw-trace-fields` because squelch is about redaction.** Rejected:
squelch has no `tracing` or `log` dependency and emits no logs of its own. It
*consumes* an application's. The gate would match zero sites here, and a gate that
asserts nothing reads as coverage.

**Adopt it anyway as a policy statement for contributors.** Rejected: a policy
nobody can violate is a policy nobody reads. The README is the right place because
it reaches the people the rule is actually for — the applications embedding this
crate, which do log.

## Consequences

- Enabling devkit's set later is a one-line `hooks = { … }` if the trade changes.
  Nothing here forecloses it.
- The guardrails reference lives in the README, cross-linked, so a consumer
  building on squelch finds the gate that covers **their** end. squelch scrubs
  secrets on the way *out*; it cannot help with what an application's logging
  already wrote down. A project doing one and not the other has a hole, and the
  README says which hole.
- The "to be settled" question is closed with evidence rather than left as a
  blocker on a decision nobody was going to make.
