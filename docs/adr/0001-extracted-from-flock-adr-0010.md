# ADR-0001: squelch is flock ADR-0010 as a crate

- **Status:** accepted
- **Date:** 2026-08-14

## Context

squelch's report pipeline was not designed here. It is
[gerchowl/flock](https://github.com/gerchowl/flock) **ADR-0010**, extracted into a
publishable crate: client-side composition, a destination derived from
`CARGO_PKG_REPOSITORY`, an allowlisted and scrubbed log tail that never enters the
prefill URL, "the binary never submits on the user's behalf", and an untouched
attestation checkbox.

It was validated against the same ~10k-line production log corpus flock used, and
the redaction corpus is the direct descendant of that one.

**Nothing in this repository said so.** That is the part worth writing down, because
it had already cost something: `MAX_URL_LEN` was carried over from ADR-0010 along
with the measurement behind it, and without the surrounding reasoning the doc
comment in `src/url.rs` ended up drawing the *opposite* conclusion from the data it
quoted — 7 500 characters chosen as a safe budget, directly above the 7 079 at
which GitHub was measured returning HTTP 500. See
[ADR-0007](0007-the-url-budget-is-under-the-measured-failure-point.md).

A reader here could not go back to the source to check, because nothing told them
there was a source.

## Decision

Record the lineage here, and carry flock's decisions forward explicitly rather than
by accident.

What squelch **inherited unchanged**:

- composition is client-side and pure — build a `Report`, get a `Composed`, decide
  separately whether anything is sent
- the destination is a macro, not an argument, so it reads the *calling* crate's
  `CARGO_PKG_REPOSITORY` rather than squelch's own
- diagnostics never enter the prefill URL. GitHub records full request URLs
  server-side, so the query string is disclosed the moment the browser opens —
  before the reporter decides anything
- the binary never submits by default; a human is the last checkpoint
- an attestation checkbox is never ticked by a tool

What squelch **changed**:

- the route set. flock had a browser route and an API route; squelch has five
  (`Browser`, `Mailto`, `File`, `GhCli`, `Endpoint`) and each is explicit about
  which guarantee it gives up. See `src/transport.rs`.
- the form model. flock assumed a form; squelch has `Form` as data, because
  `docs/stories.md` requires one composition to serve a CLI, a GUI and an agent
  surface, and a GUI has to *render* the form rather than prompt for it.
- the destination macro expanded to the caller, which is the change that makes the
  crate extractable at all.

## Alternatives considered

**Do nothing and cite the source.** Rejected: a citation in a README is not a
decision record. The reasoning that mattered — why diagnostics are out of the URL,
why the checkbox is never ticked — is spread across an ADR in another repository
that this one has no way to keep in sync, and a reader would have to know to look.

**Rewrite rather than extract.** Rejected: the extracted design had already been
exercised against a real corpus and through adversarial review. A rewrite would
have re-earned that, and there is no evidence it would have arrived somewhere
better.

**Re-fork the design and diverge deliberately.** This is the standing temptation
with an extracted design, and it is why the lineage is recorded at all. squelch has
since diverged on the host rule ([0006](0006-field-provenance-and-host-position.md)),
on the routes ([0007](0007-the-url-budget-is-under-the-measured-failure-point.md)
follows from a `Browser`-specific measurement) and on the entry points
(`panic-hook`, which ADR-0010 named as the first follow-up and did not deliver). Each
of those is recorded here. The alternative is drift nobody can audit.

## Consequences

- flock's ADRs stay the source of truth for the *original* decisions, and this
  directory is the source of truth for squelch's. Where squelch has diverged, these
  records win, and the divergence is stated.
- **Numbering is local.** flock's records are referred to as "flock ADR-0010"
  throughout, never as "ADR-0010" — the same mistake that produced a number
  collision filed against flock in gerchowl/flock#437.
- A reader comparing the two implementations has a map. That was the gap, and it
  is the whole reason this record exists.
- If flock changes a decision this crate inherited, nothing automatically alerts
  squelch. That is a real cost of the arrangement, accepted because the alternative
  is a permanent fork with no shared vocabulary.
