# ADR-0004: `Browser` refuses rather than open a form missing a section

- **Status:** accepted
- **Date:** 2026-08-14

## Context

A prefill URL has a hard length ceiling. When a report exceeds it, something has to
give, and the options are: shorten a field, drop a field, or refuse.

The failure this addresses is silent. A report is composed, a preview is shown, the
reporter approves it — and then a field that was in the preview is simply **absent**
from the form they submit. The body still contains it, so nothing downstream can
tell the reporter which section went missing. The issue arrives short a section
that both parties believe was sent.

Three findings shared this shape during the second review round: duplicate required
ids accumulating in a `Vec`, a `-->` in a form description closing an HTML comment
early and rendering as literal text in a reporter's editor, and this one. The
common thread is the crate losing or corrupting something the reporter supplied and
**saying nothing about it**.

## Decision

`PrefilledUrl` distinguishes two kinds of loss, and only one of them is fatal.

- **`shortened`** — the value was cut to fit. A stub survives and carries
  `[shortened — the full text was not sent]`. Routine: a long log tail is expected
  to be trimmed, and the reporter never expected to see all of it.
- **`dropped`** — the field did not reach the URL **at all**. Reported by name, and
  **refused** rather than sent.

They are kept separate deliberately. Reporting both under one flag meant the warning
fired on almost every report, which trains a reporter to ignore it on the one
occasion it matters. A trimmed log still leaves a recognisable stub; a dropped field
changes what the report *means*, to both the reporter and the maintainer.

`Report::preview` names the dropped sections in language the reporter can act on,
and `Transport::Browser` refuses to send a report it cannot carry whole.

Related, from the same review: `Report::require` and `Report::form` **dedupe on
insert**, preserving first-seen order. Both used to `extend` a `Vec<String>`, so
applying a form twice yielded `MissingFields(["a","b","a","b"])` — and a GUI that
re-applies its form on each keystroke accumulates O(n²) ids.

## Alternatives considered

**Truncate silently, warn generically.** This is what it did. Rejected: a
reporter who approves a preview and submits a form missing its "Reproduction"
section has been misled, and the fix is not discoverable after the fact.

**Drop the URL prefill entirely and always use `File` or `Endpoint`.** Rejected: the
prefill form is the only route that runs GitHub's *own* `required: true` validation
and keeps the reporter as the author of their own issue. It is the route worth
protecting, so it is the one worth making honest.

**Send anyway and let the maintainer notice.** Rejected, and it is the default
outcome the whole design is against. `docs/testing.md` records the same principle
found independently in the test suite: a warning that fires on nearly every report
is a warning nobody reads.

**A single `lossy: bool` plus a list.** Rejected: it is the merge that produced the
original problem. The distinction is not presentational — one is routine and one is
a change of meaning — and collapsing them is what made the common case train people
to ignore the uncommon one.

## Consequences

- A reporter on a slow connection with a large log may be **refused** rather than
  sent a partial report. That is the intended behaviour and it is a better failure
  than a silent one, but it is a behaviour change for anyone who was relying on the
  truncation.
- `Composed::url` names what was `shortened` and what was `dropped`, so a surface
  can offer another route — which is the point: the crate refuses, and the
  application decides.
- The report itself is fine at any length. Every other route carries it whole, so
  the size limit is a property of the URL and not of the report.
- The `require` dedupe means `require(["a"])` twice is `["a"]`, so a surface that
  re-applies a form is idempotent. This is now asserted as a *property* over
  generated builder sequences rather than as a unit test for the case that
  motivated it — see `tests/observability_closure.rs` and `docs/testing.md`.
