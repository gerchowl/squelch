# Decision records

Why this directory exists, and what belongs in it.

## The rule

**Record a decision only where a later reader would reverse it without knowing why
it was made.**

That is the whole test, and it is a narrow one. Most decisions do not need a
record: the code says what was chosen, and the obvious alternative was worse for
reasons visible in the code. Those are not worth writing down.

A record earns its place in exactly one situation — the decision looks wrong, or
looks arbitrary, or looks like a mistake, and only the history explains it. Every
ADR below was written because the decision had already been nearly reversed once.
`docs/testing.md` is the same repository's example of the complementary case: it
records *how* the suite is built and which of its tests were found vacuous, which
is a different question and belongs in a different file.

## The shape

Each record is **Context · Decision · Alternatives considered · Consequences**, and
the consequences section is not optional. A record with no consequences is a
record of a decision whose effects nobody worked out, which is how the next person
reverses it.

## Index

| # | Decision | Status |
|---|---|---|
| [0001](0001-extracted-from-flock-adr-0010.md) | squelch is flock ADR-0010 as a crate | accepted |
| [0002](0002-the-msrv-is-set-by-the-dependency-tree.md) | the MSRV is 1.86, verified by a build | accepted |
| [0003](0003-no-git-hook-layer.md) | no git-hook layer, and no `no-raw-trace-fields` gate | accepted |
| [0004](0004-the-browser-route-refuses-rather-than-truncate.md) | `Browser` refuses rather than open a form missing a section | accepted |
| [0005](0005-the-host-rule-is-a-prior.md) | the host rule is a prior, not a classifier | superseded in part by [0006](0006-field-provenance-and-host-position.md) |
| [0006](0006-field-provenance-and-host-position.md) | field provenance and host position, instead of a sixth shape rule | accepted |
| [0007](0007-the-url-budget-is-under-the-measured-failure-point.md) | the URL budget is 4 200, measured against a cookie-adjusted ceiling | accepted |
| [0008](0008-form-parse-skeleton-takes-self.md) | `Form::parse_skeleton` takes `&self` because it knows its own ids | accepted |

0005 and 0006 are both here on purpose. 0005 records the *diagnosis* — that a
shape-based rule is a prior and cannot converge — and 0006 records what replaced
it. A reader arriving at either one needs the other, and collapsing them would
lose the reason the second one was worth writing.
