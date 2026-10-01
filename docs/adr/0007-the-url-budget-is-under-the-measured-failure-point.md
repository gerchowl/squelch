# ADR-0007: the URL budget is 4 200, and it is under a measured ceiling

- **Status:** accepted
- **Date:** 2026-10-01
- **Origin:** [gerchowl/flock](https://github.com/gerchowl/flock) ADR-0010, which
  set the original constant. See [0001](0001-extracted-from-flock-adr-0010.md).

## Context

`MAX_URL_LEN` was 7 500, and the doc comment directly above it recorded the
measurement that says 7 500 is too high:

> 4 079 characters answered 302, **7 079 returned 500**, 8 279+ returned 414 …
> **7 500 leaves headroom under the first failing size.**

7 500 is above 7 079. The conclusion contradicted the data printed directly above
it, and nobody noticed for the life of the constant — carried over from flock ADR-0010
with its measurement, but without the reasoning, so the reasoning had to be
re-derived and got re-derived wrong.

Re-measured against github.com, 2026-10-01, bisected by request length:

| request | response |
|---|---|
| bare `curl`, ≤ 7 067 chars | normal (404 logged-out login wall) |
| bare `curl`, 7 068 – 8 000 | **500** |
| 8 200+ | 414 |
| with a well-formed 2 KB `Cookie` header | **500 from 6 000** |

The limit applies to the whole request, headers included. **The bare figure is the
wrong one to design against**: a logged-in browser sends several KB of cookies, so
the real ceiling for an actual reporter is lower than the bare number. Measured
today: bare still answers 404 at 7 072 and 500s by 7 572; with a 2 KB cookie the 500
arrives at 7 132.

## Decision

`MAX_URL_LEN = 4_200`, with the date, the method and the table recorded next to the
constant.

Two supporting changes, both because the class of bug is only visible from outside:

- **An opt-in live contract test** (`#[ignore]`d, gated on `endpoint` for the TLS
  client) that builds a URL at exactly `MAX_URL_LEN` with a 2 KB cookie and asserts
  github.com does not return 5xx or 414. Every other URL test checks the string
  squelch *built*; none checks what github.com *does with it*, which is the blind
  spot that let 7 500 stand. Verified to fail: with the constant back at 7 500 it
  reports the 500; at 4 200 it passes. A contract test that cannot fail on the bug
  it exists for asserts nothing.
- **The property suite's generators retuned** to the new budget. They were biased
  toward 7 500 and would otherwise no longer reach the truncation boundary, where
  the coverage assertion exists to prove the branch is reachable at all.

## Alternatives considered

**Keep 7 500 and re-measure later.** Rejected: that is the decision that was already
in the tree, and the re-measurement did not happen for the life of the constant.

**Split the difference at 6 000**, just under the bare failure point. Rejected: 6 000
is the *cookie-adjusted* figure, not a margin below it. Designing to a measured
failure point is how this happened once.

**Truncate the reporter's prose to fit rather than refusing.** Already rejected in
[0008-adjacent work](0004-the-browser-route-refuses-rather-than-truncate.md) and
unchanged: showing *less* than leaves is a privacy failure, showing *more*
corrupts what they believe they consented to send.

**Do nothing and add a comment asking future readers to re-measure.** Rejected: the
comment was already there, and it drew the wrong conclusion. A number plus a method
is checkable; a number plus a request is not.

## Consequences

- **More reports are refused rather than truncated.** A `FieldsDropped` refusal
  becomes more common at 4 200 than at 7 500. That is the correct trade: a refusal
  names the problem in language a reporter can act on, and a GitHub 500 page names
  nothing at all. The reporter is offered another route via `Composed::url`.
- **GitHub moves this limit, and nothing will notice but a person.** The date is
  recorded so the next reader can re-run the measurement rather than trust the
  number, and the live test exists so re-running it is one command. It is
  `#[ignore]`d because it needs the network and `nix flake check` is hermetic, and
  inherently flaky, so it is a manual or scheduled check rather than a gate.
- flock very likely has the same bug, since this constant and its measurement came
  from there. That is a separate repository's decision.
- The live test needed `ureq`, so it is gated on `endpoint`. A test that needs a
  feature to observe the crate's behaviour is slightly awkward, and the
  alternative — a raw `TcpStream` to :443 — was tried and never reached a status
  line, because the connection is reset by the TLS handshake.
