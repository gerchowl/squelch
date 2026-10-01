# ADR-0005: the host rule is a prior, not a classifier

- **Status:** accepted; the replacement is [0006](0006-field-provenance-and-host-position.md)
- **Date:** 2026-08-14

## Context

`mask_hosts` was rewritten **five times in one sitting**, and each round fixed the
previous round's defect and opened another one next door.

| round | fixed | opened |
|---|---|---|
| 1 | — | every Java/Kotlin stack frame masked |
| 2 | stack frames | `.env.local`, `com.foo.internal.Impl` masked |
| 3 | those | `bastion.corp`, `bastion.corp.acme-inc` leaked |
| 4 | those | `Bastion.internal.acme-inc`, `int.acme.corp` leaked |
| 5 | those | `bastion.internal.acme.NET`, `us.internal.acme.com` leaked |

Every one was found by a fresh adversarial review. **None was found by the tests
the previous round had written.**

## Decision

**The problem is ill-posed as stated, and the rule is kept as a prior rather than
fixed as a classifier.**

A hostname and a reverse-DNS identifier are the same string in opposite orders.
Over a context-free dotted token there is no discriminator that is not a prior:

- **case** is a convention Java breaks with `com.foo.internal.Impl` and DNS breaks
  with `SERVER01.CORP`
- **suffix membership** flips the moment `.app` and `.dev` are both gTLDs and both
  common module-path endings
- **length** is a prior module paths violate happily

So every version must have both false positives and false negatives, and the only
question is which corpus the prior is tuned against. Tuning it against an
adversarial set that grows each time the tuning changes is chasing a fixpoint that
is not there.

The six constants in the function — `HOST_SUFFIXES`, `PRIVATE_SUFFIXES`,
`WORDLIKE_PRIVATE_SUFFIXES`, `REVERSE_DNS_ROOTS`, `COMPOUND_SUFFIXES`,
`looks_like_a_machine` — are each a scar from one round's motivating case. None
carries information about hostnames as such.

The rule stays, documented as a prior, with its two residual leaks named at the
module. Six rounds would have been the same shape.

## Alternatives considered

**A sixth rewrite.** Rejected: the evidence is five rounds of each looking
obviously correct. After the third, the question is not "what did I miss" but "can
this shape be right at all".

**Replace it with a public-suffix list.** Rejected: it is a much better prior —
the PSL *is* the rule for where a name ends — but the collisions here are not
suffix membership. `django.contrib.auth.models` ends in `models`, which the PSL does
not list, and `com.acme.internal-tools` ends in a token the pattern cannot split
correctly. A suffix list narrows the shape without adding information about
*position* or *provenance*, which is what the problem turns on. It would also be a
large generated table to keep current in a crate that depends on `regex` and
nothing else.

**Drop host masking from free text entirely and rely on field provenance.** That
is the right instinct and it is where this ended up — but doing it *first*, with
nothing in the gap, would have been a regression rather than a fix. The private-
suffix rule still catches `bastion.corp` in a message, and a reporter's error
string carries bare FQDNs more often than it carries labelled fields.

## Consequences

- Two leaks are accepted and named at the module rather than papered over: a bare
  `printer.local`, and `10.1.2.3.acme.local` leaving `acme.local` behind because
  the IP rule runs first. Both come from the `.local` relaxation, which exists
  because `config.local` and `settings.local` are in every Vite, Next and Django
  project there is.
- The build-first instruction mattered more than the diagnosis. Five rounds had
  added unit assertions for their own motivating examples and none had added an
  invariant that would have predicted the next round. A **differential corpus**,
  checked in both directions, would have surfaced the whole pattern on its first
  run — that corpus is now `host_corpus` in `src/redact.rs`.
- **A run of fixes that each look obviously correct is itself evidence.** That
  lesson generalises past this function, which is why it is written down here
  rather than left in the commit message.
- The prior is now the *last* of three rules rather than the only one; see
  [0006](0006-field-provenance-and-host-position.md).
