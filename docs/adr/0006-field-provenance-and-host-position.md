# ADR-0006: field provenance and host position, instead of a sixth shape rule

- **Status:** accepted
- **Date:** 2026-10-01
- **Supersedes in part:** [0005](0005-the-host-rule-is-a-prior.md)

## Context

[0005](0005-the-host-rule-is-a-prior.md) concluded that a shape-based host rule
cannot converge, because a hostname and a reverse-DNS package are the same string
in opposite orders. It recommended a hybrid and, first, a differential corpus.

The corpus is in (`host_corpus` in `src/redact.rs`, checked in both directions over
real module paths and real hostnames). It reports one false negative and no false
positives against the prior, and it deliberately does **not** assert the generative
`{host|package}.{case}.{suffix}` invariant — measured, no context-free rule
satisfies it, because `bastion.com` and `foo.tar.gz` are the same two-label shape.

So the two better signals had to be built.

## Decision

Three rules, in order, only the last of which is a guess.

| signal | where | what it knows |
|---|---|---|
| **field provenance** | a field called `host`, `remote`, `upstream`, `peer`, … | the value **is** a name, by contract |
| **position** | after `resolve `, `connect to `, inside `host=` | nothing else goes there |
| **shape** (`mask_hosts`) | anywhere else | a prior, tuned against a corpus |

**Field provenance.** `Redactor::records` looked a value up by name and threw the
name away — `self.scrub(&raw)` with `name` right there in scope. A field called
`host` holds a hostname *by contract*, which is a statement about meaning rather
than a guess from shape. The new `scrub_value(field, value)` uses it;
`scrub` is `scrub_value(None, …)` and is unchanged for every caller with no field
context. `host`, `hostname`, `remote`, `peer`, `addr`, `address`, `endpoint`,
`server` and `upstream` joined `DEFAULT_SCRUBBED_FIELDS`, so a structured record
now carries `host="<host>"` — which tells a maintainer a network name was involved
and discloses nothing about which one.

**Position.** Nothing but a name follows `resolve ` or sits inside `host=`. This
reaches the case shape structurally cannot:

```text
resolve bastion          →  resolve <host>
```

A **single-label** name. There is no dot to build a dotted run out of, so no
amount of shape analysis finds it, and it is the machine's own name — the most
identifying thing in the line. It leaked under all five previous rounds.

Measured over 13 suffixes × 6 machine-shaped leading labels: **40 leaks in free
text, 0 in a `host` field**, and 0 module paths over-masked in either. The field
rule does not touch `message`, which is where the collisions live, so the
free-text rule stays exactly where it was instead of being widened to compensate.

**Tool verbs are a separate rule.** `curl`, `ssh` and `ping` take a host as their
first argument and also appear in ordinary sentences — `curl the page`, `ssh the
gateway`. There the token must additionally carry a dot, a digit or a hyphen.
`dial` is *not* in that set: it is a connection verb, and `dial redis` is a real
leak of a real service name with no competing English reading.

## Alternatives considered

**Delete the FQDN branch, as #5 proposed.** Measured before deciding: the branch
contributes 2 of 19 masks in the corpus and costs 0 over-masking on the real
corpus. It is not obviously wrong — but it is the branch that keeps confusing
itself with `django.contrib.auth.models`, and with the two better signals in place
its remaining 2 masks are covered by position anchors. It was kept rather than
deleted because deleting it trades a measured zero for a measured leak in bare
prose, and the honest reading of the spike is that the branch is *tolerable*, not
that it is *needed*. Recorded here so the next reader knows which way that went.

**Anchor-only, no field provenance.** Rejected: it leaves the two-label class
(`bastion.com`) open, which is 40 of the 40 measured leaks, and it depends on the
reporter's locale for a rule that a structured log makes locale-independent.

**Field provenance only, no anchors.** Rejected: `Record`'s fields are all public
and `Report::diagnostics` takes any iterator of them, so an application mapping its
own `tracing` output never goes through `records` at all. The anchors are what
cover that path.

**Make `scrub_value` take the field name as `&str` and rename `scrub`.** Rejected:
`scrub` is the API every existing consumer calls, and it has no field context.
Renaming it is a breaking change for no gain.

## Consequences

- **Four new costs, all documented at the rules** rather than discovered later:
  a bare `<word>.local` still survives in free text; a bare public FQDN with no
  verb in front of it survives; the position anchors are English, so a message in
  another language gets no help; and a field-name list is a policy surface — adding
  to `DEFAULT_SCRUBBED_FIELDS` publishes a field name that was previously dropped.
- The `.local` relaxation's single leak is now confined to the smallest region it
  can be: free text, with no field name and no position signal.
- **The field rule has to be idempotent.** Accepting bare words means the pattern
  also matches the crate's own `<host>` marker, and the first implementation
  produced `<<host>>`. Fixed by splitting the value on markers rather than testing
  the match, because `<host>` is four bare words to this pattern and its angle
  brackets are word boundaries — no callback guard on the surrounding text fires.
  `keep_hosts` needed the same treatment: its swap token was a bare word too, and
  a kept name came back as `\0<host>\0`.
- A single label in a host field **is** masked, so `host=localhost` becomes
  `<host>`. The first draft required a dot and the end-to-end canary caught it in
  one run: `host=cache01` and `peer=frontend` are exactly what these fields carry.
  `keep_hosts` is the opt-out, and it is tested.
- The three signals are locale-independent except the anchors, which is a reason to
  prefer field provenance where an application can supply it.
