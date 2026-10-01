# ADR-0008: `Form::parse_skeleton` takes `&self`

- **Status:** accepted
- **Date:** 2026-08-14

## Context

`Form::skeleton` renders an editable markdown template for a CLI that opens
`$EDITOR`: the field ids, their labels and descriptions, and empty answer blocks.
The reporter edits it and hands it back, and `Form::parse_skeleton` reads the
answers out again.

The round trip is not free, because the reporter's own text sits next to the
delimiters the parser looks for. Someone who writes `-->` inside a reproduction
step, or a field whose answer happens to imitate a heading, breaks a naive parse —
and the failure is **silent in the worst direction**: an answer is lost, and the
report is submitted without it.

Guidance rides in HTML comments so it can be left in place and still be stripped on
the way back. That creates its own hole: a description containing `-->` closes the
comment early, and the remainder renders as literal text in the reporter's editor.

## Decision

**`parse_skeleton` takes `&self`, and that is the load-bearing part of the design.**

It is not an associated function because it needs the form's own field ids to know
which blocks are answers and which are guidance. Given the ids it can distinguish a
delimiter the crate emitted from an imitation of one, and it can attribute an
answer to the field it belongs to rather than to a position in the text.

The related hardening follows from the same place:

- A description or label containing `-->` is **neutralised** before interpolation,
  so it cannot close the comment it is inside.
- The parser tolerates a reporter's own text imitating a delimiter, which is
  asserted as a **round-trip property** over generated skeletons rather than as a
  test for the one input that motivated it.
- The parser is not `pub`-crashable on a mutated answer: a malformed block is an
  `Err` that names the field, not a panic.

## Alternatives considered

**An associated function taking a list of ids.** Rejected: it moves the knowledge to
the caller, and the caller is a surface that already has the `Form`. The signature
that cannot be called wrong is the one that carries the form.

**Parse by position** — "the Nth block is the Nth field". Rejected: it breaks the
moment a field is optional and left blank, which is the common case. The reporter
skipping "Impact" would shift every answer after it.

**An explicit machine-readable envelope** (JSON between the markers rather than
markdown). Rejected: the whole point of the skeleton is that a human edits it in
their own editor, with their own tools. A format that is not pleasant to edit by
hand fails at the only job it has.

**Drop the round trip and prompt field by field.** Rejected: `docs/stories.md`
requires one composition to serve a CLI, a GUI and an agent surface, and an editor
buffer is how a CLI reports a reproduction the reporter does not want to retype.
`field(id, value)` alone is not enough for that.

## Consequences

- `parse_skeleton` cannot be used without a `Form`, which is intended: every path
  into it in this crate has one.
- The `&self` borrow means a caller can parse several skeletons against one form
  concurrently, which a GUI re-rendering a form wants.
- Round-trip fidelity is now a **property** (`a_skeleton_returns_the_answers_it_was_given`),
  so a future delimiter or a new `FieldKind` inherits the guarantee rather than
  needing a test written for it.
- Guidance is stripped on the way back, so anything a reporter types *inside* an
  HTML comment is lost. That is stated rather than silently accepted: comments are
  invisible in every editor that renders markdown, so text placed there is text
  placed where nobody will see it.
