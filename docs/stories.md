# Who squelch is for

## The thesis

Every piece of software that wants bug reports currently hand-rolls the same
thing: a template nobody fills in properly, an environment block the reporter
guesses at, and — if anyone thought about it — an ad-hoc attempt at stripping
paths out of a log tail.

Most projects do a worse job than they would like to, not because they don't
care but because doing it well is a surprising amount of work with a failure
mode that is silent. squelch exists so that offering a good report path is a
dependency, not a project.

## Actors

Four, and they want different things. Most of the design tension comes from
serving all of them at once.

### The reporter

An end user of some software that embeds squelch. They hit a problem. They do
**not** know what the maintainer needs, they do not know what a "target triple"
is, and they have no way to judge which parts of their logs are safe to publish.

They are also not obliged to trust the tool. Anything it collects on their
behalf must be visible to them before it leaves.

### The embedding developer

Ships software and wants a report path without building one. Their bar is: a
dependency, a few lines, and no new operational burden. If squelch requires
them to run a service, they will skip it.

They also carry the consequences of a leak from their software, so the default
configuration has to be the safe one.

### The maintainer

Receives the issue. Needs enough to reproduce, or enough to ask one good
question instead of three bad ones. Also needs the tracker not to fill with
noise, because a tracker nobody can triage is worse than a quiet one.

### The agent

Increasingly, the thing that noticed the problem is an AI agent running inside
the software. It can compose a far better report than a human — it has the
error, the state, and the context — but it is also prolific and confidently
wrong, and it must never be able to file unilaterally.

## Stories

### Reporter

- As a reporter, I want to describe what broke and have everything else filled
  in, so that filing costs me one command and no research.
- As a reporter, I want to see exactly what will be sent before it is sent, so
  that I can decline if it contains something I did not expect.
- As a reporter, I want the tool to strip my paths, hostnames and credentials
  by default, because I cannot audit a log tail myself and should not have to.
- As a reporter who already has `gh` authenticated, I want to file without
  leaving my terminal, because a browser round trip is the slowest part.
- As a reporter with no browser and no network — which is a state some bugs
  create — I want a file I can attach later.
- As a reporter, I want to be told what is missing *before* anything opens, not
  after I have loaded a form.

### Embedding developer

- As an embedding developer, I want a working report path in a few lines,
  because if it takes an afternoon I will do it badly or not at all.
- As an embedding developer, I want the safe configuration to be the default,
  so that shipping it without reading the docs still does not leak.
- As an embedding developer, I do not want to run a service, so the default
  route must need no infrastructure and no credential.
- As an embedding developer with a service, I want to use it, so a route that
  posts to my own endpoint must exist and take my own auth.
- As an embedding developer, I want to expose this through whichever surface my
  software has — CLI, GUI, or an agent tool — without reimplementing the logic
  per surface.
- As an embedding developer, I want my issues to look the same regardless of
  which route the reporter used, so my triage and automation do not have to
  handle two shapes.

### Maintainer

- As a maintainer, I want the environment block to be machine-collected, so it
  is accurate rather than remembered.
- As a maintainer, I want to know which build actually ran, because on a rolling
  channel a version string covers many commits and "is this already fixed" is
  otherwise unanswerable.
- As a maintainer, I want to tell "the reporter has no `SHELL` set" — itself
  diagnostic — from "the tool never looked", so absent values must be stated
  rather than omitted.
- As a maintainer, I want reports that are not reproducible to become
  discussions instead of issues, so the tracker stays actionable.
- As a maintainer, I want a redacted log tail that is still diagnostic, because
  a block that has been scrubbed into uselessness costs me the same triage round
  trip as no block at all.

### Agent

- As an agent, I want a schema for the report fields, so I do not guess at them.
- As an agent, I want to compose a report and hand it to a human, so that my
  being wrong costs a glance rather than a filed issue.
- As a maintainer, I want an agent to be unable to file without a human, so the
  tracker does not become a firehose with one extra click.

## Surfaces

squelch is an *application feature*, not a CLI. The same composition is exposed
through whatever surface the software already has:

| surface | what it needs from the crate |
| --- | --- |
| CLI | field values from flags or an editor; a preview to print; a route to send |
| GUI | the **field definitions** — label, help text, required, multiline — so it can render a form; a preview to display; a progress/result to show |
| MCP / agent tool | a **JSON schema** of the fields; a compose call that returns a payload and sends nothing |

The core must therefore assume no terminal: no printing, no prompting, no
reading of stdin. It composes and returns; the surface decides how to show and
when to send.

### The gap this reveals

A CLI can get by with `field(id, value)`. A GUI cannot — it has to *render* the
form, which means it needs the field definitions. An agent surface needs the
same information as a schema.

So squelch needs a `Form` model — id, label, description, required, kind — that
all three surfaces read. Today the crate only has values, which quietly makes it
a CLI library wearing a general-purpose name.

**Resolved:** `Form` is a plain data structure with optional serde derives.
squelch does not choose the format. A consumer declares the form in Rust, or
deserializes it from the YAML they already keep in `.github/ISSUE_TEMPLATE/`, or
from JSON, TOML or RON — with whichever parser they already depend on. The crate
takes no format dependency, because every consumer already has one and
inheriting ours would be a tax.

For the GitHub case there is `form::github::IssueForm`, which mirrors GitHub's
*documented* issue-form schema rather than any project's template, so it cannot
drift from a file we do not control.

**Proven, not asserted.** `apps/squelch-demo` exposes the CLI and the agent
surface over one `Form`, and the end-to-end suite drives the binary rather than
the library, so the claim that a surface can be built on this API is checked by
a compiler rather than by this document. Standing the agent surface up
immediately found a schema no agent could satisfy — `environment` was `required`
but absent from `properties` under `additionalProperties: false` — which is the
argument for building a surface rather than describing one. See
`docs/testing.md`.

## Non-goals

- **Being a bug tracker.** squelch composes and dispatches. It does not store,
  deduplicate, or track state.
- **Submitting on the reporter's behalf by default.** The human stays the author
  and the last checkpoint.
- **Holding a credential.** Not for GitHub, not for anything.
- **Scrubbing the reporter's own prose.** If they type their employer's name
  into the description, that is their disclosure. The crate's duty is to ensure
  *it* added nothing they did not choose to say.
- **Guessing the destination.** A missing `repository` is a build-configuration
  error worth surfacing, not something to infer.
