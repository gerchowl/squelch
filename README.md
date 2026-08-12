# squelch

**Let your users file a bug report that's actually useful — without asking them to know what you need, and without leaking their machine onto a public tracker.**

```rust
let redactor = Redactor::new();

let report = report!()?
    .template("bug.yml")
    .field("current-behavior", current)
    .field("reproduction", repro)
    .require(["current-behavior", "reproduction"])
    .provenance(provenance!().scrubbed(&redactor))
    .diagnostics(redactor.records(&logs, Some("myapp.jsonl")))
    .via(Transport::Browser);

println!("{}", report.preview()?);   // exactly what would leave
report.send()?;                       // opens GitHub's form, prefilled
```

Your user writes what broke. Everything else — versions, OS, build shape, a redacted log tail — is collected. They land on your real issue form with it already filled in, review it, and click Submit.

## Why "squelch"

On a radio, the squelch is a threshold you tune: it mutes the channel until a real signal is present, so you hear the transmission instead of the hiss.

That's the job here, at three levels. Noise out of the **report** — the reporter describes the problem, the machine supplies the facts. Noise out of the **tracker** — required fields are checked before anything opens, so nobody discovers what's missing after a browser launch. And eventually noise out of the **product**, because reports you can act on become fixes, and fixes mean fewer reports.

Tuning the squelch is the loop, not a single function.

## The problem it solves

A good bug report contains a dozen facts the reporter has no reason to know are relevant, and at least three they'd rather not publish. Existing tools do one half or the other:

| | collects environment | redacts | builds the issue |
|---|---|---|---|
| [`bugreport`](https://crates.io/crates/bugreport) | yes | **no** — [documented as unimplemented](https://github.com/sharkdp/bugreport) | no |
| [`github-issue-url`](https://crates.io/crates/github-issue-url) | no | no | yes |
| **squelch** | yes | yes | yes |

Redaction is the part that's hard to bolt on afterwards, because the failure is silent and unrecoverable: by the time you notice, the report is on a public tracker.

## What gets scrubbed

The scrubber is an **allowlist over structured fields** — named fields are kept, everything else is dropped unread — plus value rules over what survives:

- the current user's home (`/home/alice/x` → `~/x`) and username, and any other account's home, including Windows profile paths
- credentials: `ghp_…`, `github_pat_…`, `sk-…`, `xox…`, AWS keys, JWTs
- labelled secrets **including underscored ones** — `refresh_token=`, `client_secret=`, `api_key:` — which a naive `\btoken\b` rule silently misses, because `_` is a word character so there's no boundary before `token`
- emails, `user@host` ssh targets, and git remotes with their org and repository name
- IPv4, and IPv6 **including compressed forms** — `::1`, `fe80::1`, `2001::abcd`
  are what logs actually contain, and a rule needing two full `hex:` groups
  misses all of them
- hostnames under private suffixes (`.internal`, `.corp`, `.local`, …) at any
  depth, and lowercase FQDNs of four or more labels, with `_` allowed in a label
  because SRV records and internal DNS use it

  Four labels, not three, and lowercase-only, because the alternative destroys
  the block: three labels ate `config.yml.bak` and `os.path.join`, and
  case-insensitivity ate `java.lang.Thread.run`. A three-label public host like
  `foo.example.com` therefore survives — deliberately. Anything genuinely
  internal is caught by its suffix regardless of depth.

Invisible characters are stripped **before** any rule runs. A zero-width space
inside a credential breaks every character-class run, and renders as nothing —
so a reviewer sees an intact token in the preview and no reason to object.

An allowlist rather than a denylist because a denylist fails open the moment someone adds a log field, and nobody revisits a denylist when they add one. With an allowlist the worst case is a report that's less useful than it could be.

There's a test pinning the strings that must *survive* — `No such file or directory (os error 2)`, `server.log`, `0.6.8-fork.85ce040` — because over-masking makes the block worthless just as surely as under-masking makes it dangerous.

## Nothing reaches the tracker without passing one choke point

Escaping happens where a value becomes text — `Record::render` and
`Provenance::to_markdown` — not where a value is parsed. That matters because
`Record`'s fields are public and `Report::diagnostics` takes any iterator of
them, so an application mapping its own `tracing` output onto `Record` never
touches the parser. Escaping at the parser would have covered the JSONL path
and nothing else.

The environment block is escaped differently from the log block, because it is
not fenced: markup there has nothing to break out of, so `<` and `&` are
entity-escaped rather than merely flattened.

## Values can't escape the markdown block

A log value containing a fence, a `</details>`, or a newline would otherwise break out of the code block and land as live markdown in a public issue. GitHub strips `<script>` but renders `<img src=x onerror=…>`.

This is a real bug in the wild, not a hypothetical — `bugreport` formats arbitrary file and command output straight into a fence with no escaping.

## Routes, and what each one costs

| route | validates your form | human reviews first | needs a credential |
|---|---|---|---|
| `Browser` *(default)* | yes — GitHub's own | yes — the form **is** the review | no |
| `Mailto` | no | yes — their mail client | no |
| `File` | no | yes — they open it | no |
| `GhCli` | no | only if you confirm | the user's `gh` |
| `Endpoint` | no | only if you confirm | server-side |

Posting a body through an API bypasses issue-form validation entirely — `required: true` never runs. That's what the GitHub API does, not a limitation here, but it means your form is advisory on every route except `Browser`. The two routes that transmit without a built-in review surface refuse to send until you call `.confirmed()`.

**`Browser` is the only route with a size limit.** A prefill URL is capped, so a long report can lose a whole section on the way into the form. `Browser` refuses rather than open a form the reporter has already approved in a preview that showed more than would arrive — showing *less* than leaves is a privacy failure, showing *more* corrupts what they believe they consented to send. `Composed::url` names what was `shortened` and what was `dropped`, so your surface can offer another route. The report itself is fine at any length; every other route carries it whole.

**`Endpoint` is an open gateway unless you gate it.** A CLI can't solve a CAPTCHA, so the abuse protection a web app would use isn't available. An unauthenticated issue-creating endpoint is a spam target the moment its URL is found — and it will be found, because it ships inside your binary. Rate-limit at the edge, require a proof-of-work stamp, or use real per-user auth.

## What it will never do

**Carry a credential.** No bundled token, no default endpoint. A write credential inside a distributed binary gets extracted; the only safe place for one is a server you operate.

**Put diagnostics in the URL.** GitHub records full request URLs server-side, so anything in the query string is disclosed the moment the browser opens — *before* the reporter decides whether to submit. Log tails go to a file or the clipboard for a deliberate paste.

**Tick a confirmation checkbox.** GitHub can't prefill `checkboxes` at all, and that's the right outcome: a "yes, this is reproducible" box is an attestation, and a tool that ticks it forges a human's statement.

## Absent values are stated, not omitted

A missing `Shell:` line leaves a triager unable to tell "this reporter has no `SHELL` set" — itself diagnostic, and the signature of a stripped service environment — from "the tool never looked". So every field renders, with an explicit marker when it couldn't be determined. Borrowed from `bugreport`, whose collectors turn a failure into a report entry rather than dropping the section.

## Features

| feature | default | adds |
|---|---|---|
| `browser` | yes | open the prefilled form — no dependencies |
| `logs` | yes | JSONL extraction (`serde_json`) |
| `gh-cli` | no | create the issue with `gh` — no dependencies |
| `endpoint` | no | POST to an endpoint you operate (`ureq`, `serde_json`) |
| `schema` | no | `Form::json_schema()` for an agent tool surface (`serde_json`) |
| `serde` | no | derive serde on `Form`, so you can load it from your own YAML/JSON/TOML |

With `default-features = false` the only dependency is `regex`, and it still redacts, builds URLs and renders bodies.

## Build-time facts

Target triple, profile and commit aren't derivable at runtime — `std::env::consts` gives OS and architecture but can't tell a musl build from a gnu one, and "this is a debug build" explains a whole class of performance reports on its own.

```rust
// build.rs
println!("cargo:rustc-env=MYAPP_TARGET={}", std::env::var("TARGET").unwrap());
println!("cargo:rustc-env=MYAPP_PROFILE={}", std::env::var("PROFILE").unwrap());
```

```rust
provenance!()
    .build(env!("MYAPP_TARGET"), env!("MYAPP_PROFILE"))
    .commit(option_env!("MYAPP_COMMIT"))
```

## Try it

```
cargo run --example file_a_bug
```

Composes a full report, prints the preview, and shows what the redactor kept and dropped. Nothing is sent.

## Status

Early. The redaction rules have been exercised against a real ~10k-line production log corpus and an adversarial review pass, but the API may still shift before 1.0. If you find a leak, that's the bug worth reporting.

## License

MIT OR Apache-2.0
