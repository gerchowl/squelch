//! Scrubbing identifying material out of text and structured log records.
//!
//! This is the module the crate exists for. Everything else — provenance,
//! URL building, transports — is assembly you could write yourself in an
//! afternoon. Getting redaction right is not, because the failure is silent
//! and unrecoverable: the report is already on a public tracker.
//!
//! # Allowlist, never denylist
//!
//! [`Redactor`] keeps an explicitly named set of structured fields and drops
//! everything else **unread** — with two exceptions, `timestamp` and `level`,
//! which are always extracted because a log line without them is not a log
//! line. Both are scrubbed like any other value, and were the one hole in this
//! promise: pulled out of the JSON and rendered verbatim, they published
//! whatever a hostile emitter put in them while the allowlist protected every
//! field except the two guaranteed to be present.
//!
//! A denylist over a logging surface fails open the
//! moment someone adds an emitter, and nobody revisits a denylist when they add
//! a field. With an allowlist, a new field is excluded by default and the worst
//! case is a report that is less useful than it could be.
//!
//! # What the value rules cover
//!
//! Retained values still pass through the scrubber, because being on the
//! allowlist is not a promise that a future emitter keeps the value boring:
//!
//! - the current user's home directory (`/home/alice/x` → `~/x`) and username
//! - any other account's home (`/home/bob/x` → `<path>`), including Windows
//! - credentials: `ghp_…`, `github_pat_…`, `sk-…`, `xox…`, AWS keys, JWTs
//! - labelled secrets, **including underscored ones** — `refresh_token=`,
//!   `client_secret=`, `api_key:` — which a naive `\btoken\b` misses, since
//!   `_` is a word character and so there is no boundary before `token`
//! - email addresses, `user@host` ssh targets, and git remotes with their org
//!   and repository name
//! - IPv4, IPv6 and MAC addresses
//! - hostnames under private suffixes, and FQDNs of three or more labels whose
//!   final label is a real suffix
//! - identifiers *labelled* as naming the machine — `machine-id`, `serial`,
//!   `udid`, `imei`
//!
//! # Hostnames: three signals, and why there are three
//!
//! A hostname and a reverse-DNS package identifier are **the same string in
//! opposite orders** — `bastion.corp.acme.com` against `com.example.app` — and
//! over a context-free dotted token there is no discriminator that is not itself
//! a prior. Shape cannot do it, and neither can length, nor case (Java breaks
//! convention with `com.foo.internal.Impl`, DNS with `SERVER01.CORP`), nor
//! suffix membership (`.app` and `.dev` are both gTLDs and both common endings
//! of module paths).
//!
//! That is not a gap to be closed by a better shape rule. It is why
//! `mask_hosts` was rewritten **five times**, each round correct about the case
//! that motivated it and wrong about the case next door, and why the fifth round
//! was not the last. `mask_hosts` is still there and still a prior — but it is
//! now the *last* of three, not the only one, because two better signals were
//! sitting unused.
//!
//! | signal | where | what it knows |
//! |---|---|---|
//! | `scrub_value` | a field called `host`, `remote`, `upstream` | the value **is** a name, by contract |
//! | the anchored rules | after `resolve `, `connect to `, inside `host=` | nothing else goes in that position |
//! | `mask_hosts` | anywhere | shape — a prior, and the only one of the three |
//!
//! The first two are not heuristics and do not need a corpus. A field called
//! `host` holds a hostname by the contract of its name, and a name after
//! `resolve` is a name whatever it is made of. That is what finally reaches the
//! case the shape rule structurally cannot:
//!
//! ```text
//! resolve bastion          →  resolve <host>
//! ```
//!
//! A **single-label** name. There is no dot to build a dotted run out of, so no
//! amount of shape analysis finds it, and it is the machine's own name — the
//! most identifying thing in the line. It leaked under every previous version.
//!
//! # What it deliberately does not cover
//!
//! **Encoded secrets.** A base64, hex or `\u`-escaped token matches nothing
//! here. Decoding every candidate run to search inside it is a different tool
//! with a different cost, and the decoded-and-re-encoded search space has no
//! natural floor. What contains encoded credentials in practice is a JSON
//! error body from a downstream service, and the labelled-secret rule catches
//! those by their key rather than their contents.
//!
//! **Bare UUIDs.** Request ids, trace ids and span ids are UUIDs, and they are
//! the thread a maintainer follows through a log. Masking them costs the
//! report the one thing that makes it followable, for a machine id that is
//! only a machine id when something says so — which is why the label, not the
//! shape, is what fires the rule.
//!
//! **Hostnames on unusual suffixes.** The FQDN rule tests the final label
//! against a list, because without one it cannot tell
//! `bastion.corp.acme.com` from `django.contrib.auth.models` — they have the
//! same shape, and masking the second cost a Django traceback the line that
//! says where the bug is. A host under a suffix not on that list is not
//! matched by *this* rule; the field-name and position rules, the
//! private-suffix rule, `user@host` and the git-remote rule are what cover the
//! shapes that carry a name in practice.
//!
//! **A bare two-label `<word>.local` or `<word>.private` in free text.**
//! `printer.local` is kept, because `.env.local`, `settings.local` and
//! `keys.private` are the same shape and are in every project there is. At two
//! labels a name under one of those two suffixes has to *look* like a machine —
//! a digit or a hyphen — before it is treated as one. That is a narrower loss
//! than it sounds: the names which actually identify a person are the ones macOS
//! and DHCP generate, and those carry hyphens (`alices-macbook.local` is
//! masked).
//!
//! The same name in a field called `host` **is** masked, and the same name after
//! `resolve ` **is** masked. This gap is now confined to the one place it has to
//! live: free text with no position signal and no field name. That is the
//! smallest region it can be confined to, which is the argument for the two new
//! rules rather than a sixth attempt at the shape.
//!
//! Only those two suffixes. There is no `settings.corp` or `keys.intranet`, so
//! `bastion.corp`, `vault.internal` and `db.lan` are masked at two labels like
//! anything else — relaxing every private suffix uniformly leaked exactly the
//! names the rule exists for.
//!
//! **A bare public FQDN in prose with no verb in front of it.**
//! `the server at build01.foo_bar.example.com is down` survives unless the
//! sentence says `resolve` or `connect to`. This is the cost of relying on
//! position, and it is stated here rather than left to be discovered: a public
//! hostname in an error message is a far smaller disclosure than a corporate
//! one, and the alternative — a shape rule broad enough to catch it — is the
//! rule that ate `django.contrib.auth.models` in the first place.
//!
//! **A non-English message.** The anchors are English and
//! configuration-file conventions: `Could not resolve` is one resolver's
//! wording, and a library that phrases it differently gets no help from the
//! position rules. A guarantee that quietly depends on the reporter's locale is
//! not a guarantee, so this is a documented limit rather than an implied one.
//! The field-name rule is locale-independent, which is one more reason to prefer
//! it where the application can supply it.
//!
//! The trade runs the other way too, and two losses are accepted on purpose:
//!
//! - A three-label filename ending in a private suffix —
//!   `docker-compose.override.local` — is masked, because at three labels the
//!   shape really is a hostname's.
//! - A module path from an ecosystem that does *not* use reverse-DNS, with a
//!   private-suffix word in the middle — `myapp.internal.helpers` — is masked.
//!   It is indistinguishable from `bastion.corp.acme-inc`, and only one of the
//!   two is recoverable when the rule guesses wrong. It survives in a `message`
//!   field, and in any field not named for a host.
//!
//! A filename or a frame costs a round trip; a hostname does not come back.
//!
//! Two known leaks, both consequences of the `.local` relaxation and both
//! kept because the fix endangers `.env.local`: a bare `printer.local`, and an
//! address immediately followed by a dotted name — `10.1.2.3.acme.local`
//! leaves `acme.local` behind, because the IP rule runs first and the
//! remaining two labels then look like a filename.
//!
//! # This rule is a prior, not a classifier
//!
//! A hostname and a reverse-DNS identifier are the same string in opposite
//! orders, and no context-free test over a dotted token settles which is
//! which. Case is a convention Java breaks with `com.foo.internal.impl` and
//! DNS breaks with `SERVER01.CORP`; suffix membership flips the moment `.app`
//! and `.dev` become both gTLDs and bundle-id endings.
//!
//! So every constant above is a prior tuned against the cases someone has
//! thought of, and the numbered decisions in `mask_hosts` are the order
//! those priors are applied in. Five rewrites in one sitting each fixed the
//! previous round's defect and opened another one next door — the history is
//! in `docs/testing.md`, and the honest reading of it is that this shape has
//! run out of discriminating power rather than that the last exception has
//! been found.
//!
//! What replaces it is context: mask what appears in host *position* — after
//! `resolve`, `connect to`, `://`, `@`, `host=` — and, for structured records,
//! use the field name, which this crate already knows and currently throws
//! away before scrubbing. Tracked as its own change rather than a sixth patch.
//!
//! Free-form user prose. If your reporter types their employer's name into the
//! description field, that is their disclosure to make — the crate's job is to
//! ensure *it* did not add anything they did not choose to say.

use std::sync::OnceLock;

use regex::Regex;

/// Structured field names carried out of a log record by default.
///
/// Every one is a low-cardinality, enum-shaped value or a bare program name.
/// Adding to this list is a privacy decision, not a formatting one.
pub const DEFAULT_ALLOWED_FIELDS: &[&str] = &[
    "event",
    "subsystem",
    "component",
    "outcome",
    "status",
    "code",
    "kind",
    "state",
    "reason",
    "phase",
    "duration_ms",
    "elapsed_ms",
    "latency_ms",
    "attempt",
    "retries",
    "count",
    "bytes",
    "pid",
    "protocol",
    "version",
    // The program NAME only ("git", "ssh"). Its arguments are NOT allowed —
    // that is where paths, branches and remotes live.
    "program",
];

/// Fields carried only after passing through the scrubber.
///
/// `err` is the single most diagnostic field in a bug report — dropping it
/// leaves records that say only "something failed" — so it is scrubbed rather
/// than discarded.
///
/// The network-name fields are here for the same reason, and the entry is only
/// safe **because** [`Redactor::scrub_value`] exists. Before it, a `host` field
/// had to be either dropped or published, and publishing it meant guessing from
/// the shape of a token that is indistinguishable from a module path — the
/// position five rounds of `mask_hosts` failed to resolve. Now the field name is
/// the evidence, so the value can be carried and masked with certainty: what
/// reaches the report is `host="<host>"`, which tells a maintainer that a
/// network name was involved and discloses nothing about which one.
///
/// This is a privacy decision, like every other entry here — adding a field is
/// not a formatting choice. It runs the safe way: the value is masked by a rule
/// that is *more* aggressive in this field than anywhere else, so the worst case
/// is a report carrying `<host>` where it might have carried nothing.
pub const DEFAULT_SCRUBBED_FIELDS: &[&str] = &[
    "message", "msg", "error", "err",
    // Field-provenance fields. A value in one of these is a network name by
    // contract, so it is masked by name rather than by shape.
    "host", "hostname", "remote", "peer", "addr", "address", "endpoint", "server", "upstream",
];

/// Cap on any single retained value, in characters.
const MAX_VALUE_CHARS: usize = 1_024;

/// One log record reduced to what may be published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// When the line was emitted, scrubbed. Always extracted, because a log
    /// line without one is not a log line — see the allowlist note in the
    /// module docs.
    pub timestamp: String,
    /// The severity the emitter gave it, scrubbed. Defaults to `INFO` when the
    /// line carried none.
    pub level: String,
    /// Which file or stream this came from, when the caller tagged it.
    pub source: Option<String>,
    /// Retained fields, in a stable order so two runs render identically.
    pub fields: Vec<(String, String)>,
}

impl Record {
    /// Render as a single line. A record is always one line — see
    /// [`sanitize_for_block`].
    pub fn render(&self) -> String {
        // Every part is sanitized HERE rather than only where records are
        // parsed, because this is the one choke point a value must pass to
        // become text. Two ways in were open otherwise:
        //
        // - `timestamp`, `level` and `source` never went through the JSONL
        //   path's escaping, so a log line whose timestamp carried a newline
        //   and a fence broke out of the block and landed as live markdown.
        // - every field of `Record` is `pub` and [`crate::Report::diagnostics`]
        //   takes any `IntoIterator<Item = Record>`, so an application that
        //   builds records from its own logging stack — an entirely ordinary
        //   thing to do — bypassed escaping completely.
        //
        // `sanitize_for_block` is idempotent, so the JSONL path escaping the
        // value earlier costs nothing here.
        let mut out = format!(
            "{} {:>5}",
            sanitize_for_block(&self.timestamp),
            sanitize_for_block(&self.level)
        );
        if let Some(source) = &self.source {
            out.push_str(&format!(" [{}]", sanitize_for_block(source)));
        }
        for (key, value) in &self.fields {
            out.push_str(&format!(
                " {}={}",
                sanitize_for_block(key),
                sanitize_for_block(value)
            ));
        }
        out
    }
}

/// Scrubs identifying material out of text.
///
/// Construct with [`Redactor::new`] to read the environment, or
/// [`Redactor::with_identity`] to supply the home directory and username
/// explicitly — useful in tests, and for daemons whose environment has been
/// stripped.
#[derive(Clone)]
pub struct Redactor {
    home: Option<String>,
    user: Option<String>,
    allowed: Vec<String>,
    scrubbed: Vec<String>,
    keep_hosts: Vec<String>,
}

impl std::fmt::Debug for Redactor {
    /// Deliberately manual. Deriving it would print the home directory and
    /// username — the two values this type exists to keep out of output, and
    /// `Debug` output has a way of ending up in the very logs being scrubbed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Redactor")
            .field("home", &self.home.as_ref().map(|_| "<set>"))
            .field("user", &self.user.as_ref().map(|_| "<set>"))
            .field("allowed_fields", &self.allowed.len())
            .field("scrubbed_fields", &self.scrubbed.len())
            .finish()
    }
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new()
    }
}

impl Redactor {
    /// Read identity from the environment, falling back to the password
    /// database on unix.
    ///
    /// A process started by systemd or launchd frequently has neither `HOME`
    /// nor `USER`. Without the fallback the scrubber silently becomes a no-op
    /// for the username and for any non-standard home, which is the worst kind
    /// of failure here: quiet and total.
    pub fn new() -> Self {
        let home = first_env(&["HOME", "USERPROFILE"]).or_else(passwd_home);
        let user = first_env(&["USER", "LOGNAME", "USERNAME"]).or_else(passwd_name);
        Self::with_identity(home, user)
    }

    /// Supply the identity to mask explicitly.
    pub fn with_identity(home: Option<String>, user: Option<String>) -> Self {
        Self {
            home: home
                .map(|home| home.trim_end_matches(['/', '\\']).to_string())
                .filter(|home| home.len() > 1),
            // Two-character account names are common in corporate directories;
            // filtering them out would silently disable masking for exactly
            // those users. Only an empty name is useless.
            user: user.filter(|user| !user.is_empty()),
            allowed: DEFAULT_ALLOWED_FIELDS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            scrubbed: DEFAULT_SCRUBBED_FIELDS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            keep_hosts: DEFAULT_PUBLIC_HOSTS.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Replace the retained-field allowlist.
    pub fn allow_fields<I, S>(mut self, fields: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allowed = fields.into_iter().map(Into::into).collect();
        self
    }

    /// Add to the retained-field allowlist.
    pub fn also_allow<I, S>(mut self, fields: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allowed.extend(fields.into_iter().map(Into::into));
        self
    }

    /// Hostnames that survive the private-host rule because they identify a
    /// public service rather than the reporter's network.
    pub fn keep_hosts<I, S>(mut self, hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.keep_hosts.extend(hosts.into_iter().map(Into::into));
        self
    }

    /// Scrub a single string.
    pub fn scrub(&self, value: &str) -> String {
        self.scrub_value(None, value)
    }

    /// Scrub a value that arrived in a named field.
    ///
    /// The field name is the decisive signal the crate already has and was
    /// throwing away. Over a context-free dotted token there is no
    /// discriminator between a hostname and a reverse-DNS package — they are
    /// the same string in opposite orders — so any rule working from shape
    /// alone is a *prior* tuned against a corpus, and tuning it against an
    /// adversarial set that grows each time the tuning changes chases a
    /// fixpoint that is not there. Five rewrites of `mask_hosts` are what that
    /// costs (issue #5).
    ///
    /// A field called `host`, `remote` or `upstream` is a hostname **by
    /// contract**: nothing else belongs in it. So for those names the question
    /// is not "is this shaped like a hostname" but "is this a name at all",
    /// which is answerable — and it is answered confidently rather than
    /// probabilistically, in the one place where a false negative is a leak and
    /// a false positive is a mangled field a maintainer can still read.
    ///
    /// Everything else — `message`, `err`, an unknown name — gets exactly what
    /// it got before. That is deliberate: the module-path collisions live in
    /// free text, so this is the signal that lets the free-text rule stay where
    /// it is instead of being widened to compensate.
    ///
    /// `None` is [`Self::scrub`], and is what any caller with no field context
    /// gets. Passing `Some("")` is the same as `None`: an empty name carries no
    /// information, and treating it as a host field would be inventing one.
    pub fn scrub_value(&self, field: Option<&str>, value: &str) -> String {
        // Everything below, unchanged: the general rules, and the free-text
        // host rule at the end.
        let mut out = self.scrub_common(value);

        if field.is_some_and(is_host_field) {
            // The field-aware pass, which runs AFTER the general rules so a value
            // they already handled is not handled twice. Deliberately last:
            // `mask_hosts` in the free-text path can only over-mask, while this
            // can only mask a name that is a name.
            //
            // `keep_hosts` is re-swapped out around it. The general rules
            // restore a kept name on their way out, so by the time this runs the
            // name is back in the text and would be masked again — silently
            // breaking `keep_hosts` for exactly the fields where a consumer most
            // needs it. Swapping here rather than patching afterwards is what
            // keeps the two passes from each undoing the other.
            //
            // The token is NUL-delimited because this pass's pattern accepts bare
            // words, and a token like `sqf0` is one: it was masked in place and
            // the name came out as `\0<host>\0`. NUL cannot appear in the input —
            // `sanitize_for_block` turns control characters into a replacement
            // glyph long before this — so the token is unambiguous.
            let mut restored: Vec<(String, &str)> = Vec::new();
            for (index, host) in self.keep_hosts.iter().enumerate() {
                if out.contains(host.as_str()) {
                    let token = format!("\u{0}{index}\u{0}");
                    out = out.replace(host.as_str(), &token);
                    restored.push((token, host));
                }
            }
            out = mask_names_in_host_field(&out);
            for (token, host) in restored {
                out = out.replace(&token, host);
            }
        }
        out
    }

    /// The rules that do not depend on the field name.
    ///
    /// Split out of [`Redactor::scrub_value`] so the general path and the
    /// field-aware one share one implementation rather than two that can drift.
    fn scrub_common(&self, value: &str) -> String {
        // Strip invisibles only where one could hide a split credential:
        // between two ASCII alphanumerics. A zero-width space inside
        // `ghp_abc<zwsp>def` defeats every character-class run below and
        // renders as nothing, so a reviewer sees an intact token. Stripping
        // unconditionally was worse than the problem — U+200D between emoji is
        // a grapheme joiner, and removing it turned one glyph into three.
        let chars: Vec<char> = value.chars().collect();
        let invisible = |c: char| {
            matches!(c,
                '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{feff}'
            )
        };
        let mut stripped = String::with_capacity(value.len());
        for (index, ch) in chars.iter().enumerate() {
            let hides_a_secret = invisible(*ch)
                && index
                    .checked_sub(1)
                    .and_then(|i| chars.get(i))
                    .is_some_and(|c| c.is_ascii_alphanumeric())
                && chars
                    .get(index + 1)
                    .is_some_and(|c| c.is_ascii_alphanumeric());
            if !hides_a_secret {
                stripped.push(*ch);
            }
        }
        let mut out = stripped;

        // Swap public hosts out before the host rule runs, and back after.
        // A negative lookahead is not available in this regex engine, and
        // keeping the pattern simple is worth more than avoiding the dance.
        let mut preserved: Vec<(String, &str)> = Vec::new();
        for (index, host) in self.keep_hosts.iter().enumerate() {
            if out.contains(host.as_str()) {
                let token = format!("\u{0}sqh{index}\u{0}");
                out = out.replace(host.as_str(), &token);
                preserved.push((token, host));
            }
        }

        // Order matters. The git-remote rule must precede the email rule:
        // `git@github.com:org/private.git` matches as an address, which masks
        // only the prefix and publishes the org and repository in the tail.
        for (pattern, replacement) in [
            (git_remote_re(), "<git-remote>"),
            (secret_token_re(), "<redacted-token>"),
            // Before `labeled_secret_re`, which would otherwise consume the
            // `id=` and leave the identifier itself standing.
            (machine_id_re(), "${1}${2}${3}<machine-id>"),
            (labeled_secret_re(), "${1}${2}${3}${4}=<redacted>"),
            (email_re(), "<email>"),
            (ssh_target_re(), "<ssh-target>"),
            // Before the IPv6 rule, whose colon-run alternative would claim a
            // colon-form MAC and report it as an address.
            (mac_address_re(), "${1}<mac>${2}"),
            (ipv6_re(), "${1}<ip>${3}"),
            (ipv4_re(), "<ip>"),
        ] {
            out = pattern.replace_all(&out, replacement).to_string();
        }
        // Last, and not in the table above: the host rules need the match in
        // hand to decide, so they cannot be expressed as a replacement string.
        //
        // The anchored rule runs FIRST, before the shape-based one, and for a
        // deliberate reason: it decides on *position*, which is the one signal
        // available in free text, and it is right about a token the shape rule
        // would have to guess at. A name in host position is a name whether or
        // not it has a dot in it — `resolve bastion` and `connect to vault` leak
        // under every shape-based rule in this file, and this one catches both.
        out = mask_anchored_hosts(&out);
        out = mask_anchored_machines(&out);
        out = mask_hosts(&out);

        for (token, host) in preserved {
            out = out.replace(&token, host);
        }

        // This user's home first (most specific), then anyone else's.
        if let Some(home) = &self.home {
            // Bounded, not a bare substring replace: with HOME `/Users/alice`,
            // `/Users/aliceOLD/x` became `~OLD/x`, which discloses that a
            // sibling account exists and half-names it.
            let bounded = Regex::new(&format!(r"{}(?:/|\b)", regex::escape(home)))
                .expect("escaped home pattern");
            out = bounded
                .replace_all(&out, |caps: &regex::Captures<'_>| {
                    if caps[0].ends_with('/') {
                        "~/".to_string()
                    } else {
                        "~".to_string()
                    }
                })
                .to_string();
        }
        // `${1}` restores the captured left delimiter. The tilde alternative
        // needs one — with no boundary before `~`, every `HEAD~1` in a pasted
        // git command became `HEAD<path>` — and this engine has no lookaround,
        // so the delimiter is captured and put back rather than looked past.
        out = home_path_re().replace_all(&out, "${1}<path>").to_string();
        if let Some(user) = &self.user {
            // Case-insensitive: logs and macOS paths preserve display case, so
            // `ATTACKER` and `Attacker` walked straight past a plain replace.
            let cased =
                Regex::new(&format!(r"(?i){}", regex::escape(user))).expect("escaped user pattern");
            out = cased.replace_all(&out, "<user>").to_string();
        }
        out
    }

    /// Parse JSON-lines log text into redacted [`Record`]s.
    ///
    /// Non-JSON lines are **skipped, not guessed at**: a partially understood
    /// line is exactly the case where an unrecognised field could ride along
    /// unredacted.
    #[cfg(feature = "logs")]
    pub fn records(&self, jsonl: &str, source: Option<&str>) -> Vec<Record> {
        jsonl
            .lines()
            .filter_map(|line| self.record(line, source))
            .collect()
    }

    #[cfg(feature = "logs")]
    fn record(&self, line: &str, source: Option<&str>) -> Option<Record> {
        let line = line.trim();
        if !line.starts_with('{') {
            return None;
        }
        let value: serde_json::Value = serde_json::from_str(line).ok()?;
        let object = value.as_object()?;

        // Scrubbed like any other value. These two were pulled straight out
        // of the JSON and rendered verbatim, so a log line could carry a home
        // path, a token or an address in its `timestamp` and have it published
        // untouched — the allowlist protected every field except the two that
        // are always present.
        let timestamp = self.scrub(&first_str(
            object,
            &["timestamp", "ts", "time", "@timestamp"],
        )?);
        let level = self.scrub(
            &first_str(object, &["level", "severity", "lvl"]).unwrap_or_else(|| "INFO".to_string()),
        );

        let mut fields: Vec<(String, String)> = Vec::new();

        // The field name is passed through, which is the whole point: it is the
        // one piece of context that says whether a dotted value is a hostname or
        // a package path, and it is free here because JSONL hands it to us. The
        // same loop existed before and discarded it.
        for name in &self.scrubbed {
            if let Some(raw) = object.get(name).and_then(json_scalar) {
                let scrubbed = self.scrub_value(Some(name), &raw);
                if !scrubbed.is_empty() {
                    fields.push((name.clone(), quote_if_spaced(&scrubbed)));
                }
            }
        }
        for name in &self.allowed {
            if let Some(raw) = object.get(name).and_then(json_scalar) {
                fields.push((
                    name.clone(),
                    quote_if_spaced(&self.scrub_value(Some(name), &raw)),
                ));
            }
        }

        if fields.is_empty() {
            return None;
        }

        Some(Record {
            timestamp,
            level: level.to_uppercase(),
            source: source.map(str::to_string),
            fields,
        })
    }
}

/// Render records as a fenced block safe to embed in an issue body.
pub fn render_block(records: &[Record]) -> String {
    let mut out = String::from("```text\n");
    for record in records {
        out.push_str(&record.render());
        out.push('\n');
    }
    out.push_str("```\n");
    out
}

/// Make a value safe to place inside a fenced markdown block.
///
/// A block is a ```` ```text ```` region, often nested in `<details>`, and each
/// record is ONE line. A value carrying a fence, a closing `</details>`, or a
/// newline would break out of both containers and land as live markdown in a
/// public issue. GitHub strips `<script>` but renders `<img src=x onerror=…>`,
/// so this is injection, not cosmetics.
///
/// This is a real bug in the wild — the widely used `bugreport` crate formats
/// arbitrary file and command output into a fence with no escaping.
pub fn sanitize_for_block(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\n' | '\r' => out.push('\u{23ce}'),
            // Zero-width and bidi controls can hide the rest of a line from
            // someone reading the preview.
            c if c.is_control() => out.push('\u{fffd}'),
            c => out.push(c),
        }
    }
    out.replace("```", "`\u{200b}`\u{200b}`")
        .replace("~~~", "~\u{200b}~\u{200b}~")
        .replace("</details", "<\u{200b}/details")
        .replace("<summary", "<\u{200b}summary")
}

/// Make a value safe to place in markdown **body text**, outside any fence.
///
/// [`sanitize_for_block`] is enough inside a ```` ```text ```` region, where
/// HTML is inert because the fence makes it literal. Provenance entries have
/// no such fence: they are rendered as `- Label: value` list items, so an
/// `<img src=x onerror=…>` in a value is live HTML the moment the issue is
/// viewed. GitHub strips `<script>` and renders that one.
///
/// So this flattens the value as for a block, then escapes the two characters
/// that let HTML start. Markdown emphasis can still apply and is left alone —
/// it is cosmetic, and escaping every metacharacter would make an environment
/// block unreadable for no security gain.
///
/// Not idempotent: `&` becomes `&amp;`, so apply it exactly once, at render.
pub fn sanitize_inline(value: &str) -> String {
    sanitize_for_block(value)
        .replace('&', "&amp;")
        .replace('<', "&lt;")
}

/// Cap a value so one pathological record cannot eat the whole issue body.
/// GitHub rejects bodies over 65 535 characters.
pub fn cap(value: &str) -> String {
    if value.chars().count() <= MAX_VALUE_CHARS {
        return value.to_string();
    }
    let kept: String = value.chars().take(MAX_VALUE_CHARS).collect();
    format!("{kept}…[truncated]")
}

/// Only reachable from the JSONL record path today, but it is the shared
/// "make a value safe to render" step, so it stays next to its siblings rather
/// than moving behind the feature gate.
#[cfg_attr(not(feature = "logs"), allow(dead_code))]
fn quote_if_spaced(value: &str) -> String {
    let value = sanitize_for_block(&cap(value));
    if value.contains(char::is_whitespace) {
        format!("\"{value}\"")
    } else {
        value
    }
}

#[cfg(feature = "logs")]
fn first_str(
    object: &serde_json::Map<String, serde_json::Value>,
    names: &[&str],
) -> Option<String> {
    names
        .iter()
        .find_map(|name| object.get(*name).and_then(|v| v.as_str()))
        .map(str::to_string)
}

#[cfg(feature = "logs")]
fn json_scalar(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(text) => Some(text.clone()),
        serde_json::Value::Number(number) => Some(number.to_string()),
        serde_json::Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

/// Hosts that are diagnostic rather than identifying.
const DEFAULT_PUBLIC_HOSTS: &[&str] = &[
    "api.github.com",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
    "index.crates.io",
    "static.crates.io",
];

fn first_env(names: &[&str]) -> Option<String> {
    names
        .iter()
        .find_map(|name| std::env::var(name).ok())
        .filter(|value| !value.is_empty())
}

#[cfg(unix)]
fn passwd_home() -> Option<String> {
    passwd_field(|entry| entry.pw_dir)
}

#[cfg(unix)]
fn passwd_name() -> Option<String> {
    passwd_field(|entry| entry.pw_name)
}

/// The one `unsafe` block in the crate, which is why the workspace policy sets
/// `unsafe_code = "deny"` rather than `forbid`: banned everywhere, allowed here,
/// with the argument written down beside it.
#[allow(unsafe_code)]
#[cfg(unix)]
fn passwd_field(select: fn(&libc::passwd) -> *mut libc::c_char) -> Option<String> {
    // SAFETY: getpwuid returns a pointer into a static buffer owned by libc, or
    // null. The value is copied into an owned String before returning, so the
    // borrow does not outlive the call.
    unsafe {
        let entry = libc::getpwuid(libc::getuid());
        if entry.is_null() {
            return None;
        }
        let field = select(&*entry);
        if field.is_null() {
            return None;
        }
        std::ffi::CStr::from_ptr(field)
            .to_str()
            .ok()
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    }
}

#[cfg(not(unix))]
fn passwd_home() -> Option<String> {
    None
}

#[cfg(not(unix))]
fn passwd_name() -> Option<String> {
    None
}

fn git_remote_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            // `(?i)`: a scheme is case-insensitive per RFC 3986, and `HTTPS://`
            // is what a Windows shell and a good many log formatters emit. The
            // rule was case-sensitive, so shifting two characters defeated it.
            r"(?ix)
              \bgit@[A-Za-z0-9._\-]+:[^\s\x22]+
            | \bssh://[^\s\x22]+
            # A named forge, with or without `.git`. Requiring the suffix meant
            # the rule missed the form git itself prints — `fatal: repository
            # 'https://github.com/acme/prod-vault/' not found` — and every URL
            # a human pastes from a browser. The path is consumed to the end so
            # `/pull/42` and `/-/tree/main` cannot leave a tail behind.
            # The path class excludes `),;` so the rule cannot eat the
            # punctuation after a URL and then the diagnosis that follows it.
            | \bhttps?://(?:www\.)?(?:github|gitlab|bitbucket|codeberg)\.[a-z]+/[^\s\x22),;]*
            # sourcehut is its own alternative because its host IS `sr.ht`:
            # folded into the list above it required `sr.ht.<something>/`, which
            # is not a host, so the branch could never match and every real
            # sourcehut URL published its org and repository.
            | \bhttps?://(?:git\.|hg\.)?sr\.ht/[^\s\x22),;]*
            # Any other host, still requiring `.git`: without a known forge
            # there is nothing to distinguish a repository URL from an ordinary
            # link, and masking every URL in a log would take the diagnosis
            # with it.
            | \bhttps?://[A-Za-z0-9._\-]+/[A-Za-z0-9._\-]+/[A-Za-z0-9._\-]+\.git
            ",
        )
        .expect("static git-remote pattern")
    })
}

fn secret_token_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?x)
              gh[pousr]_[A-Za-z0-9]{16,}
            | github_pat_[A-Za-z0-9_]{20,}
            # Stripe and friends separate with `_`, not `-`; requiring the dash
            # let every `sk_live_…` through.
            | [sr]k_(?:live|test)_[A-Za-z0-9]{16,}
            | sk-[A-Za-z0-9_\-]{20,}
            | xox[baprs]-[A-Za-z0-9\-]{10,}
            # Slack's app-level token (Socket Mode) is not an `xox` at all.
            | xapp-[0-9]-[A-Za-z0-9\-]{10,}
            # Google API keys — Firebase, Maps, Places, Cloud. A fixed prefix
            # and a fixed length, and it was not in the list.
            | AIza[0-9A-Za-z_\-]{35}
            # Telegram bot tokens: `<bot id>:AA<secret>`. The `AA` prefix is
            # what keeps this from matching an ordinary `id:value` pair.
            | \b[0-9]{6,12}:AA[A-Za-z0-9_\-]{30,}
            # Discord and Firebase custom tokens: three base64url segments,
            # like a JWT but without the `eyJ` header that the rule below
            # anchors on.
            | \b[MNO][A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{5,8}\.[A-Za-z0-9_\-]{25,}
            # The whole AWS key-id family, not just long-lived user keys. ASIA
            # (STS session) is the one a compromised CI actually leaks.
            | (?:AKIA|ASIA|AIDA|AROA|AGPA|AIPA|ANPA|ANVA|APKA)[0-9A-Z]{16}
            # Private key material: mask the armour, since the base64 body that
            # follows is on its own lines and matches nothing else here.
            # The space is ESCAPED. `(?x)` strips whitespace inside a character
            # class too, not only between tokens, so `[A-Z ]*` compiled as
            # `[A-Z]*` and this rule required `-----BEGINPRIVATE KEY-----`.
            # It matched no armour any tool has ever emitted.
            | -----BEGIN[A-Z\ ]*PRIVATE\ KEY-----
            | eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}
            ",
        )
        .expect("static secret-token pattern")
    })
}

fn labeled_secret_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // The label is frequently a SUFFIX of a longer identifier:
        // `refresh_token`, `access_token`, `client_secret`, `github_token`.
        // `\b` does not help there — `_` is a word character, so there is no
        // boundary before `token` and a `\btoken\b` rule never fires.
        Regex::new(
            r#"(?ix)
              # `Bearer <token>` / `Basic <base64>`: separated by a SPACE, so
              # the `[=:]` form below never fired and the token rode along in
              # the clear behind a masked `Authorization=`.
              (^|[^A-Za-z0-9])((?:bearer|basic))\s+[A-Za-z0-9._\-+/=]{8,}
              # The leading delimiter is CAPTURED, not consumed. Swallowing it
              # ran words together and, worse, ate newlines — joining a secret's
              # line to the one before it and hiding where it came from.
              #
              # The optional quotes around the separator are what let a secret
              # inside a JSON payload match: `{"token":"value"}` puts a `"`
              # between the label and the colon, and `err`/`message` fields
              # routinely carry JSON from downstream services.
            | (^|[^A-Za-z0-9])
              (\w*(?:
                  authorization|bearer|token|password|passwd|pwd|passphrase
                | secret|credentials?|cookie|auth
                | session(?:[-_]?id)?
                | api[-_]?key|access[-_]?key|private[-_]?key
              ))
              # The trailing quote is NOT consumed here: the quoted-value
              # alternative below has to see it, or `password="hunter 2"`
              # matches only `hunter` and publishes ` 2"`.
              "?\s*[=:]\s*
              (?:"[^"]*"|'[^']*'|(?:bearer|basic)\s+\S+|[^\s"',;]+)
            "#,
        )
        .expect("static labeled-secret pattern")
    })
}

fn email_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
            .expect("static email pattern")
    })
}

fn ssh_target_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b[A-Za-z0-9._\-]+@[A-Za-z0-9.\-]+\b").expect("static ssh-target pattern")
    })
}

fn ipv6_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Delimited on both sides. Without that, the compressed alternative
        // matched `d::c` inside `std::collections::HashMap`, so every Rust log
        // line and backtrace came out corrupted mid-word. The engine has no
        // lookaround, so the delimiters are captured and restored.
        Regex::new(
            r"(?x)
              (^|[^0-9A-Za-z_:.])
              (
                (?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}
              | (?:[0-9A-Fa-f]{1,4}:)+:(?:[0-9A-Fa-f]{1,4}:?)*[0-9A-Fa-f]{0,4}
              | ::(?:[0-9A-Fa-f]{1,4}:)*[0-9A-Fa-f]{1,4}
              )
              (?:%[A-Za-z0-9]+)?
              ($|[^0-9A-Za-z_:.])
            ",
        )
        .expect("static ipv6 pattern")
    })
}

fn ipv4_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b",
        )
        .expect("static ipv4 pattern")
    })
}

/// Hardware addresses, which name the machine rather than the network.
///
/// Colon-form MACs were already masked, but only by accident: they collide
/// with the IPv6 rule. Dash-form had nothing at all, and it is the form
/// Windows, `ip link` and most driver logs print.
fn mac_address_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            // The delimiters are captured and restored, as elsewhere: without
            // a boundary this bites into the middle of a long hex run.
            r"(?xi)
              (^|[^0-9A-Za-z:\-])
              (?:(?:[0-9A-F]{2}-){5}[0-9A-F]{2}|(?:[0-9A-F]{2}:){5}[0-9A-F]{2})
              ($|[^0-9A-Za-z:\-])
            ",
        )
        .expect("static mac pattern")
    })
}

/// An identifier that has been *labelled* as naming the machine.
///
/// A bare UUID is deliberately left alone. Request ids, trace ids and span ids
/// are UUIDs, they are the thread a maintainer follows through a log, and
/// masking them costs the report the one thing that makes it followable. The
/// label is what turns the same bytes into a claim about the hardware.
fn machine_id_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?xi)
              (^|[^A-Za-z0-9_])
              ((?:machine|device|hardware|hw|installation|install|node|host)
                 [-_\ ]?(?:id|uuid|guid)
              | serial(?:[-_\ ]?(?:number|no|num))?
              | udid
              | imei)
              # The separator is CAPTURED and restored, not normalised. It was
              # rewritten to `=` whatever the log actually said, which is the
              # crate editing text it was only asked to redact — in a preview
              # whose whole promise is that it shows what would leave.
              (\s*[:=]?\s*)
              [A-Za-z0-9][A-Za-z0-9._:\-]{5,}
            ",
        )
        .expect("static machine-id pattern")
    })
}

/// Hostnames that identify a network rather than a public service.
///
/// The ssh-target rule only fires when there is a `user@`, and error strings
/// overwhelmingly carry a bare FQDN instead ("Could not resolve hostname
/// bastion.internal.acme.corp").
///
/// Three labels is the floor on purpose, with an alphabetic final label: it
/// keeps `server.log` and `config.yml` intact, and stops version strings like
/// `0.6.8-fork.85ce040` being mistaken for hosts.
/// Suffixes that make a dotted run a hostname rather than an identifier.
///
/// Deliberately not exhaustive, and deliberately short of the "new gTLD"
/// space. `app`, `dev`, `cloud`, `tech`, `systems`, `network`, `email`, `blog`
/// and their neighbours are all real suffixes AND all common final segments of
/// module paths, bundle ids and filenames — `com.example.app`,
/// `config.yml.dev`, `some.package.name.systems`. Including them cost every
/// mobile crash log its bundle id, which is the first thing a maintainer looks
/// for.
///
/// `rs`, `sh`, `pl`, `md` and `so` are out for the same reason: they are file
/// extensions far more often than they are Serbia, and `webpack.config.prod.js`
/// must survive.
///
/// The trade is that a host on a suffix outside this list is not matched by
/// *this* rule. The private-suffix rule, `user@host` and the git-remote rule
/// are what cover the shapes that carry a name in practice.
const HOST_SUFFIXES: &[&str] = &[
    "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "name", "pro", "coop", "aero",
    "io", "co", "ai", "xyz", "eu", "us", "uk", "de", "fr", "jp", "cn", "ru", "br", "in", "au",
    "ca", "ch", "nl", "se", "no", "fi", "dk", "es", "it", "be", "at", "cz", "pt", "gr", "hu", "ro",
    "tr", "ua", "kr", "tw", "hk", "sg", "nz", "za", "mx", "ar", "cl", "ie", "il", "lt", "lv", "ee",
    "sk", "si", "hr", "bg", "by", "kz", "th", "vn", "ph", "id", "my",
];

/// Suffixes that name a private network outright, wherever they appear.
///
/// A match containing one of these is masked without further argument: nothing
/// legitimate is called `bastion.internal.acme.corp`.
const PRIVATE_SUFFIXES: &[&str] = &[
    "corp", "internal", "intranet", "local", "lan", "home", "priv", "private", "arpa",
];

/// Hostnames that identify a network rather than a public service.
///
/// The ssh-target rule only fires when there is a `user@`, and error strings
/// overwhelmingly carry a bare FQDN instead ("Could not resolve hostname
/// bastion.internal.acme.corp").
///
/// The pattern is built from [`HOST_SUFFIXES`] and [`PRIVATE_SUFFIXES`] rather
/// than restating them, so the regex and the guards in [`mask_hosts`] cannot
/// drift apart — which is the failure that would quietly turn the guards off.
fn private_host_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let private = PRIVATE_SUFFIXES.join("|");
        let public = HOST_SUFFIXES.join("|");
        Regex::new(&format!(
            r"(?xi)
              # A private suffix, plus anything after it. The trailing group is
              # what stops the rule biting off `bastion.corp` and publishing
              # `acme-inc.com` — the interesting half of the name.
              [A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]+)*
              \.(?:{private})
              (?:\.[A-Za-z0-9_\-]+)*\b
            # Three or more labels under a real suffix, and case-sensitive:
            # a capitalised label means a class name, and case-insensitivity
            # ate `java.lang.Thread.run`.
            | (?-i:
                [a-z0-9_\-]+(?:\.[a-z0-9_\-]+){{1,}}\.(?:{public})
              )\b
            "
        ))
        .expect("static private-host pattern")
    })
}

/// Suffixes that are two labels wearing one job.
///
/// `co.uk` is a single public suffix. Counting it as two labels made
/// `module.co.uk` look like a three-label FQDN when it is a bare registrable
/// domain with nothing in front of it. A hand-written slice rather than the
/// public suffix list: this crate depends on `regex` and nothing else, and the
/// handful below covers the compound suffixes that actually appear.
const COMPOUND_SUFFIXES: &[&str] = &[
    "co.uk", "ac.uk", "org.uk", "gov.uk", "co.jp", "ne.jp", "or.jp", "com.au", "net.au", "com.br",
    "co.nz", "co.za", "co.in", "com.cn", "com.mx", "com.tr",
];

/// Suffixes a reverse-DNS identifier actually begins with.
///
/// Every two-letter ccTLD is a public suffix, so testing "the first label is a
/// suffix" excused `us.internal.acme.com` — a corporate host, published whole.
/// The roots an Android, Java or Apple identifier really starts with are a
/// much smaller set, and none of them is two letters.
///
/// A reverse-DNS name under a ccTLD (`uk.co.example.app`) is therefore masked.
/// That is the trade, and it runs the safe way: a mangled package path costs a
/// round trip, a published hostname does not come back.
const REVERSE_DNS_ROOTS: &[&str] = &["com", "org", "net", "edu", "gov", "mil", "int", "io", "dev"];

/// The one private suffix that is also a real filename extension:
/// `.env.local`, `settings.local`, `config.local`.
///
/// Only this one gets the two-label relaxation, and the list is deliberately
/// as short as the evidence supports. Every entry here is a hole — `X.local`
/// at two labels is kept unless `X` looks like a machine — so `private` was
/// removed once it became clear that `keys.private` is a contrivance while
/// `.env.local` is in every project. There is no `settings.corp` either:
/// relaxing the private suffixes uniformly leaked `bastion.corp` and
/// `vault.internal`, which are exactly the names the rule exists for.
const WORDLIKE_PRIVATE_SUFFIXES: &[&str] = &["local"];

/// Whether a label looks like it names a machine rather than a word.
///
/// A digit or a hyphen is the cheapest positive signal there is: `db01`,
/// `web-3`, `ip-10-0-1-5`, `alices-macbook` all carry one, and `env`,
/// `settings`, `keys`, `config` do not. It is what lets a two-label
/// `X.local` be judged at all — and it is not an accident that the names
/// which actually identify a person are the ones macOS and DHCP generate with
/// hyphens in them.
fn looks_like_a_machine(label: &str) -> bool {
    label.contains('-') || label.bytes().any(|b| b.is_ascii_digit())
}

/// Field names whose value is a hostname by contract.
///
/// The decisive signal, and it is already in the crate: the JSONL path knows a
/// value came from a field called `host` or `upstream`, which is a statement
/// about the value's meaning rather than a guess from its shape. Nothing else
/// belongs in a field with one of these names — a `host` field holding
/// `django.contrib.auth.models` is a mislabelled log, and a masked one is the
/// right answer to that.
///
/// Matched case-insensitively and as a **suffix of a dotted path**, so
/// `net.peer.address` and `db_host` are caught. A bare `contains` would also
/// catch `ghost` and `hostname_suffix`, which are not hostnames — the cost of a
/// false positive here is one mangled field, and the cost of a false negative
/// is a published internal name, so the bias is deliberate but the match is
/// still anchored.
const HOST_FIELD_NAMES: &[&str] = &[
    // The core set #5 names.
    "host",
    "hostname",
    "remote",
    "peer",
    "addr",
    "endpoint",
    "server",
    "upstream",
    // Shapes that appear in the same contract position and mean the same thing.
    "address",
    "destination",
    "target",
    "origin",
    "node",
    "instance",
    "authority",
    "upstream_addr",
    "remote_addr",
];

/// Whether a field name says its value is a network name.
///
/// Empty is not a host field: an absent name carries no information, and
/// treating `Some("")` as one would invent a certainty the caller did not give.
///
/// Matched on a `.` or `_` boundary, so `net.peer.address` and `db_host` both
/// reach `address` and `host`. A bare `contains` would also swallow `ghost` and
/// `hostname_suffix`, which name no network at all — the cost of a false
/// positive here is one mangled field, and the cost of a false negative is a
/// published internal name, so the bias is deliberate but the match is still
/// anchored.
///
/// Note this governs how a value is scrubbed, not whether it is carried. A
/// field is retained by exact name from the allowlist, so `peer_addr` is dropped
/// before this ever runs unless a caller has added it — the boundary is
/// deliberate, since an unlisted field is a field nobody has decided to publish.
fn is_host_field(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    HOST_FIELD_NAMES.iter().any(|candidate| {
        lower == *candidate
            || lower.ends_with(&format!(".{candidate}"))
            || lower.ends_with(&format!("_{candidate}"))
    })
}

/// A dotted run that is a name, for the field-aware rule.
///
/// **A dot is not required.** The first draft of this required one, reasoning
/// that a single label carries no domain to disclose — and the end-to-end canary
/// caught it immediately, because `host=cache01` and `peer=frontend` are exactly
/// the values these fields exist to carry. A single label in a field called
/// `host` is the machine's own name, which is the most identifying thing in the
/// line, not the least.
///
/// The trade it introduces is real and narrow: `host=localhost` becomes
/// `<host>`. That is a loss of a useful word, and it is taken deliberately,
/// because the alternative is a rule that publishes the name whenever the name
/// happens to be one label long — and a name that is one label long is the
/// common case for a container, a service, or a developer's laptop.
///
/// A consumer who wants `localhost` kept has `keep_hosts` for it, and the
/// preservation happens around this rule rather than through it.
fn host_field_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?x)
              [A-Za-z0-9_](?:[A-Za-z0-9_\-]*[A-Za-z0-9_])?
              (?:\.[A-Za-z0-9_](?:[A-Za-z0-9_\-]*[A-Za-z0-9_])?)*
              (?::\d{1,5})?
            ",
        )
        .expect("static host-field pattern")
    })
}

/// Mask every name in a value that arrived in a host field.
///
/// See [`Redactor::scrub_value`] for why this is separate from [`mask_hosts`]
/// and can be more aggressive than it.
///
/// The boundaries are checked in the callback rather than the pattern, because
/// there is no look-around to spend. Both are the same test: a match that is
/// flush against a character which could be part of a longer name is a fragment
/// of that name, and masking the fragment would publish the rest — masking
/// `bastion` out of `bastion.corp.acme.com` and leaving `corp.acme.com` is
/// worse than useless, because that is the half that names the organisation.
fn mask_names_in_host_field(value: &str) -> String {
    // Markers this crate has already produced, protected from a second pass.
    //
    // Done by splitting on them rather than by testing the match, because the
    // match cannot be tested: `<host>` is four bare words to a pattern that
    // accepts bare words, and its `<` and `>` are word boundaries, so a callback
    // guard on the surrounding text does not fire. Splitting also makes the
    // idempotence structural instead of a check that has to be re-derived every
    // time the pattern changes.
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    // The markers `scrub_common` can emit. `keep_hosts` swaps in a token of its
    // own and restores it afterwards, so it is handled by the caller instead.
    const MARKERS: &[&str] = &["<host>", "<ip>", "<ssh-target>", "<git-remote>"];

    loop {
        // The earliest marker wins, so a value carrying two of them is handled
        // in one pass rather than needing a loop per marker.
        let next = MARKERS
            .iter()
            .filter_map(|marker| rest.find(marker).map(|at| (at, *marker)))
            .min_by_key(|(at, _)| *at);
        let Some((at, marker)) = next else {
            out.push_str(&mask_names_in_host_field_run(rest));
            return out;
        };
        out.push_str(&mask_names_in_host_field_run(&rest[..at]));
        out.push_str(marker);
        rest = &rest[at + marker.len()..];
        if rest.is_empty() {
            return out;
        }
    }
}

/// Mask the runs in a stretch of text that contains no markers.
fn mask_names_in_host_field_run(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    host_field_re()
        .replace_all(value, |caps: &regex::Captures<'_>| {
            let Some(matched) = caps.get(0) else {
                return String::new();
            };
            // The boundaries are checked here rather than in the pattern because
            // there is no look-around to spend.
            //
            // `:` counts as a continuation on BOTH sides. The general rules run
            // first and have already masked the name, so what reaches this pass
            // is `<host>:5432`; without it, the run starting after the colon is
            // masked as a port in its own right and the value comes out
            // `<host>:<host>`, which reads as two things rather than one. The
            // port identifies the service, which is the half of that value a
            // maintainer actually needs.
            //
            // NUL blocks a match outright. It cannot occur in input —
            // `sanitize_for_block` replaces control characters long before here
            // — so it is only ever the delimiter of a `keep_hosts` token, and
            // that name must not be masked. It has to be an explicit check: a
            // token like `\0 0 \0` contains the bare word `0`, which this pattern
            // matches, and without this the kept name came back as `\0<host>\0`.
            let before = value
                .get(..matched.start())
                .and_then(|b| b.chars().next_back());
            let after = value.get(matched.end()..).and_then(|a| a.chars().next());
            if before == Some('\u{0}') || after == Some('\u{0}') {
                return matched.as_str().to_string();
            }
            let continues_left = before
                .is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':'));
            let continues_right = after
                .is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':'));

            if continues_left || continues_right {
                matched.as_str().to_string()
            } else {
                "<host>".to_string()
            }
        })
        .to_string()
}

/// A name in host position, after an anchor that settles it.
///
/// The second half of #5's hybrid, and the signal free text actually offers. A
/// hostname and a reverse-DNS package are the same string in opposite orders,
/// so shape cannot separate them — but **position** can: a name after `resolve `
/// or inside `host=` is a name, whatever it looks like, because nothing else
/// goes there. That is a statement about the sentence rather than a prior tuned
/// against a corpus, which is what lets this rule be certain where
/// [`mask_hosts`] has to guess.
///
/// It also covers a shape no rule in this file could reach before: a
/// **single-label** name. `resolve bastion` publishes the machine's own name and
/// leaked under every shape-based rule, because there is no dot to build a
/// dotted run out of. Position is the only thing that identifies those.
///
/// The anchors here are the ones that settle the question by themselves —
/// a resolver naming what it could not find, a connection naming its target, a
/// `key=` form a structured logger emits. Tool verbs are in
/// [`anchored_machine_re`] instead, because they need more evidence; see there
/// for why.
///
/// **Locale-specific, and stated rather than hidden.** These are English and
/// configuration conventions. `Could not resolve` is one resolver's wording; a
/// message in another language, or from a library that phrases it differently,
/// gets no help from this rule. A guarantee that quietly depends on the
/// reporter's locale is not a guarantee, so the limitation belongs in the docs
/// rather than in a test that would only ever assert the English case.
fn mask_anchored_hosts(value: &str) -> String {
    anchored_host_re()
        .replace_all(value, "${1}${2}<host>")
        .to_string()
}

/// A name in host position, after a tool verb — which needs more evidence.
///
/// `curl`, `ssh` and `ping` take a host as their first argument, but they also
/// appear in ordinary sentences: `curl the page`, `ssh the gateway`, `ping the
/// printer`. An anchor that settles the question on its own is no use there, so
/// the token must additionally carry one of the three things that make it a
/// machine name — a dot, a digit, or a hyphen.
///
/// `curl web-01.acme.com` and `ssh db-01.internal` are caught; `curl the page` is
/// left alone.
///
/// **`dial` is not one of these.** It is a connection verb, not a tool, and
/// belongs with the anchors that settle it: `dial redis` is a real leak of a
/// real service name, and there is no ordinary English reading of it — the false
/// positive it costs (`dial tone`, in a phone-system error message) is rarer
/// than the leak it prevents. That asymmetry is the whole reason the two rules
/// are separate rather than one rule with a shape test.
///
/// No look-around, as everywhere in this file. The left boundary is *consumed*
/// and restored in group 1 rather than looked past, which is what stops
/// `presolve` from anchoring, and the right boundary is asserted in the callback
/// because a pattern cannot.
///
/// A dotted run is **one** name and is masked whole: `resolve bastion.corp.acme-inc`
/// has to become `resolve <host>`, not `resolve<host>.corp.acme-inc`. Nibbling
/// the first label off and leaving the tail is worse than no rule at all, because
/// the tail is the part that names the organisation — the failure this file
/// already records once, for a fragment-of-a-longer-run match.
fn mask_anchored_machines(value: &str) -> String {
    anchored_machine_re()
        .replace_all(value, |caps: &regex::Captures<'_>| {
            let Some(matched) = caps.get(0) else {
                return String::new();
            };
            let whole = matched.as_str();
            // A flush continuation means this is a fragment of a longer token,
            // and masking the fragment would publish the rest.
            let continues = value
                .get(matched.end()..)
                .and_then(|rest| rest.chars().next())
                .is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
            // The shape test. `curl the page` is English; `curl web-01.acme.com`
            // is a diagnostic. See `anchored_machine_re` for why this is not a
            // look-ahead in the pattern.
            let name = caps.name("name").map(|m| m.as_str()).unwrap_or_default();
            if continues || !looks_like_a_machine_name(name) {
                whole.to_string()
            } else {
                // Restore the consumed boundary character, then the masked name.
                let boundary = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
                format!("{boundary}<host>")
            }
        })
        .to_string()
}

/// Anchors that settle it: resolution, connection, and `key=` forms.
///
/// Group 1 is the boundary in front of the anchor and group 2 is the anchor
/// itself; both are restored on substitution, so the sentence keeps its verb
/// (`Could not resolve <host>`) and a structured field keeps its key
/// (`host=<host>`). Losing the key would leave a maintainer reading a bare
/// `<host>` with nothing saying what it was.
///
/// The trailing `\b` on each alternative is what keeps `presolve`, `resolver` and
/// `resolve()` from anchoring — `resolve()` is a call in a stack trace, and that
/// is the one line in a bug report a maintainer most wants intact.
fn anchored_host_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?xi)
              (^|[^A-Za-z0-9_])
              # The trailing whitespace is INSIDE group 2 so it is restored with
              # the anchor. Outside it, `resolve bastion` became
              # `resolve<host>` — the crate editing text it was only asked to
              # redact, in a preview whose whole promise is that it shows what
              # would leave.
              (
                \b(?:could\s+not\s+)?resolv(?:e|ed|ing)\b\s+
              | \bconnect(?:ing|ed)?\s+to\s+
              | \bdial(?:l?ing|led)?\s+
              | \b(?:host|hostname|addr|address|peer|remote|server|upstream
                    |endpoint|origin|node|destination|target)\s*[=:]\s*
              )
              (?P<name>[A-Za-z0-9_](?:[A-Za-z0-9_\-]*[A-Za-z0-9_])?
                (?:\.[A-Za-z0-9_](?:[A-Za-z0-9_\-]*[A-Za-z0-9_])?)*)
              (?::\d{1,5})?
            ",
        )
        .expect("static anchored-host pattern")
    })
}

/// Tool verbs, which need the token to look like a machine name as well.
///
/// The shape requirement is checked in the callback rather than the pattern,
/// because "at least one of `.`, `-` or a digit appears somewhere in this run"
/// is not expressible without a look-ahead, and this engine has none. The
/// pattern takes any run and the callback decides.
fn anchored_machine_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?xi)
              (^|[^A-Za-z0-9_])
              \b(?:curl|wget|ping|nc|ssh|scp|rsync|dig|nslookup|telnet|smtp|proxy)\b\s+
              (?P<name>[A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]+)*(?::\d{1,5})?)
            ",
        )
        .expect("static anchored-machine pattern")
    })
}

/// Whether a run carries one of the three things that make it a machine name.
///
/// A dot, a hyphen, or a digit. `the`, `page` and `tone` have none and are left
/// alone; `web-01`, `10.0.0.5` and `acme-inc` each have one and are masked.
fn looks_like_a_machine_name(run: &str) -> bool {
    run.contains('.') || run.contains('-') || run.bytes().any(|b| b.is_ascii_digit())
}

/// Apply [`private_host_re`], with the guards a regex cannot express.
///
/// The pattern is deliberately loose; every real decision is made here, with
/// the match in hand. A hostname and a reverse-DNS identifier are the same
/// string in opposite orders, and no amount of alternation settles that.
///
/// - **A suffix is only a suffix at the END.** `internal` and `corp` are a
///   Kotlin visibility keyword and a routine Java package segment, so matching
///   them anywhere destroyed every stack frame that contained one.
/// - **A hostname ENDS with its suffix; an identifier BEGINS with one.**
///   `bastion.corp.acme.com` against `com.example.app`.
/// - **A hostname is not a prefix of a longer dotted run.** `std.foo.io`
///   inside `std.foo.io.println` matched, and `<host>.println` says less than
///   either half did.
/// - **Two labels is not enough on its own.** `local`, `home` and `private`
///   are English words, and `.env.local` is in every Vite, Next and Django
///   project there is. At two labels the name has to look like a machine.
fn mask_hosts(text: &str) -> String {
    private_host_re()
        .replace_all(text, |caps: &regex::Captures<'_>| {
            let Some(matched) = caps.get(0) else {
                return String::new();
            };
            let found = matched.as_str();
            let labels: Vec<&str> = found.split('.').collect();
            let keep = || found.to_string();
            let mask = || "<host>".to_string();

            let is = |label: &str, set: &[&str]| set.iter().any(|s| label.eq_ignore_ascii_case(s));
            let Some(last) = labels.last() else {
                return keep();
            };

            // A match that stops immediately before a `-` is a FRAGMENT of a
            // longer token, not a name. The pattern's trailing group needs a
            // `.` to continue, so `com.acme.internal-tools.util.Client` matched
            // only `com.acme.internal` and was judged as if that were the whole
            // thing — masking the front of an ordinary package path.
            if text
                .get(matched.end()..)
                .is_some_and(|rest| rest.starts_with('-'))
            {
                return keep();
            }

            // The order below IS the rule. Each of the three preceding rounds
            // on this function got it wrong by testing the right things in the
            // wrong sequence.
            //
            // 1. A private suffix at the END settles it: `int.acme.corp` is a
            //    host whatever it begins with. Checking the reverse-DNS escape
            //    first gave a free pass to any host whose first label happened
            //    to be a TLD.
            if is(last, PRIVATE_SUFFIXES) {
                // Two labels is enough unless the suffix is also a word, in
                // which case the name has to look like a machine — see
                // `WORDLIKE_PRIVATE_SUFFIXES`.
                let relaxable = is(last, WORDLIKE_PRIVATE_SUFFIXES) && labels.len() <= 2;
                return if !relaxable || labels.first().is_some_and(|l| looks_like_a_machine(l)) {
                    mask()
                } else {
                    keep()
                };
            }

            // 2. A CamelCase LAST label is a class name, so the run is a
            //    package path. "Contains an uppercase letter anywhere" was
            //    standing in for this and is not the same test: Windows and AD
            //    hostnames are routinely capitalised, so it switched the rule
            //    off on exactly the hosts it exists for.
            //
            //    CamelCase, not merely a leading capital — `.COM` and `.NET`
            //    start with one too, and an operator who shouts the TLD is not
            //    writing Java. A class name has a lowercase letter after it.
            //    And a label that IS a suffix is a suffix however it is
            //    cased. `Com` is CamelCase by shape and a TLD by meaning.
            let camel_case = last.starts_with(|c: char| c.is_ascii_uppercase())
                && last.chars().any(|c| c.is_ascii_lowercase())
                && !is(last, HOST_SUFFIXES)
                && !is(last, PRIVATE_SUFFIXES);
            if camel_case {
                return keep();
            }

            // 3. A private label MID-RUN, in a run that ends in neither a
            //    private nor a public suffix: `bastion.corp.acme-inc`, an
            //    internal root with no public TLD. Requiring a known final
            //    label let every one of those through.
            //
            //    The exception is a genuine reverse-DNS package —
            //    `com.acme.internal.util` — which begins with a suffix and
            //    contains no label shaped like a machine. A hyphen or a digit
            //    in there means `io.corp.acme-inc`, not `io.netty.internal`.
            if labels.iter().any(|label| is(label, PRIVATE_SUFFIXES)) {
                let reverse_dns = labels
                    .first()
                    .is_some_and(|first| is(first, REVERSE_DNS_ROOTS))
                    && !labels.iter().any(|label| looks_like_a_machine(label));
                return if reverse_dns { keep() } else { mask() };
            }

            // 4. A reverse-DNS identifier begins with the suffix a hostname
            //    ends with: `com.example.app` against `bastion.corp.acme.com`.
            if labels
                .first()
                .is_some_and(|first| is(first, REVERSE_DNS_ROOTS))
            {
                return keep();
            }

            // Otherwise it has to end in a public suffix to be a host at all.
            // The pattern's private alternative can match a run whose last
            // label is neither — `com.foo.internal.Impl` — and that is a
            // package path.
            let compound = labels
                .len()
                .checked_sub(2)
                .and_then(|at| labels.get(at))
                .is_some_and(|penultimate| {
                    let pair = format!("{penultimate}.{last}");
                    COMPOUND_SUFFIXES
                        .iter()
                        .any(|s| pair.eq_ignore_ascii_case(s))
                });
            if !compound && !is(last, HOST_SUFFIXES) {
                return keep();
            }

            // A prefix of a longer dotted run is part of that run, not a host.
            let continues = text
                .get(matched.end()..)
                .and_then(|rest| rest.strip_prefix('.'))
                .is_some_and(|rest| {
                    rest.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
                });
            if continues {
                return keep();
            }

            // Subdomains live to the LEFT of the registrable domain, so a bare
            // `<name>.<suffix>` is a domain rather than a host, and two labels
            // in front of a compound suffix is the same shape as three in
            // front of a simple one.
            let suffix_labels = if compound { 2 } else { 1 };
            if labels.len().saturating_sub(suffix_labels) >= 2 {
                mask()
            } else {
                keep()
            }
        })
        .to_string()
}

/// Another account's home directory. The current user's is rewritten to `~`
/// before this runs. Covers Windows profile paths too.
fn home_path_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            // The captured left delimiter, restored by `${1}` in the
            // replacement, applies ONLY to the alternatives that need one:
            // `~name`, which would otherwise eat `HEAD~1`, and the driveless
            // Windows path, which would otherwise match inside `MyUsers\bob`.
            //
            // Requiring it everywhere narrowed the absolute-path alternatives
            // and reintroduced a leak: `prefix/home/alice/x` stopped matching,
            // so any concatenated or prefix-tagged path published the account
            // name. Group 1 simply does not participate in the alternatives
            // below, and `${1}` expands to nothing there.
            r"(?xi)
              (?:
                (?:/Users|/home)/[^\s\x22/]+(?:/[^\s\x22]*)?
              # Root's home is still an account's home, and a path under it says
              # the process ran privileged.
              | /var/root\b(?:/[^\s\x22]*)?
              | /root\b(?:/[^\s\x22]*)?
              # macOS per-user temp: the salt uniquely identifies the user.
              | /private/var/folders/[^\s\x22]*
              | /var/folders/[^\s\x22]*
              # `~alice/.bashrc` names the account without any /home prefix.
              # The first character must be a LETTER: `HEAD~1` and `main~2` are
              # git revisions, and with a digit allowed here every one of them
              # in a pasted command became `<path>`.
              | (^|[^A-Za-z0-9_])~[A-Za-z][A-Za-z0-9._\-]*(?:/[^\s\x22]*)?
              # A UNC path names the file server as well as the account.
              | \\\\[A-Za-z0-9._\-]+\\[^\s\x22]*
              # The drive letter is OPTIONAL. A stack trace prints the path
              # relative to the profile root, and `Users\bob\...` named the
              # account with nothing to stop it.
              | (^|[^A-Za-z0-9_])(?:[A-Z]:)?\\?Users\\[^\\/\s\x22]+(?:\\[^\s\x22]*)?
              | (^|[^A-Za-z0-9_])(?:[A-Z]:)?\\?Documents\ and\ Settings\\[^\\/\s\x22]+(?:\\[^\s\x22]*)?
              )
            ",
        )
        .expect("static home-path pattern")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redactor() -> Redactor {
        Redactor::with_identity(Some("/Users/attacker".into()), Some("attacker".into()))
    }

    #[test]
    fn masks_homes_users_secrets_hosts_and_addresses() {
        let r = redactor();
        assert_eq!(r.scrub("/Users/attacker/secret"), "~/secret");
        assert_eq!(r.scrub("/home/someone/x"), "<path>");
        assert_eq!(r.scrub(r"C:\Users\someone\Desktop"), "<path>");
        assert_eq!(
            r.scrub("ghp_abcdefghijklmnopqrstuvwxyz01"),
            "<redacted-token>"
        );
        assert_eq!(r.scrub("token=hunter2"), "token=<redacted>");
        assert_eq!(r.scrub("10.1.2.3"), "<ip>");
    }

    #[test]
    fn underscored_secret_labels_are_masked() {
        let r = redactor();
        for input in [
            "refresh_token=1//0abcDEFghiJKL",
            "client_secret: s3cr3t",
            "github_token=abcdefghijklmnop",
            "Cookie: session=deadbeefcafe",
        ] {
            assert!(r.scrub(input).contains("<redacted>"), "not masked: {input}");
        }
    }

    #[test]
    fn git_remote_does_not_leak_org_or_repo() {
        let masked = redactor().scrub("cloned git@github.com:acmecorp/prod-vault.git");
        assert!(!masked.contains("acmecorp"), "{masked}");
        assert!(!masked.contains("prod-vault"), "{masked}");
    }

    #[test]
    fn bare_internal_hostnames_and_ipv6_are_masked() {
        let r = redactor();
        let masked = r.scrub("could not resolve bastion.internal.acme.corp");
        assert!(!masked.contains("acme"), "{masked}");
        let masked = r.scrub("connect to [2001:db8:85a3::8a2e:370:7334]:22 refused");
        assert!(!masked.contains("2001:db8"), "{masked}");
    }

    #[test]
    fn works_with_no_environment_identity() {
        // The systemd/launchd case: HOME and USER stripped.
        let bare = Redactor::with_identity(None, None);
        let masked = bare.scrub("spawned for ops@int.acme.corp from /home/someone/x");
        assert!(!masked.contains("acme"), "{masked}");
        assert!(!masked.contains("someone"), "{masked}");
    }

    #[test]
    fn two_character_usernames_are_masked() {
        let masked =
            Redactor::with_identity(Some("/home/al".into()), Some("al".into())).scrub("run by al");
        assert!(!masked.contains(" al"), "{masked}");
    }

    #[test]
    fn debug_never_prints_the_identity() {
        let out = format!("{:?}", redactor());
        assert!(!out.contains("attacker"), "{out}");
        assert!(out.contains("<set>"), "{out}");
    }

    #[test]
    fn diagnostic_text_survives() {
        // Over-masking makes the block useless; these must NOT be touched.
        let r = redactor();
        for keep in [
            "No such file or directory (os error 2)",
            "process exec completed",
            "server.log",
            "0.6.8-fork.85ce040",
            "protocol 24 vs 25",
        ] {
            assert_eq!(r.scrub(keep), keep, "wrongly masked {keep:?}");
        }
    }

    #[test]
    fn public_hosts_survive() {
        let r = redactor();
        assert!(r
            .scrub("GET https://api.github.com/repos")
            .contains("api.github.com"));
    }

    #[test]
    fn values_cannot_escape_a_markdown_fence() {
        let hostile = "boom ```\n</details>\n\n# INJECTED\n<img src=x onerror=alert(1)>";
        let safe = sanitize_for_block(hostile);
        assert!(!safe.contains("```"), "{safe}");
        assert!(!safe.contains("</details"), "{safe}");
        assert_eq!(safe.lines().count(), 1, "{safe}");
    }

    #[test]
    fn oversized_values_are_capped() {
        let capped = cap(&"x".repeat(50_000));
        assert!(capped.chars().count() < 1_100);
        assert!(capped.contains("[truncated]"));
    }

    #[cfg(feature = "logs")]
    mod records {
        use super::*;

        fn rendered(line: &str) -> String {
            redactor()
                .record(line, Some("app.log"))
                .expect("record")
                .render()
        }

        #[test]
        fn keeps_the_diagnostic_fields_and_drops_the_rest() {
            let out = rendered(
                r#"{"timestamp":"t","level":"error","message":"exec failed","event":"process.exec","program":"git","args":"-C /home/someone/private-client remote get-url origin","err":"No such file or directory (os error 2)"}"#,
            );
            assert!(out.contains("program=git"), "{out}");
            assert!(out.contains("event=process.exec"), "{out}");
            assert!(out.contains("No such file or directory"), "{out}");
            // `args` is not on the allowlist — that is where the paths live.
            assert!(!out.contains("args"), "{out}");
            assert!(!out.contains("private-client"), "{out}");
        }

        #[test]
        fn unknown_fields_are_excluded_by_default() {
            let out = rendered(
                r#"{"timestamp":"t","level":"info","message":"m","brand_new_field":"/Users/attacker/secret"}"#,
            );
            assert!(!out.contains("brand_new_field"), "{out}");
            assert!(!out.contains("secret"), "{out}");
        }

        #[test]
        fn accepts_common_timestamp_and_level_spellings() {
            let out = redactor()
                .record(r#"{"ts":"t","severity":"warn","msg":"hi"}"#, None)
                .expect("record");
            assert_eq!(out.level, "WARN");
        }

        #[test]
        fn non_json_lines_are_skipped_not_guessed() {
            assert!(redactor().record("2026-01-01 INFO hello", None).is_none());
            assert!(redactor().record("{\"partial\":", None).is_none());
        }

        #[test]
        fn canary_record_leaks_nothing() {
            let out = rendered(
                r#"{"timestamp":"t","level":"error","message":"install failed for attacker at /Users/attacker/x with ghp_abcdefghijklmnopqrstuvwxyz01","event":"remote.install","dest":"/Users/attacker/.local/bin/app","ssh_opts":"-o ProxyJump=bastion.int.acme.corp","err":"auth failed for ops@int.acme.corp at 10.1.2.3"}"#,
            );
            for forbidden in [
                "attacker",
                "/Users/",
                "ghp_",
                "acme",
                "bastion",
                "10.1.2.3",
                "ProxyJump",
            ] {
                assert!(!out.contains(forbidden), "leaked {forbidden:?} in {out}");
            }
            assert!(out.contains("event=remote.install"), "{out}");
        }
    }

    #[test]
    fn code_shaped_text_is_not_mistaken_for_a_host_or_an_address() {
        // Every string here was destroyed by a redaction fix at some point.
        // Over-masking is not the safe direction: a block scrubbed into
        // uselessness costs the same triage round trip as no block at all.
        let redactor = redactor();
        for intact in [
            // `d::c` inside this matched the compressed-IPv6 rule.
            "std::collections::HashMap",
            "std::io::Error",
            "app::db::conn",
            // Dotted identifiers are not FQDNs.
            "com.example.Main",
            "at java.lang.Thread.run",
            "org.apache.commons.Lang",
            "os.path.join",
            "django.db.models",
            // Filenames with two extensions are not FQDNs either.
            "config.yml.bak",
            "foo.tar.gz",
            "lib.rs.orig",
            // A prefix is not a path.
            "/roots",
            "/rootbeer",
            "/var/rooted",
        ] {
            assert_eq!(
                redactor.scrub(intact),
                intact,
                "{intact:?} must survive the scrubber intact"
            );
        }
    }

    #[test]
    fn an_emoji_joiner_is_not_treated_as_a_hidden_credential() {
        // Invisibles are stripped so a zero-width space cannot split a token,
        // but U+200D between emoji is a grapheme joiner: removing it turns one
        // glyph into three.
        let redactor = redactor();
        let family = "\u{1f469}\u{200d}\u{1f52c} ran the job";
        assert_eq!(redactor.scrub(family), family);
    }

    #[test]
    fn compressed_ipv6_is_still_masked_after_the_boundary_fix() {
        let redactor = redactor();
        for (input, expected) in [
            ("peer fe80::1 down", "peer <ip> down"),
            ("peer 2001::abcd down", "peer <ip> down"),
            ("listening on ::1", "listening on <ip>"),
        ] {
            assert_eq!(redactor.scrub(input), expected, "{input:?}");
        }
    }

    /// Assert that nothing recognisable from `secret` survives.
    ///
    /// Comparing against an exact expected string would pass while the rule
    /// masked only a prefix — which is how the git-remote hole stayed open:
    /// `git@github.com:org/private.git` matched as an email, so the address
    /// went and the org and repository were published in the tail.
    fn assert_gone(redactor: &Redactor, input: &str, secret: &str) {
        let out = redactor.scrub(input);
        assert!(
            !out.contains(secret),
            "{secret:?} survived redaction of {input:?}: {out}"
        );
    }

    #[test]
    fn private_key_armour_is_masked() {
        // `(?x)` strips whitespace INSIDE a character class in this engine, so
        // `[A-Z ]*` compiled as `[A-Z]*` and the rule only ever matched
        // `-----BEGINPRIVATE KEY-----`, which nothing emits. Every real key
        // header went through untouched, and the base64 body after it matches
        // no other rule.
        let redactor = redactor();
        for armour in [
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
        ] {
            assert_gone(&redactor, armour, "PRIVATE KEY");
        }
    }

    #[test]
    fn forge_urls_lose_the_org_and_repository_without_a_dot_git() {
        // The rule required a trailing `.git`, which is the one form a human
        // reading an error message rarely sees. `fatal: repository
        // 'https://github.com/acme/prod-vault/' not found` is what git
        // actually prints, and the private repository name rode out in it.
        let redactor = redactor();
        for input in [
            "See https://github.com/acmecorp/prod-vault",
            "https://github.com/acmecorp/prod-vault/pull/42",
            "https://gitlab.com/acmecorp/prod-vault/-/tree/main",
            "repository 'https://github.com/acmecorp/prod-vault/' not found",
            // Case in the scheme was enough to defeat it even WITH the `.git`.
            "at HTTPS://github.com/acmecorp/prod-vault.git",
        ] {
            assert_gone(&redactor, input, "acmecorp");
            assert_gone(&redactor, input, "prod-vault");
        }
    }

    #[test]
    fn credential_shapes_the_pattern_list_had_missed() {
        let redactor = redactor();
        for (input, secret) in [
            // Firebase / Maps / Cloud. A single very common shape, absent.
            (
                "key AIzaSyD-1234567890abcdefghijklmnopqrstu",
                "AIzaSyD-1234567890abcdefghijklmnopqrstu",
            ),
            // Slack app-level (Socket Mode). Only `xox[baprs]-` was listed.
            (
                "xapp-1-A00000000-1234567890-abcdefabcdefabcdef",
                "xapp-1-A00000000",
            ),
            (
                "bot 123456789:AAG1234567890abcdefghijklmnopqrstuv",
                "AAG1234567890abcdefghijklmnopqrstuv",
            ),
        ] {
            assert_gone(&redactor, input, secret);
        }
    }

    #[test]
    fn windows_and_unc_paths_name_no_account() {
        // The rule required a drive letter. A relative `Users\bob\...` is what
        // a stack trace prints, and a UNC path names both the file server and
        // the account.
        let redactor = redactor();
        assert_gone(&redactor, r"at Users\bob\Documents\Diary.txt", "bob");
        assert_gone(&redactor, r"\\fileserver\share\alice\q.docx", "alice");
        assert_gone(&redactor, r"\\fileserver\share\alice\q.docx", "fileserver");
    }

    #[test]
    fn hardware_addresses_are_masked() {
        let redactor = redactor();
        // Colon-form MACs are already caught, but incidentally — they collide
        // with the IPv6 rule. Dash-form had nothing.
        assert_gone(&redactor, "iface aa-bb-cc-dd-ee-ff up", "aa-bb-cc-dd-ee-ff");
        assert_gone(&redactor, "iface aa:bb:cc:dd:ee:ff up", "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn a_masked_identifier_keeps_the_separator_it_was_written_with() {
        // The rule normalised whatever separator it matched to `=`, so
        // `machine id: <uuid>` came back as `machine id=<machine-id>`. Small,
        // but it is the crate rewriting text it was only asked to redact —
        // and the reporter is being shown a preview of "what would leave".
        let redactor = redactor();
        for (input, expected) in [
            (
                "machine-id: 550e8400-e29b-41d4-a716-446655440000",
                "machine-id: <machine-id>",
            ),
            (
                "device_id=550e8400-e29b-41d4-a716-446655440000",
                "device_id=<machine-id>",
            ),
            ("serial number C02XG2JMJGH8", "serial number <machine-id>"),
        ] {
            assert_eq!(redactor.scrub(input), expected, "{input:?}");
        }
    }

    #[test]
    fn labelled_machine_identifiers_are_masked() {
        // A bare UUID stays: request and trace ids are UUIDs, they are the
        // thread a maintainer follows through a log, and masking them costs
        // the report its correlation. A *labelled* one is a different claim
        // about the same bytes.
        let redactor = redactor();
        for input in [
            "machine-id 550e8400-e29b-41d4-a716-446655440000",
            "device_id=550e8400-e29b-41d4-a716-446655440000",
            "serial number C02XG2JMJGH8",
        ] {
            let out = redactor.scrub(input);
            assert!(
                !out.contains("550e8400") && !out.contains("C02XG2JMJGH8"),
                "{input:?} kept its identifier: {out}"
            );
        }
        let trace = "request 550e8400-e29b-41d4-a716-446655440000 failed";
        assert_eq!(
            redactor.scrub(trace),
            trace,
            "an unlabelled UUID is a correlation id and must survive"
        );
    }

    #[test]
    fn dotted_module_paths_are_not_hostnames() {
        // The four-label rule masked any all-lowercase dotted run ending in
        // letters, which is the exact shape of a Python, Java or Kotlin stack
        // frame. Every Django traceback lost the line that says where the bug
        // is — and a log block scrubbed into uselessness costs the maintainer
        // the same round trip as no log block at all.
        let redactor = redactor();
        for path in [
            "django.contrib.auth.models",
            "django.contrib.auth.models.User.save",
            "org.jetbrains.kotlin.compiler.plugin",
            "boto3.session.session.client",
            "server.log.old.tmp",
            "webpack.config.prod.js",
            "std::collections::HashMap",
            "java.lang.Thread.run",
        ] {
            assert_eq!(redactor.scrub(path), path, "mangled a module path");
        }
    }

    #[test]
    fn real_hostnames_are_still_masked_whole() {
        let redactor = redactor();
        for (input, kept) in [
            ("could not resolve bastion.internal.acme.corp", "acme"),
            // The private-suffix alternative stopped at `corp` and left the
            // rest, so the interesting half of the name was published.
            ("could not resolve bastion.corp.acme-inc.com", "acme-inc"),
            ("could not resolve db01.prod.acme-inc.com", "acme-inc"),
            ("could not resolve db01.prod.acme-inc.co.uk", "acme-inc"),
        ] {
            assert_gone(&redactor, input, kept);
        }
    }

    #[test]
    fn sourcehut_urls_lose_the_org_and_repository() {
        // `(?:github|gitlab|...|sr\.ht)\.[a-z]+/` required a label AFTER the
        // forge name, so the `sr.ht` alternative could only ever match
        // `sr.ht.something/…`, which is not a host. Every real sourcehut URL
        // went through, and the fallback alternative wants a `.git` suffix a
        // browser-copied URL does not have.
        let redactor = redactor();
        for input in [
            "https://sr.ht/orguser/prod-vault",
            "https://git.sr.ht/~orguser/prod-vault",
            "cloning https://git.sr.ht/~orguser/prod-vault failed",
        ] {
            assert_gone(&redactor, input, "orguser");
            assert_gone(&redactor, input, "prod-vault");
        }
    }

    #[test]
    fn a_forge_url_does_not_swallow_the_sentence_after_it() {
        // `[^\s\x22]*` ate trailing punctuation and then the rest of the
        // line, so the diagnosis around the URL disappeared with it.
        let redactor = redactor();
        let out = redactor.scrub("issue at https://github.com/acme/vault/pull/42; then it dies");
        assert!(
            out.contains("then it dies"),
            "the text after the URL was consumed: {out}"
        );
        let out = redactor.scrub("try https://github.com/acme/vault) and report");
        assert!(out.contains("and report"), "{out}");
    }

    #[test]
    fn a_home_path_is_masked_wherever_it_appears() {
        // The captured left delimiter was added for the tilde alternative, and
        // applying it to the absolute-path alternatives narrowed them: a
        // `/Users/...` preceded by a word character stopped matching, so a
        // concatenated or prefix-tagged path leaked the account name.
        let redactor = redactor();
        for input in [
            "/home/someone/x",
            "at /home/someone/x",
            "path=/home/someone/x",
            "file:///home/someone/x",
            "prefix/home/someone/x",
            "\"/home/someone/x\"",
        ] {
            assert_gone(&redactor, input, "someone");
        }
    }

    #[test]
    fn reverse_dns_identifiers_are_not_hostnames() {
        // A hostname ENDS with its suffix; a reverse-DNS identifier BEGINS with
        // one. The TLD list could not tell them apart, so every Android, Java
        // and Apple bundle id became `<host>` — `com.example.app` is the single
        // most common identifier shape in a mobile crash log.
        let redactor = redactor();
        for input in [
            "com.example.app crashed",
            "launched bundle com.apple.dock.app",
            "at org.jetbrains.kotlin.compiler.plugin",
            "uk.co.example.service started",
        ] {
            assert_eq!(redactor.scrub(input), input, "mangled a reverse-DNS id");
        }
    }

    #[test]
    fn a_dotted_run_longer_than_the_match_is_left_alone() {
        // The rule matched a PREFIX of a longer dotted path and masked it,
        // leaving a tail — `<host>.println` says less than either half.
        let redactor = redactor();
        for input in [
            "stack: at std.foo.io.println",
            "error opening config.yml.dev.bak",
            "some.long.package.name.systems.thing",
        ] {
            assert_eq!(redactor.scrub(input), input, "bit a prefix out of a path");
        }
    }

    #[test]
    fn a_private_suffix_mid_run_is_not_a_hostname() {
        // `PRIVATE_SUFFIXES` matched ANY label anywhere and masked
        // unconditionally, so `internal` and `corp` — a Kotlin visibility
        // keyword and a routine Java package segment — destroyed every frame
        // that contained one. The suffix has to be the LAST label to be a
        // suffix at all.
        let redactor = redactor();
        for input in [
            "at com.foo.internal.Impl",
            "kotlin.internal.PlatformDependent",
            "at com.corp.acme.Service",
            "com.acme.internal.security.Token",
        ] {
            assert_eq!(redactor.scrub(input), input, "mangled a package path");
        }
    }

    #[test]
    fn a_dotfile_is_not_a_machine_on_the_local_network() {
        // `local` is a filename extension as well as a private suffix, and
        // `.env.local` is in every Vite, Next and Django project there is. Two
        // labels alone is not enough to call something a host.
        //
        // Only `local`. Every entry in `WORDLIKE_PRIVATE_SUFFIXES` is a hole,
        // so the list is as short as the evidence supports: `keys.private` is
        // a contrivance and `safe.private` is a machine, so `private` is not
        // on it.
        let redactor = redactor();
        for input in [
            "cannot read .env.local",
            "settings.local missing",
            "loading config.local",
        ] {
            assert_eq!(redactor.scrub(input), input, "mangled a filename");
        }
    }

    #[test]
    fn a_machine_on_the_local_network_is_still_masked() {
        // The other side of the same rule. Three labels is enough on its own;
        // at two, the name has to look like a host — which the ones that
        // actually identify someone do, because that is how macOS and DHCP
        // generate them.
        let redactor = redactor();
        for (input, secret) in [
            ("resolve bastion.internal.acme.corp", "acme"),
            ("resolve ip-10-0-1-5.ec2.internal", "ip-10-0-1-5"),
            ("resolve web.default.svc.cluster.local", "default"),
            ("resolve alices-macbook.local failed", "alices-macbook"),
            ("resolve db01.local failed", "db01"),
        ] {
            assert_gone(&redactor, input, secret);
        }
    }

    #[test]
    fn corporate_dns_without_a_public_tld_is_still_a_host() {
        // A private root with no public suffix at the end — `bastion.corp.acme-inc`
        // — is an ordinary corporate DNS shape. Requiring the last label to be
        // a known suffix let every one of them through.
        let redactor = redactor();
        for (input, secret) in [
            ("resolve bastion.corp.acme-inc failed", "acme-inc"),
            ("resolve mydb.corp.deploys failed", "deploys"),
            ("resolve vault.internal.subnet1 failed", "subnet1"),
            ("resolve bastion.corp.acme-inc.com failed", "acme-inc"),
        ] {
            assert_gone(&redactor, input, secret);
        }
        // …while the reverse-DNS packages that share the shape stay. The
        // discriminator is case: a hostname label is conventionally lowercase,
        // and a class name is not.
        for input in [
            "at com.foo.internal.Impl",
            "kotlin.internal.PlatformDependent",
            "com.acme.internal.security.Token",
        ] {
            assert_eq!(redactor.scrub(input), input, "mangled a package path");
        }
    }

    #[test]
    fn a_capital_anywhere_does_not_make_a_host_a_class_name() {
        // "contains an uppercase letter" was standing in for "is a class
        // name", and one capital anywhere disabled the rule. Windows and AD
        // hostnames are routinely capitalised, so it disabled it on exactly
        // the hosts it exists for. What actually marks a package path is the
        // LAST label being a class name.
        let redactor = redactor();
        for (input, secret) in [
            ("resolve Bastion.internal.acme-inc failed", "acme-inc"),
            ("resolve Server01.corp.acme-inc failed", "Server01"),
            ("resolve BASTION.CORP.acme-inc failed", "acme-inc"),
        ] {
            assert_gone(&redactor, input, secret);
        }
    }

    #[test]
    fn a_shouted_tld_is_still_a_tld() {
        // "Last label starts with a capital" was standing in for "is a class
        // name", and an operator who types `.COM` — or a Windows event log
        // that does — is not writing Java. A class name is CamelCase: it has a
        // lowercase letter after the capital.
        let redactor = redactor();
        for (input, secret) in [
            ("resolve bastion.internal.acme.NET", "acme"),
            ("resolve bastion.internal.acme.Com", "acme"),
            ("resolve bastion.corp.acme-inc.COM", "acme-inc"),
        ] {
            assert_gone(&redactor, input, secret);
        }
        assert_eq!(
            redactor.scrub("at com.foo.internal.Impl"),
            "at com.foo.internal.Impl"
        );
    }

    #[test]
    fn a_country_code_is_not_a_reverse_dns_root() {
        // Every two-letter ccTLD is a public suffix, so "begins with a suffix"
        // excused `us.internal.acme.com` — a corporate host, published whole.
        // Reverse-DNS roots are a much smaller set than public suffixes.
        let redactor = redactor();
        for (input, secret) in [
            ("resolve us.internal.acme.com", "acme"),
            ("resolve de.internal.acme.com", "acme"),
            ("resolve us.acme-inc.com", "acme-inc"),
        ] {
            assert_gone(&redactor, input, secret);
        }
        // …and the real reverse-DNS roots still excuse a package.
        for input in ["at com.acme.internal.util", "at io.netty.internal.buffer"] {
            assert_eq!(redactor.scrub(input), input, "mangled a package path");
        }
    }

    #[test]
    fn a_hyphen_after_a_suffix_means_the_run_is_longer() {
        // `com.acme.internal-tools.util.Client` came back as
        // `<host>-tools.util.Client`: the pattern stopped at `internal`,
        // because its trailing group needs a `.`, and the fragment was judged
        // as if it were the whole name.
        let redactor = redactor();
        let input = "at com.acme.internal-tools.util.Client";
        assert_eq!(redactor.scrub(input), input, "masked a fragment of a path");
    }

    #[test]
    fn a_leading_suffix_does_not_excuse_a_private_root() {
        // The reverse-DNS escape hatch was checked before the suffix at the
        // end, so any host whose first label happened to be a TLD got a free
        // pass — including `int.acme.corp`, which ends in a private suffix and
        // is unambiguously a host.
        let redactor = redactor();
        for (input, secret) in [
            ("resolve int.acme.corp failed", "acme"),
            ("resolve io.corp.acme-inc failed", "acme-inc"),
        ] {
            assert_gone(&redactor, input, secret);
        }
        // …and the reverse-DNS packages it is there for still survive.
        assert_eq!(
            redactor.scrub("at com.acme.internal.util"),
            "at com.acme.internal.util"
        );
    }

    #[test]
    fn only_the_suffixes_with_a_filename_analog_are_relaxed() {
        // The two-label relaxation exists because `.env.local` and
        // `keys.private` are real files. There is no `settings.corp` or
        // `keys.intranet`, so those suffixes get no such licence.
        let redactor = redactor();
        for (input, secret) in [
            ("connect to bastion.corp failed", "bastion"),
            ("connect to vault.internal failed", "vault"),
            ("connect to gitlab.intranet failed", "gitlab"),
            ("connect to db.lan failed", "db"),
            ("connect to router.home failed", "router"),
            ("connect to safe.priv failed", "safe"),
        ] {
            assert_gone(&redactor, input, secret);
        }
    }

    #[test]
    fn a_registrable_domain_under_a_compound_suffix_is_not_a_host() {
        // `co.uk` is one suffix wearing two labels. Counting it as two made
        // `module.co.uk` look like a three-label FQDN when it is a bare
        // registrable domain with nothing in front of it.
        let redactor = redactor();
        assert_eq!(
            redactor.scrub("module.co.uk is a thing"),
            "module.co.uk is a thing"
        );
        // …and a real host under one still goes.
        assert_gone(&redactor, "resolve db01.acme-inc.co.uk failed", "acme-inc");
    }

    #[test]
    fn git_revisions_are_not_home_directories() {
        // `~[A-Za-z0-9._-]+` had no left boundary, so every tilde-suffixed
        // git revision in a command line became `<path>`.
        let redactor = redactor();
        for input in [
            "git reset --hard HEAD~1",
            "git log HEAD~3..HEAD",
            "rebase onto main~2",
        ] {
            assert_eq!(redactor.scrub(input), input, "mangled a git revision");
        }
        // …while the thing the rule is actually for still goes.
        assert_gone(&redactor, "cat ~someone/.bashrc", "someone");
    }
}

// ── The differential corpus (issue #5, step one) ──
//
// The five rewrites of `mask_hosts` each fixed the previous round's defect and
// opened another one next door. Every one was found by a fresh adversarial
// review; **none was found by the tests the previous round had written.** Each
// round added a unit assertion for its own motivating example, and none added
// an invariant that would have predicted the next round.
//
// So the corpus is differential and it is checked in both directions, over real
// strings rather than the one case that motivated a change:
//
//   SURVIVORS  — module paths, bundle ids and filenames. Masking one costs a
//                round trip on the single most useful line in a bug report.
//   HOSTS      — names that identify a private network. Publishing one does not
//                come back.
//
// Run against the rule as it stands, this is the measurement that says which
// way the residual errors fall. It reports one false negative and no false
// positives over the real corpus, and that false negative is a documented
// decision rather than an oversight — see `mask_hosts` and #5.
//
// What it deliberately does NOT do is assert a generative
// `{host|package}.{case}.{suffix}` invariant. Measured, that grid is
// unsatisfiable by any context-free rule: `bastion.com` and `foo.tar.gz` are the
// same two-label shape, and the rule must keep one while masking the other. The
// discriminator is not shape but position and field provenance, which is the
// redesign #5 asks for rather than a patch on top of the prior.
#[cfg(test)]
mod host_corpus {
    use super::*;

    fn redactor() -> Redactor {
        Redactor::with_identity(Some("/Users/testuser".into()), Some("testuser".into()))
    }

    fn masked(input: &str) -> bool {
        let out = redactor().scrub(input);
        out.contains("<host>") || out.contains("<ip>")
    }

    /// Module paths, bundle ids and filenames. Every one has exactly the shape
    /// of a hostname, which is the whole difficulty.
    const SURVIVORS: &[&str] = &[
        // Python
        "os.path.join",
        "django.db.models",
        "django.contrib.auth.models",
        "celery.utils.collections",
        // Java / Kotlin
        "at java.lang.Thread.run",
        "com.example.Main",
        "java.util.concurrent.FutureTask",
        "com.google.common.base.Strings",
        "io.netty.internal.PlatformDependent",
        "kotlin.internal.PlatformDependent",
        "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler",
        // Private suffix as a package segment — the case that broke rounds 2, 3
        // and 5. `internal` is a Kotlin visibility keyword and a routine Java
        // package segment, so it appears in both roles.
        "com.acme.internal.util",
        "com.acme.internal.Impl",
        "com.acme.internal-tools.util.Client",
        // Filenames that end in something shaped like a TLD
        "webpack.config.prod.js",
        "config.yml.bak",
        "config.yml.dev",
        "foo.tar.gz",
        "lib.rs.orig",
        "some.package.name.systems",
        // Reverse-DNS / bundle identifiers
        "com.apple.dock.app",
        "uk.co.example.service",
        "io.grpc.okhttp",
    ];

    /// Names that identify a private network. A mix of the shapes the five
    /// rounds actually broke on, so a regression names the round it undoes.
    const HOSTS: &[&str] = &[
        // Round 3 opened these.
        "bastion.corp",
        "bastion.corp.acme-inc",
        "vault.internal",
        // Round 4 opened these: a capitalised AD hostname, and a leading TLD.
        "Bastion.internal.acme-inc",
        "int.acme.corp",
        // Round 5 opened these: a shouted TLD, and a ccTLD that is also a
        // reverse-DNS root.
        "bastion.internal.acme.NET",
        "us.internal.acme.com",
        // Position: a private label mid-run in a run ending in a private
        // suffix. A hostname ENDS with its suffix; a package BEGINS with one.
        "db01.corp.acme.corp",
        "io.corp.acme-inc",
        "gitlab.intranet",
        "db.lan",
        "cache.private",
        "in-addr.arpa",
        // The `local` relaxation, where the leading label looks like a machine.
        "alices-macbook.local",
        "web-3.local",
        "print-01.internal",
    ];

    #[test]
    fn no_module_path_is_masked() {
        for input in SURVIVORS {
            assert!(
                !masked(input),
                "{input:?} is a module path and must survive"
            );
        }
    }

    #[test]
    fn no_private_host_is_published() {
        for input in HOSTS {
            assert!(masked(input), "{input:?} names a private network");
        }
    }

    /// The decision this corpus exists to make visible.
    ///
    /// `.local` at two labels is relaxed unless the leading label looks like a
    /// machine, because `config.local` and `settings.local` are in every Vite,
    /// Next and Django project there is. The cost is a bare `printer.local`
    /// surviving — a real leak, kept deliberately, and named at `mask_hosts`.
    ///
    /// Asserted as its own test rather than left implicit in the two above: it
    /// is the one place the rule is knowingly wrong, so a change to either side
    /// of the trade has to be deliberate. If the fix in #5 closes it, this test
    /// is what changes.
    #[test]
    fn the_local_relaxation_costs_a_bare_two_label_host() {
        assert!(masked("alices-macbook.local"), "machine-shaped: masked");
        assert!(
            !masked("printer.local"),
            "word-shaped: survives, by decision"
        );
        assert!(!masked("config.local"), "the case the relaxation protects");
    }

    // ── Field provenance (#5) ──
    //
    // The free-text rule above is a prior and cannot do better: a hostname and
    // a reverse-DNS package are the same string in opposite orders, and over a
    // context-free token there is no discriminator that is not another prior.
    // That is why `printer.local` survives and why the five rounds before it
    // each fixed the last and opened another.
    //
    // What changes with field provenance is that the question stops being
    // "what does this token look like". A field called `host` says what it is,
    // so the rule can be certain instead of probable — and certain is what a
    // two-label name needs, because that is exactly the case the shape-based
    // rule has to keep for `foo.tar.gz`.
    //
    // Measured across 13 suffixes × 6 machine-shaped leading labels: 40 leaks
    // in free text, 0 in a `host` field. And 0 over-masked module paths in
    // either, because the field rule does not touch `message`.

    /// The leak class the free-text rule cannot close, closed.
    #[test]
    fn a_host_field_names_are_masked_whatever_the_suffix() {
        // Every one of these survives `scrub`. Two labels is not enough for the
        // free-text rule — `config.local` and `foo.tar.gz` are the same shape —
        // so the whole set is a leak today and none of it is after.
        for tld in [
            "com", "net", "org", "io", "dev", "co.uk", "corp", "internal", "intranet", "lan",
            "local", "arpa", "private",
        ] {
            for host in ["bastion", "db01", "vault", "web-3", "cache", "gateway"] {
                let value = format!("{host}.{tld}");
                assert!(
                    redactor()
                        .scrub_value(Some("host"), &value)
                        .contains("<host>"),
                    "{value:?} in a `host` field must be masked"
                );
            }
        }
    }

    /// The other half, and the one that makes the rule safe to be certain about.
    ///
    /// The aggressive behaviour is only defensible because it is confined to
    /// fields that claim to hold a network name. If it reached `message` it
    /// would eat every stack frame again — which is what round one of the five
    /// did, and what the `SURVIVORS` corpus above exists to prevent.
    #[test]
    fn the_field_rule_does_not_reach_free_text() {
        for input in SURVIVORS {
            // The same value, in a field that does not claim to be a host.
            assert_eq!(
                redactor().scrub_value(Some("message"), input),
                *input,
                "{input:?} in a `message` field must survive untouched"
            );
        }
    }

    /// `scrub` is `scrub_value(None, …)`, and the two must not drift.
    ///
    /// A caller with no field context — `Provenance::scrubbed`, a hand-built
    /// value, any future surface — gets the free-text rules and nothing else.
    /// If this drifts, every one of those paths silently acquires the aggressive
    /// behaviour, and the module paths go with it.
    #[test]
    fn no_field_context_means_the_free_text_rules() {
        for input in [
            "bastion.com",
            "vault.internal",
            "os.path.join",
            "config.local",
        ] {
            assert_eq!(
                redactor().scrub(input),
                redactor().scrub_value(None, input),
                "scrub and scrub_value(None) disagree on {input:?}"
            );
        }
    }

    /// An empty field name carries no information.
    ///
    /// `Some("")` is what a record with a blank key produces, and treating it as
    /// a host field would invent a certainty the caller never gave. It is the
    /// free-text path.
    #[test]
    fn an_empty_field_name_is_not_a_host_field() {
        assert_eq!(
            redactor().scrub_value(Some(""), "bastion.com"),
            redactor().scrub("bastion.com")
        );
    }

    /// Field names are matched case-insensitively and as a dotted path.
    ///
    /// `net.peer.address` and `db_host` are the same contract as `host`. A bare
    /// `contains` would also swallow `ghost` and `hostname_suffix`, which name
    /// no network at all — so the match is anchored at a `.` or the whole name.
    #[test]
    fn host_field_names_match_paths_and_case_but_not_substrings() {
        for name in [
            "host",
            "Host",
            "HOST",
            "net.peer.address",
            "db_host",
            "remote_addr",
        ] {
            assert!(
                is_host_field(name),
                "{name:?} names a network endpoint and should match"
            );
            assert!(
                redactor()
                    .scrub_value(Some(name), "bastion.com")
                    .contains("<host>"),
                "{name:?} should mask a name in its value"
            );
        }
        for name in [
            "ghost",
            "hostname_suffix",
            "message",
            "err",
            "event",
            "whostname",
        ] {
            assert!(!is_host_field(name), "{name:?} is not a host field");
        }
    }

    /// A run is masked whole or not at all.
    ///
    /// Masking `bastion` out of `bastion.corp.acme.com` and leaving
    /// `corp.acme.com` would publish the half that names the organisation, which
    /// is the part a reader can act on. The boundary guards exist for this and
    /// are in the callback, because this engine has no look-around.
    #[test]
    fn a_host_field_name_is_masked_whole_never_in_pieces() {
        for value in [
            "bastion.corp.acme.com",
            "db-01.internal.acme.corp",
            "vault.internal.and.cache.lan",
        ] {
            let masked = redactor().scrub_value(Some("host"), value);
            assert!(
                !masked.contains("acme") && !masked.contains("corp") && !masked.contains("lan"),
                "{value:?} left a fragment behind: {masked}"
            );
        }
    }

    /// A single label in a host field is the machine's own name, and is masked.
    ///
    /// The first draft of this rule required a dot, on the reasoning that a bare
    /// word carries no domain to disclose. The end-to-end canary caught it in one
    /// run: `host=cache01` and `peer=frontend` are exactly the values these
    /// fields carry, and both were published whole. A name that is one label long
    /// is the common case for a container or a service, not the rare one.
    ///
    /// So `localhost` is masked too, which is a real loss of a useful word and is
    /// taken deliberately — the alternative is a rule that publishes the name
    /// whenever the name happens to be short. `keep_hosts` is the opt-out, and it
    /// works because preservation happens around this rule rather than through it.
    #[test]
    fn a_bare_word_in_a_host_field_is_masked() {
        for value in ["localhost", "redis", "cache01", "frontend", "kubernetes"] {
            assert_eq!(
                redactor().scrub_value(Some("host"), value),
                "<host>",
                "{value:?} in a `host` field is the machine's own name"
            );
        }
        // A literal address is masked by the address rule, which runs first and
        // is not field-aware — also correct, and asserted so the two rules are
        // not confused for one.
        assert_eq!(
            redactor().scrub_value(Some("host"), "127.0.0.1"),
            "<ip>",
            "a literal address is masked by the address rule, which runs first"
        );
    }

    /// `keep_hosts` is the opt-out, and it still works.
    ///
    /// The preservation happens in the general rules and is restored after them,
    /// so a name a consumer has explicitly kept is not re-masked by the
    /// field-aware pass running afterwards. Without this, `keep_hosts` would be
    /// silently broken for every field named `host`.
    #[test]
    fn an_explicitly_kept_host_survives_a_host_field() {
        let redactor = Redactor::new().keep_hosts(["api.github.com", "localhost"]);
        assert_eq!(
            redactor.scrub_value(Some("host"), "api.github.com"),
            "api.github.com"
        );
        assert_eq!(redactor.scrub_value(Some("host"), "localhost"), "localhost");
    }

    /// The field rule is idempotent.
    ///
    /// It runs after rules that have already produced markers, and a bare word
    /// is four of them, so without a guard `<host>` came back as `<<host>>`. A
    /// rule that changes a value on a second pass makes every caller that
    /// scrubs twice — a preview and a send, say — produce something different
    /// from what was shown.
    #[test]
    fn the_field_rule_does_not_re_mask_its_own_output() {
        for field in ["host", "peer", "upstream"] {
            let once = redactor().scrub_value(Some(field), "bastion.corp");
            let twice = redactor().scrub_value(Some(field), &once);
            assert_eq!(once, twice, "scrubbing {field} twice changed the value");
            assert!(!once.contains("<<"), "{field} double-masked: {once}");
        }
    }

    /// A port belongs to the name and travels with it.
    ///
    /// `<host>:5432` says the connection was refused on a database port, which is
    /// the difference between a maintainer reading this and asking a question.
    #[test]
    fn a_port_stays_attached_to_the_masked_name() {
        assert_eq!(
            redactor().scrub_value(Some("host"), "db01.corp:5432"),
            "<host>:5432"
        );
    }

    /// Several names in one value are each masked.
    ///
    /// A field can hold a comma-joined list, and a value where only the first
    /// name is masked is a value that still names the rest.
    #[test]
    fn every_name_in_a_listed_value_is_masked() {
        let masked = redactor().scrub_value(Some("upstream"), "vault.internal, cache.lan, db01");
        assert_eq!(masked.matches("<host>").count(), 3, "{masked}");
    }

    /// The JSONL path is where the signal exists, so it is where it must be used.
    ///
    /// `records` has the field name in hand and was discarding it. This is the
    /// only test that proves the plumbing, rather than proving the rule: a rule
    /// that works and is never called is worth nothing.
    ///
    /// The assertion is on the *field*, not on the string. The same name appears
    /// in `message` in the same line, and there the free-text rules apply and it
    /// survives — which is correct, and is the point: the two fields hold the
    /// same bytes and get different treatment because of what they are called.
    #[cfg(feature = "logs")]
    #[test]
    fn the_jsonl_path_passes_the_field_name_through() {
        let line = r#"{"timestamp":"2026-08-12T09:00:00Z","level":"error","message":"bastion.com is down","host":"bastion.com"}"#;
        let records = redactor().records(line, None);
        assert_eq!(records.len(), 1);
        let rendered = records[0].render();

        let host = records[0]
            .fields
            .iter()
            .find(|(name, _)| name == "host")
            .map(|(_, value)| value.as_str())
            .expect("the host field is carried");
        assert_eq!(host, "<host>", "the `host` field is masked by its name");

        assert!(
            rendered.contains("bastion.com is down"),
            "`message` is free text and keeps the free-text rules: {rendered}"
        );
    }

    // ── Host position (#5) ──
    //
    // The third signal, and the one free text actually offers. A hostname and a
    // reverse-DNS package are the same string in opposite orders, so shape cannot
    // separate them; **position** can, because nothing but a name follows
    // `resolve ` or sits inside `host=`.
    //
    // What it buys that shape cannot: a **single-label** name. `resolve bastion`
    // publishes the machine's own name, and no rule in this file could reach it,
    // because there is no dot to build a dotted run out of. That is the leak
    // class the five rounds could not close and the one this closes.

    /// A single-label name in host position, which shape alone cannot find.
    ///
    /// The expected outputs keep the verb and the key. That is not incidental:
    /// the crate is here to redact, not to rewrite, and a preview whose promise
    /// is "exactly what would leave" cannot also be a preview of a tidied-up
    /// sentence. `host=<host>` rather than `<host>` for the same reason — a
    /// maintainer reading a bare `<host>` has lost the field it came from.
    #[test]
    fn a_single_label_name_in_host_position_is_masked() {
        for (value, expected) in [
            ("resolve bastion failed", "resolve <host> failed"),
            ("could not resolve gateway", "could not resolve <host>"),
            ("connect to vault refused", "connect to <host> refused"),
            ("dial redis timed out", "dial <host> timed out"),
            ("host=standalone", "host=<host>"),
            ("peer=frontend", "peer=<host>"),
            ("upstream=cache-01", "upstream=<host>"),
        ] {
            assert_eq!(
                redactor().scrub(value),
                expected,
                "{value:?} names a machine in host position"
            );
        }
    }

    /// A bare word after a *tool* verb is English, and stays.
    ///
    /// The asymmetry with the rule above is deliberate and is the whole reason
    /// there are two of them. `resolve bastion` has no ordinary reading, so a
    /// bare word there is a leak. `curl the page` and `ping the printer` are
    /// sentences, so a bare word there is not — and `ssh the gateway` is exactly
    /// the kind of thing a bug report contains.
    ///
    /// The token still has to look like a machine name, so the tool rules are not
    /// simply weaker: they are differently conditioned.
    #[test]
    fn a_bare_word_after_a_tool_verb_is_english() {
        for value in [
            "curl the page",
            "ping the printer",
            "ssh the gateway",
            "scp the file",
        ] {
            assert!(
                !redactor().scrub(value).contains("<host>"),
                "{value:?} is a sentence, not a hostname"
            );
        }
    }

    /// And the tool rules do fire when the token does look like a machine.
    #[test]
    fn a_tool_verb_with_a_machine_shaped_token_is_masked() {
        for value in [
            "curl web-01.acme.com",
            "ssh db-01.internal",
            "ping build01.corp",
            "rsync cache-01.acme.com:/srv",
        ] {
            assert!(
                redactor().scrub(value).contains("<host>"),
                "{value:?} is a tool invocation naming a host"
            );
        }
    }

    /// An anchor has to be a word, not a fragment of one.
    ///
    /// `presolve`, `resolver` and `resolve()` are a different vocabulary
    /// entirely, and `resolve()` in particular is a function call in a stack
    /// trace — the one line in a bug report a maintainer most wants intact.
    #[test]
    fn an_anchor_must_be_a_whole_word() {
        for value in [
            "presolve x",
            "the hostname is unset",
            "resolve() returned 3",
            "unresolved reference",
            "connecting is not a word boundary here",
        ] {
            assert_eq!(
                redactor().scrub(value),
                value,
                "{value:?} must not be treated as host position"
            );
        }
    }

    /// A run in host position is masked whole, tail included.
    ///
    /// The failure is worth naming because it is the one this rule could easily
    /// have introduced: taking the first label and leaving the rest publishes
    /// `corp.acme-inc`, which is the half that names the organisation. The
    /// pattern claims the entire dotted run for exactly that reason.
    #[test]
    fn an_anchored_run_is_masked_whole() {
        for value in [
            "resolve bastion.corp.acme-inc failed",
            "connect to db01.internal.acme.corp",
            "host=us.internal.acme.com",
        ] {
            let masked = redactor().scrub(value);
            for leak in ["acme", "corp", "internal", "bastion", "db01"] {
                assert!(
                    !masked.contains(leak),
                    "{value:?} leaked {leak:?} in a fragment: {masked}"
                );
            }
        }
    }

    /// The position rules must not reach module paths, which is the failure
    /// mode of every previous round.
    ///
    /// `SURVIVORS` re-checked through `scrub`, now that two more rules run over
    /// the same text. A new rule that widened the reach of the host rules would
    /// show up here first.
    #[test]
    fn the_position_rules_do_not_reach_module_paths() {
        for input in SURVIVORS {
            assert!(
                !redactor().scrub(input).contains("<host>"),
                "{input:?} must survive the position rules too"
            );
        }
    }
}
