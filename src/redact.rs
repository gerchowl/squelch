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
//! - IPv4 and IPv6
//! - hostnames under private suffixes, and any FQDN of three or more labels
//!
//! # What it deliberately does not cover
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
pub const DEFAULT_SCRUBBED_FIELDS: &[&str] = &["message", "msg", "error", "err"];

/// Cap on any single retained value, in characters.
const MAX_VALUE_CHARS: usize = 1_024;

/// One log record reduced to what may be published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub timestamp: String,
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
            (labeled_secret_re(), "${1}${2}${3}${4}=<redacted>"),
            (email_re(), "<email>"),
            (ssh_target_re(), "<ssh-target>"),
            (ipv6_re(), "${1}<ip>${3}"),
            (ipv4_re(), "<ip>"),
            (private_host_re(), "<host>"),
        ] {
            out = pattern.replace_all(&out, replacement).to_string();
        }

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
                .replace_all(&out, |caps: &regex::Captures| {
                    if caps[0].ends_with('/') {
                        "~/".to_string()
                    } else {
                        "~".to_string()
                    }
                })
                .to_string();
        }
        out = home_path_re().replace_all(&out, "<path>").to_string();
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

        for name in &self.scrubbed {
            if let Some(raw) = object.get(name).and_then(json_scalar) {
                let scrubbed = self.scrub(&raw);
                if !scrubbed.is_empty() {
                    fields.push((name.clone(), quote_if_spaced(&scrubbed)));
                }
            }
        }
        for name in &self.allowed {
            if let Some(raw) = object.get(name).and_then(json_scalar) {
                fields.push((name.clone(), quote_if_spaced(&self.scrub(&raw))));
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
            r"(?x)
              \bgit@[A-Za-z0-9._\-]+:[^\s\x22]+
            | \bssh://[^\s\x22]+
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
            # The whole AWS key-id family, not just long-lived user keys. ASIA
            # (STS session) is the one a compromised CI actually leaks.
            | (?:AKIA|ASIA|AIDA|AROA|AGPA|AIPA|ANPA|ANVA|APKA)[0-9A-Z]{16}
            # Private key material: mask the armour, since the base64 body that
            # follows is on its own lines and matches nothing else here.
            | -----BEGIN[A-Z ]*PRIVATE\ KEY-----
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

/// Hostnames that identify a network rather than a public service.
///
/// The ssh-target rule only fires when there is a `user@`, and error strings
/// overwhelmingly carry a bare FQDN instead ("Could not resolve hostname
/// bastion.internal.acme.corp").
///
/// Three labels is the floor on purpose, with an alphabetic final label: it
/// keeps `server.log` and `config.yml` intact, and stops version strings like
/// `0.6.8-fork.85ce040` being mistaken for hosts.
fn private_host_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?xi)
              [A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]+)*\.(?:corp|internal|intranet|local|lan|home|priv|private|arpa)\b
            # Four labels, and case-sensitive: hostnames are conventionally
            # lowercase, while a capitalised label means a class name. Three
            # labels ate `config.yml.bak` and `os.path.join`; case-insensitivity
            # ate `java.lang.Thread.run`. A capitalised host under a private
            # suffix is still caught by the rule above.
            | (?-i:[a-z0-9_\-]+(?:\.[a-z0-9_\-]+){2,}\.[a-z]{2,})\b
            ",
        )
        .expect("static private-host pattern")
    })
}

/// Another account's home directory. The current user's is rewritten to `~`
/// before this runs. Covers Windows profile paths too.
fn home_path_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?xi)
              (?:/Users|/home)/[^\s\x22/]+(?:/[^\s\x22]*)?
            # Root's home is still an account's home, and a path under it says
            # the process ran privileged.
            | /var/root\b(?:/[^\s\x22]*)?
            | /root\b(?:/[^\s\x22]*)?
            # macOS per-user temp: the salt uniquely identifies the user.
            | /private/var/folders/[^\s\x22]*
            | /var/folders/[^\s\x22]*
            # `~alice/.bashrc` names the account without any /home prefix.
            | ~[A-Za-z0-9._\-]+(?:/[^\s\x22]*)?
            | [A-Z]:\\Users\\[^\\/\s\x22]+(?:\\[^\s\x22]*)?
            | [A-Z]:\\Documents\ and\ Settings\\[^\\/\s\x22]+(?:\\[^\s\x22]*)?
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
