//! Prefilled GitHub issue-form URLs.
//!
//! # Why diagnostics never go in the URL
//!
//! GitHub records full request URLs server-side. Anything in the query string
//! is therefore disclosed the moment the browser opens — *before* the reporter
//! has decided whether to submit. A composed-then-abandoned report still leaves
//! its contents in an access log.
//!
//! So the URL carries the prose the reporter wrote and the environment block
//! they can see, and log tails go to the clipboard or a file for a deliberate
//! paste. This also removes the truncation ambiguity entirely: the interesting
//! payload was never competing for URL budget.

use crate::destination::Destination;

/// Hard ceiling on the whole URL.
///
/// Measured against github.com rather than guessed: 4 079 characters answered
/// 302 normally, 7 079 returned 500, 8 079 reset the connection, and 8 279+
/// returned 414. Browsers tolerate far more — Chrome and Firefox handle roughly
/// 32 KB — but GitHub's server cap bites first. 7 500 leaves headroom under the
/// first failing size.
pub const MAX_URL_LEN: usize = 7_500;

/// A built URL, and whether anything was lost building it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefilledUrl {
    pub url: String,
    /// Some text was shortened to fit. The caller **must** say so out loud —
    /// a silently truncated report reads as complete.
    pub truncated: bool,
}

/// Build a prefilled issue-form URL.
///
/// `template` is the issue-form filename (`bug.yml`). It is not optional in
/// practice: a repository with `blank_issues_enabled: false` shows the template
/// chooser rather than a form when it is absent.
///
/// `fields` are `(field id, value)` pairs, where the id is the YAML `id:` of
/// the form field.
pub fn build(destination: &Destination, template: &str, fields: &[(&str, String)]) -> PrefilledUrl {
    let base = format!(
        "https://github.com/{}/issues/new?template={}",
        destination.slug(),
        encode(template)
    );

    let mut budget = MAX_URL_LEN.saturating_sub(base.len());
    let mut query = String::new();
    let mut truncated = false;

    for (id, value) in fields {
        if value.trim().is_empty() {
            continue;
        }
        let prefix = format!("&{}=", encode(id));
        let mut encoded = encode(value);
        if prefix.len() + encoded.len() > budget {
            const NOTE: &str = "\n\n[shortened — the full text was not sent]";
            let room = budget.saturating_sub(prefix.len() + encode(NOTE).len());
            if room == 0 {
                truncated = true;
                continue;
            }
            encoded = truncate_encoded(&encoded, room);
            encoded.push_str(&encode(NOTE));
            truncated = true;
        }
        budget = budget.saturating_sub(prefix.len() + encoded.len());
        query.push_str(&prefix);
        query.push_str(&encoded);
    }

    PrefilledUrl {
        url: format!("{base}{query}"),
        truncated,
    }
}

/// Cut an already-encoded string without splitting a `%XX` triplet.
fn truncate_encoded(encoded: &str, room: usize) -> String {
    let mut cut = encoded.len().min(room);
    let bytes = encoded.as_bytes();
    while cut > 0 {
        let tail = &bytes[cut.saturating_sub(2)..cut];
        if tail.contains(&b'%') {
            cut -= 1;
        } else {
            break;
        }
    }
    encoded[..cut].to_string()
}

/// Percent-encode a query value.
///
/// Space becomes `%20` rather than `+` so the value round-trips however the
/// receiver decodes it, and `+` is escaped so it is never read back as a space.
fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Gate for anything handed to a platform URL opener.
///
/// `open(1)` honours `-a`, `-b` and `-g`, so a string beginning with `-` that
/// reaches it as an argument is read as an option rather than a URL. Openers
/// are commonly invoked without a `--` separator, so this refuses anything that
/// is not plainly an `https://github.com/` URL rather than trusting the caller
/// to have got the separator right.
pub fn is_safe_to_open(url: &str) -> bool {
    // The gate exists because a platform opener may treat argv without a `--`
    // separator specially, so the deny-set has to cover everything a shell or a
    // JS-based opener could act on — not only the obvious whitespace. Tab and
    // NBSP are word-splittable, backslash and backtick carry shell meaning, and
    // U+2028/U+2029 terminate a line for a JavaScript parser.
    //
    // An allowlist would be stricter still, but a GitHub prefill URL legitimately
    // carries percent-escapes, `&`, `=` and `?`, so the useful distinction here
    // is exactly "characters an opener might interpret".
    url.starts_with("https://github.com/")
        && !url.chars().any(|c| {
            c.is_control()
                || c.is_whitespace()
                || matches!(c, '"' | '\'' | '`' | '\\' | '$' | '|' | ';' | '<' | '>')
                || matches!(c, '\u{2028}' | '\u{2029}' | '\u{00a0}' | '\u{feff}')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn destination() -> Destination {
        Destination::parse("gerchowl/squelch").unwrap()
    }

    #[test]
    fn builds_a_prefilled_form_url() {
        let built = build(
            &destination(),
            "bug.yml",
            &[
                ("current-behavior", "panes freeze".into()),
                ("reproduction", "run `app` then split".into()),
            ],
        );
        assert!(built
            .url
            .starts_with("https://github.com/gerchowl/squelch/issues/new?template=bug.yml"));
        assert!(built.url.contains("&current-behavior=panes%20freeze"));
        assert!(built.url.contains("%60app%60"), "{}", built.url);
        assert!(!built.truncated);
    }

    #[test]
    fn skips_empty_values() {
        let built = build(
            &destination(),
            "bug.yml",
            &[("impact", "   ".into()), ("reproduction", "x".into())],
        );
        assert!(!built.url.contains("impact"));
        assert!(built.url.contains("reproduction=x"));
    }

    #[test]
    fn stays_under_the_measured_cap() {
        let built = build(
            &destination(),
            "bug.yml",
            &[("current-behavior", "x".repeat(40_000))],
        );
        assert!(built.truncated);
        assert!(built.url.len() <= MAX_URL_LEN, "{} chars", built.url.len());
        assert!(built.url.contains("shortened"));
    }

    #[test]
    fn many_oversized_fields_still_fit() {
        let fields: Vec<(&str, String)> = vec![
            ("a", "é".repeat(3_000)),
            ("b", "x".repeat(3_000)),
            ("c", "y".repeat(3_000)),
        ];
        let built = build(&destination(), "bug.yml", &fields);
        assert!(built.url.len() <= MAX_URL_LEN, "{} chars", built.url.len());
        assert!(built.truncated);
    }

    #[test]
    fn truncation_never_splits_a_percent_escape() {
        for len in 1..64 {
            let built = build(&destination(), "bug.yml", &[("impact", "é".repeat(len))]);
            let bytes = built.url.as_bytes();
            for (index, byte) in bytes.iter().enumerate() {
                if *byte == b'%' {
                    assert!(index + 2 < bytes.len(), "dangling escape: {}", built.url);
                }
            }
        }
    }

    #[test]
    fn open_gate_rejects_option_shaped_and_foreign_urls() {
        assert!(is_safe_to_open(
            "https://github.com/o/r/issues/new?template=bug.yml"
        ));
        for bad in [
            "-a/Applications/Calculator.app",
            "--version",
            "file:///etc/passwd",
            "https://evil.example/github.com/",
            "http://github.com/o/r",
            "https://github.com/o/r\nmore",
            "https://github.com/o/r other",
        ] {
            assert!(!is_safe_to_open(bad), "{bad}");
        }
    }

    #[test]
    fn the_opener_gate_rejects_everything_an_opener_could_interpret() {
        // The gate's justification is that a platform opener may treat argv
        // specially without a `--`. That claim needs more than the obvious
        // whitespace: these all passed before.
        let base = "https://github.com/o/r";
        for bad in [
            "\t", "\\", "$HOME", "`x`", "\u{000b}", "\u{007f}", "\u{2028}", "\u{2029}", "\u{00a0}",
            "|x", ";x", "<x", ">x",
        ] {
            let url = format!("{base}{bad}");
            assert!(
                !is_safe_to_open(&url),
                "{bad:?} should not survive the opener gate"
            );
        }
        assert!(is_safe_to_open(
            "https://github.com/o/r/issues/new?template=bug.yml&a=b%20c"
        ));
    }
}
