//! What the binary knows about itself and its host.
//!
//! Everything here is collected, never asked. The reporter's job is to describe
//! what went wrong; assembling version strings is the machine's.
//!
//! # Absent values are stated, not omitted
//!
//! A missing "Shell:" line leaves a triager unable to tell "this reporter has no
//! `SHELL` set" — itself diagnostic, and the signature of a stripped service
//! environment — from "the tool never looked". So every field renders, with an
//! explicit marker when it could not be determined.
//!
//! This idea is borrowed from the `bugreport` crate, whose collectors turn a
//! failure into a report entry rather than dropping the section.

use std::fmt::Write as _;

/// A single collected fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Known(String),
    /// Looked for, definitively not present.
    NotSet,
    /// Could not be determined, with the reason.
    Unavailable(String),
}

impl Value {
    pub fn from_env(name: &str) -> Self {
        match std::env::var(name) {
            Ok(value) if !value.is_empty() => Self::Known(value),
            Ok(_) | Err(std::env::VarError::NotPresent) => Self::NotSet,
            Err(err) => Self::Unavailable(err.to_string()),
        }
    }

    pub fn known(value: impl Into<String>) -> Self {
        Self::Known(value.into())
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Known(value) => value,
            Self::NotSet => "not set",
            Self::Unavailable(_) => "unavailable",
        }
    }

    fn render(&self) -> String {
        match self {
            Self::Known(value) => value.clone(),
            Self::NotSet => "not set".into(),
            Self::Unavailable(reason) => format!("could not determine ({reason})"),
        }
    }
}

/// The environment block of a report.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Provenance {
    entries: Vec<(String, Value)>,
}

impl Provenance {
    pub fn new() -> Self {
        Self::default()
    }

    /// Everything derivable without knowing anything about the application:
    /// OS, architecture, and the terminal/shell the user is in.
    ///
    /// Add the caller's own version and build shape with [`Provenance::app`]
    /// and [`Provenance::build`], or use the [`crate::provenance!`] macro,
    /// which fills both from the calling crate.
    pub fn standard() -> Self {
        let mut provenance = Self::new();
        provenance.set("Operating system", Value::known(std::env::consts::OS));
        provenance.set("Architecture", Value::known(std::env::consts::ARCH));

        // TERM_PROGRAM names the emulator; TERM only names its capabilities.
        let terminal = match Value::from_env("TERM_PROGRAM") {
            Value::Known(value) => Value::Known(value),
            _ => Value::from_env("TERM"),
        };
        provenance.set("Terminal", terminal);

        // Basename only: a full path can be `/nix/store/<hash>-zsh-5.9/bin/zsh`,
        // which is noise and discloses the store layout.
        let shell = match Value::from_env("SHELL") {
            Value::Known(path) => path
                .rsplit(['/', '\\'])
                .next()
                .filter(|name| !name.is_empty())
                .map(Value::known)
                .unwrap_or(Value::NotSet),
            other => other,
        };
        provenance.set("Shell", shell);
        provenance
    }

    /// The application's name and version.
    pub fn app(mut self, name: &str, version: &str) -> Self {
        self.set("Application", Value::known(format!("{name} {version}")));
        self
    }

    /// Target triple and profile.
    ///
    /// Neither is derivable at runtime — `std::env::consts` gives OS and
    /// architecture but cannot distinguish a musl build from a gnu one — and
    /// "this is a debug build" explains a whole class of performance reports
    /// on its own. Populate from a build script; see the crate docs.
    pub fn build(mut self, target: &str, profile: &str) -> Self {
        self.set("Build", Value::known(format!("{target} ({profile})")));
        self
    }

    /// The commit the binary was built from.
    ///
    /// The field that answers "is this already fixed". On a rolling or nightly
    /// channel many builds share one version string, so a version alone cannot
    /// identify the code that ran.
    pub fn commit(mut self, commit: Option<&str>) -> Self {
        self.set(
            "Commit",
            commit
                .filter(|c| !c.is_empty())
                .map(Value::known)
                .unwrap_or(Value::NotSet),
        );
        self
    }

    /// Add or replace an entry. Order of first insertion is preserved.
    pub fn set(&mut self, label: &str, value: Value) -> &mut Self {
        match self.entries.iter_mut().find(|(name, _)| name == label) {
            Some((_, slot)) => *slot = value,
            None => self.entries.push((label.to_string(), value)),
        }
        self
    }

    /// Add an entry, builder-style.
    pub fn with(mut self, label: &str, value: Value) -> Self {
        self.set(label, value);
        self
    }

    /// Add a fact whose collection may have failed, preserving the reason.
    pub fn with_result<E: std::fmt::Display>(self, label: &str, value: Result<String, E>) -> Self {
        let value = match value {
            Ok(value) if value.is_empty() => Value::NotSet,
            Ok(value) => Value::Known(value),
            Err(err) => Value::Unavailable(err.to_string()),
        };
        self.with(label, value)
    }

    pub fn entries(&self) -> &[(String, Value)] {
        &self.entries
    }

    /// Render as the markdown bullet list an environment field expects.
    pub fn to_markdown(&self) -> String {
        // Sanitized, and not only scrubbed. `scrubbed` masks identifying
        // material; it does not stop a value from being READ as markdown.
        // These entries are rendered as body text rather than inside a fence,
        // so a value carrying a newline and a `##` or an `<img onerror=…>`
        // lands as live markup in a public issue — no fence to break out of,
        // because there was never one to begin with.
        //
        // Values here are routinely environment-derived (`SHELL`, `TERM`, the
        // executable's own path), which is exactly the material an attacker
        // upstream of the reporter can influence.
        let mut out = String::new();
        for (label, value) in &self.entries {
            let _ = writeln!(
                out,
                "- {}: {}",
                crate::redact::sanitize_inline(label),
                crate::redact::sanitize_inline(&value.render())
            );
        }
        out
    }

    /// Scrub every value. Call before rendering if any entry may carry a path
    /// or hostname — the binary's own location usually does.
    pub fn scrubbed(mut self, redactor: &crate::Redactor) -> Self {
        // Labels too. Only values were scrubbed, but a label is caller-supplied
        // and an entirely reasonable one — `Hostname`, `Config path` — carries
        // exactly the material this masks when the caller builds it from
        // something dynamic.
        for (label, value) in &mut self.entries {
            *label = redactor.scrub(label);
            if let Value::Known(text) = value {
                *text = redactor.scrub(text);
            }
        }
        self
    }
}

/// Build a [`Provenance`] pre-filled from the *calling* crate: name, version,
/// and the standard host facts.
///
/// ```
/// let provenance = squelch::provenance!();
/// assert!(provenance.to_markdown().contains("Operating system"));
/// ```
#[macro_export]
macro_rules! provenance {
    () => {
        $crate::Provenance::standard().app(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_values_are_stated_not_omitted() {
        let out = Provenance::new()
            .with("Shell", Value::NotSet)
            .with("Terminal", Value::Unavailable("not unicode".into()))
            .to_markdown();
        assert!(out.contains("- Shell: not set"), "{out}");
        assert!(out.contains("could not determine (not unicode)"), "{out}");
    }

    #[test]
    fn standard_collects_host_facts() {
        let out = Provenance::standard().to_markdown();
        assert!(out.contains("Operating system"), "{out}");
        assert!(out.contains("Architecture"), "{out}");
        // Every label renders, even when the value is absent.
        assert!(out.contains("Shell"), "{out}");
    }

    #[test]
    fn set_replaces_without_reordering() {
        let mut provenance = Provenance::new();
        provenance.set("A", Value::known("1"));
        provenance.set("B", Value::known("2"));
        provenance.set("A", Value::known("3"));
        let labels: Vec<&str> = provenance
            .entries()
            .iter()
            .map(|(label, _)| label.as_str())
            .collect();
        assert_eq!(labels, vec!["A", "B"]);
        assert_eq!(provenance.entries()[0].1, Value::known("3"));
    }

    #[test]
    fn results_keep_their_failure_reason() {
        let out = Provenance::new()
            .with_result("Config", Err::<String, _>(std::fmt::Error))
            .to_markdown();
        assert!(out.contains("could not determine"), "{out}");
    }

    #[test]
    fn scrubbing_reaches_every_value() {
        let redactor =
            crate::Redactor::with_identity(Some("/Users/alice".into()), Some("alice".into()));
        let out = Provenance::new()
            .with("Binary", Value::known("/Users/alice/bin/app"))
            .scrubbed(&redactor)
            .to_markdown();
        assert!(!out.contains("alice"), "{out}");
        assert!(out.contains("~/bin/app"), "{out}");
    }

    #[test]
    fn build_and_commit_render() {
        let out = Provenance::new()
            .build("aarch64-apple-darwin", "release")
            .commit(Some("abc1234"))
            .to_markdown();
        assert!(out.contains("aarch64-apple-darwin (release)"), "{out}");
        assert!(out.contains("abc1234"), "{out}");
    }

    #[test]
    fn absent_commit_says_so() {
        let out = Provenance::new().commit(None).to_markdown();
        assert!(out.contains("- Commit: not set"), "{out}");
    }
}
