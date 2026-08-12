//! Let your users file a bug report that is actually useful — without asking
//! them to know what you need, and without leaking their machine onto a public
//! tracker.
//!
//! # Why "squelch"
//!
//! On a radio, the squelch is a threshold you tune: it mutes the channel until
//! a real signal is present, so you hear the transmission instead of the hiss.
//! That is the job here, at three levels.
//!
//! Noise out of the **report** — the reporter writes what broke, and the
//! machine fills in versions, build shape and a redacted log tail, so the
//! issue carries signal rather than "it doesn't work on my computer".
//!
//! Noise out of the **tracker** — required fields are checked before anything
//! opens, and the reporter is told what is missing rather than discovering it
//! after a browser launch.
//!
//! And eventually noise out of the **product**: reports you can act on become
//! fixes, and fixes mean fewer reports. Tuning the squelch is the loop, not a
//! single function.
//!
//! # The shape of it
//!
//! ```no_run
//! use squelch::{report, provenance, Redactor, Transport};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let (current, repro) = ("it hangs", "run it twice");
//! let redactor = Redactor::new();
//!
//! # #[cfg(feature = "logs")]
//! let records = {
//!     let logs = std::fs::read_to_string("/var/log/myapp.jsonl").unwrap_or_default();
//!     redactor.records(&logs, Some("myapp.jsonl"))
//! };
//! # #[cfg(not(feature = "logs"))]
//! # let records: Vec<squelch::Record> = Vec::new();
//!
//! let report = report!()?
//!     .template("bug.yml")
//!     .field("current-behavior", current)
//!     .field("reproduction", repro)
//!     .require(["current-behavior", "reproduction"])
//!     .provenance(provenance!().scrubbed(&redactor))
//!     .diagnostics(records)
//!     .via(Transport::Browser);
//!
//! println!("{}", report.preview()?);   // exactly what would leave
//! report.send()?;                       // opens GitHub's form, prefilled
//! # Ok(())
//! # }
//! ```
//!
//! # What it will not do
//!
//! **Submit on your users' behalf by default.** [`Transport::Browser`] opens
//! GitHub's own form so the human reviews and clicks Submit. That keeps them
//! the author of their own issue, runs the template's required-field
//! validation, and needs no credential anywhere. Other routes exist and are
//! explicit about which of those guarantees they give up — see [`transport`].
//!
//! **Carry a credential.** There is no bundled token and no default endpoint.
//! A write credential inside a distributed binary is extracted and abused; the
//! only safe place for one is a server you operate.
//!
//! **Tick a confirmation checkbox.** GitHub cannot prefill `checkboxes` at all,
//! and that is the right outcome: a "yes, this is reproducible" box is an
//! attestation, and a tool that ticks it forges a human's statement.
//!
//! # Build-time facts
//!
//! Target triple, profile and commit are not derivable at runtime. Export them
//! from a build script and pass them to [`Provenance`]:
//!
//! ```no_run
//! // build.rs
//! println!("cargo:rustc-env=MYAPP_TARGET={}", std::env::var("TARGET").unwrap());
//! println!("cargo:rustc-env=MYAPP_PROFILE={}", std::env::var("PROFILE").unwrap());
//! ```
//!
//! ```text
//! provenance!().build(env!("MYAPP_TARGET"), env!("MYAPP_PROFILE"))
//! ```
//!
//! `text`, not `ignore`: those variables are set by *your* build script, so
//! this can never compile here. An `ignore`d block reads as a doctest someone
//! switched off and means to switch back on.
//!
//! # Features
//!
//! | feature | default | what it adds |
//! | --- | --- | --- |
//! | `browser` | yes | open the prefilled form; no dependencies |
//! | `logs` | yes | JSONL extraction (`serde_json`) |
//! | `gh-cli` | no | create the issue with `gh`; no dependencies |
//! | `endpoint` | no | POST to an endpoint you operate (`ureq`, `serde_json`) |
//! | `schema` | no | `Form::json_schema` for an agent tool surface (`serde_json`). Not an intra-doc link: the target does not exist on a default build, and a link that only resolves under one feature breaks `cargo doc` on every other |
//! | `serde` | no | derive serde on [`Form`], so you can load it from YAML/JSON/TOML/RON with your own parser |
//!
//! With `default-features = false` the crate pulls `regex`, plus `libc` on
//! Unix — the scrubber falls back to `getpwuid` for the home directory and
//! username when a service manager has stripped `HOME` and `USER` from the
//! environment, which is exactly when it would otherwise stop recognising the
//! paths it exists to mask. It still redacts, builds URLs and renders bodies.

#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_debug_implementations)]

pub mod destination;
pub mod error;
pub mod form;
pub mod provenance;
pub mod redact;
pub mod report;
pub mod transport;
pub mod url;

pub use destination::{Destination, DestinationError};
pub use error::{Error, Result};
pub use form::{Field, FieldKind, Form};
pub use provenance::{Provenance, Value};
pub use redact::{Record, Redactor};
pub use report::{Composed, Report, Sent};
pub use transport::Transport;
// `Composed::url` is a public field of this type, so a consumer who binds it
// has to be able to name it without reaching into the module path.
pub use url::PrefilledUrl;

#[cfg(feature = "endpoint")]
pub use transport::Auth;
// The type a consumer must name to build `Auth::Dynamic`.
#[cfg(feature = "endpoint")]
pub use transport::DynamicAuth;

/// Start a [`Report`] aimed at the *calling* crate's `repository`.
///
/// Expands at the call site so it reads the consumer's `CARGO_PKG_REPOSITORY`,
/// not this crate's. Returns [`Err`] when the caller declares no `repository`
/// — which is a build-configuration problem worth surfacing loudly rather than
/// guessing a destination.
#[macro_export]
macro_rules! report {
    () => {
        $crate::Destination::from_cargo_repository(option_env!("CARGO_PKG_REPOSITORY"))
            .map($crate::Report::to)
            .map_err($crate::Error::from)
    };
}

#[cfg(test)]
mod tests {
    use crate::provenance;

    #[test]
    fn report_macro_resolves_this_crate_in_its_own_tests() {
        // Inside squelch's own test binary the calling crate IS squelch, so
        // this exercises the macro end to end.
        let report = report!().expect("squelch declares a repository");
        let preview = report
            .field("current-behavior", "x")
            .preview()
            .expect("preview");
        assert!(preview.contains("gerchowl/squelch"), "{preview}");
    }

    #[test]
    fn provenance_macro_names_the_calling_crate() {
        let out = provenance!().to_markdown();
        assert!(out.contains("squelch"), "{out}");
    }
}
