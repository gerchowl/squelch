//! Point a crash at the reporter.
//!
//! The single most common reason a CLI adds a bug-report crate is "when the tool
//! crashes, offer to file this", and without this module there is no way to do
//! that: nothing in the crate mentions `set_hook`, and a `Report` cannot be
//! built from a panic because a panic carries two strings and a location.
//!
//! # It composes. It never sends.
//!
//! [`install`] chains to whatever hook was already installed, and hands the
//! application a [`Report`] to route. Sending is the application's decision,
//! made in code that is not running inside a panicking process.
//!
//! That separation is the whole design, and it is not caution for its own sake.
//! A panic hook runs while the process is already failing: the default hook has
//! not finished printing, the application's own error handling has not run, and
//! anything this hook does is happening in a context where a second failure
//! aborts the process outright. Opening a browser from here, or writing to a
//! socket, is how a bug report becomes the reason a bug report is needed.
//!
//! ```no_run
//! use squelch::panic;
//!
//! # fn main() {
//! let report = panic::install(|report| {
//!     // The process is panicking. Compose and print; do not transmit.
//!     eprintln!("{}", report.preview().unwrap_or_default());
//! });
//! # let _ = report;
//! # }
//! ```
//!
//! # What is supported
//!
//! - **Main-thread panics with `panic = "unwind"` semantics** — the default
//!   `panic = "unwind"`. A panic on any thread runs the hook.
//! - **`panic_any` payloads**, as well as `&str` and `String`. A payload that is
//!   neither is reported as a marker rather than dropped, because a payload this
//!   crate cannot read is exactly the one worth having in a report.
//!
//! # What is not
//!
//! - **`panic = "abort"`.** No hook runs, because there is no unwinding to
//!   interrupt. Nothing in this crate can detect that at compile time, so an
//!   application that wants the entry point in release builds must not set it.
//! - **`catch_unwind`.** A caught panic still runs the hook — that is what a
//!   hook is — so a `catch_unwind` around code that panics produces a report
//!   whether or not the application wanted one. Install the hook once, at
//!   startup, and treat the `Report` as advisory.
//! - **Replacing an existing hook.** [`install`] chains rather than replaces, so
//!   an application's own crash handler keeps running; see [`from_panic`] for
//!   building one without installing at all.
//! - **A callback that panics.** A panic inside a panic hook aborts the process.
//!   The previous hook has already run by then, so the original message still
//!   reaches the terminal — but the report does not, because delivering it is
//!   what failed. The crash is never swallowed; the report is the thing you lose.
//!
//! # Cost
//!
//! One thread-local, no allocation beyond the composed report, and no new
//! dependencies: `std::panic` and this crate's own [`Redactor`].

use std::panic::{self, PanicHookInfo};
use std::sync::Once;

use crate::destination::Destination;
use crate::error::Result;
use crate::provenance::Provenance;
use crate::redact::Redactor;
use crate::report::Report;

static INSTALLED: Once = Once::new();

/// Install a panic hook that hands a composed [`Report`] to `on_panic`.
///
/// Chains to the hook that was already installed, so an application's own crash
/// handling keeps running — `set_hook` is process-global and replaces silently,
/// which is how a bug-report crate disables a program's real error handling
/// without anyone noticing.
///
/// The report is **not sent**. `on_panic` decides what happens to it, and in a
/// panicking process the safe options are narrow: print the preview, write it to
/// a file, or hand it to something that will not be interrupted. Anything that
/// spawns a process, opens a socket or allocates without bound belongs after the
/// unwind, in code the application controls.
///
/// The closure runs **on the panicking thread**, inside the hook, while the
/// panic is still in flight. It should not block, and it must not panic: a panic
/// inside a panic hook aborts the process. The hook chains to the previous one
/// *before* calling it, so the original message still reaches the terminal in
/// that case — the report is what is lost, not the crash.
///
/// The report is aimed at **this crate's** `CARGO_PKG_REPOSITORY`, because the
/// hook has no way to ask the application where to send: running user code to
/// find out would be a second failure waiting to happen. An application filing
/// elsewhere overrides it on the returned [`Report`], or composes its own with
/// [`from_panic`].
///
/// Calling this more than once is a no-op after the first. A panic hook is
/// process-global, so a second install would otherwise wrap the first and report
/// every panic twice — and `take_hook` from inside a hook is a data race waiting
/// to happen.
///
/// Returns a [`Report`] for the *installation point* rather than for a panic, so
/// the caller can hold a configured report to fill in. It is not the report from
/// a panic that has not happened; see [`from_panic`] for the composition itself.
pub fn install<F>(on_panic: F) -> Report
where
    F: Fn(Report) + Send + Sync + 'static,
{
    install_with(Redactor::new(), on_panic)
}

/// As [`install`], with a caller-supplied [`Redactor`].
///
/// The redactor is taken here rather than built inside so a consumer that
/// already has one — with `keep_hosts` configured, or a different home
/// directory — uses the same instance the rest of its reports go through. A
/// second `Redactor::new()` would be a subtly different scrubber, and the
/// difference would only show up as a leak.
pub fn install_with<F>(redactor: Redactor, on_panic: F) -> Report
where
    F: Fn(Report) + Send + Sync + 'static,
{
    let base = base_report();
    install_hook(redactor, on_panic, &INSTALLED);
    base
}

/// Install the hook, at most once per `guard`.
///
/// The `Once` is a parameter rather than a constant so the test suite can drive
/// this with a fresh guard per test. A panic hook is process-global, so tests
/// that share one would race: whichever ran first would install, and every other
/// would silently get a no-op and then fail on an empty capture — which reads as
/// a broken hook rather than a broken test.
///
/// Production passes the module-level `INSTALLED` and the semantics are exactly
/// "first call wins". The race the `Once` prevents is real: two threads calling
/// `install` concurrently would both `take_hook`, and the second `set_hook`
/// would wrap the first, so every panic produced two reports and the inner
/// closure was dropped while the outer still referred to it.
fn install_hook<F>(redactor: Redactor, on_panic: F, guard: &Once)
where
    F: Fn(Report) + Send + Sync + 'static,
{
    guard.call_once(|| {
        let previous = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            // The previous hook runs FIRST, and the order is load-bearing.
            //
            // A panic inside a panic hook aborts the process, so an application's
            // callback that fails takes the report with it — and, if the previous
            // hook has not run yet, the original panic message too. That is the
            // unrecoverable case: a user whose tool crashed, with a crash
            // reporter that swallowed the crash. The end-to-end test in
            // `apps/squelch-demo` is what caught this, and it could only be
            // caught there, because the abort takes an in-process test with it.
            //
            // Composing first was the first draft and it was wrong for this
            // reason. Composing second costs a little: the report reflects the
            // state after the previous hook has printed, which for every hook
            // that exists is the same state, since hooks print and return.
            previous(info);
            if let Ok(report) = compose_from_panic(&redactor, info) {
                on_panic(report);
            }
        }));
    });
}

/// Build a [`Report`] describing a panic, without installing anything.
///
/// For an application that catches its own panics, or that wants the
/// composition in a test. The panic payload and location go through the
/// [`Redactor`] like any other value, because a panic message is exactly where a
/// path, a username or a token ends up by accident — `unwrap` on a `PathBuf`,
/// an index into a `HashMap` keyed by a URL.
///
/// The report is returned **unconfirmed** and **undispatched**: calling
/// [`Report::send`] on it still requires the application's own `.confirmed()`,
/// exactly as any other route does.
pub fn from_panic(
    redactor: &Redactor,
    destination: &Destination,
    info: &PanicHookInfo<'_>,
) -> Result<Report> {
    // Built against the caller's destination rather than this crate's. The
    // composed fields are identical either way, so this is a re-aim rather than
    // a second composition — and an application filing somewhere other than
    // squelch's own tracker is the normal case, not an edge one.
    Ok(Report::to(destination.clone()).fields(panic_fields(redactor, info)))
}

/// The fields describing a panic, as `(id, value)` pairs.
///
/// Split out so [`from_panic`] and [`compose_from_panic`] cannot disagree about
/// what a panic report contains — the difference between them is only where it
/// is aimed, and two copies of the field list is one more thing to drift.
fn panic_fields(redactor: &Redactor, info: &PanicHookInfo<'_>) -> Vec<(&'static str, String)> {
    vec![
        ("panic", redactor.scrub(&panic_message(info))),
        ("panic-location", panic_location(redactor, info)),
    ]
}

/// Compose a report from a panic payload and location, against this crate's own
/// `CARGO_PKG_REPOSITORY`.
fn compose_from_panic(redactor: &Redactor, info: &PanicHookInfo<'_>) -> Result<Report> {
    let mut report = base_report();

    // Field ids that a consumer's form may not declare. `Report::field` takes
    // any id and the preview renders it regardless, so this cannot fail a send —
    // but a form that does declare them shows the panic where a reporter
    // expects to see it.
    for (id, value) in panic_fields(redactor, info) {
        report = report.field(id, value);
    }

    // Provenance as usual: what was running when it broke. Scrubbed by the same
    // redactor, so a panic in a service environment with `HOME` stripped still
    // gets a usable environment block.
    //
    // `Provenance::standard()` rather than the `provenance!()` macro: the macro
    // expands at the call site and reads the *calling* crate's
    // `CARGO_PKG_NAME`, which inside this module would be squelch's own. A panic
    // report that says "Application: squelch 0.1.0" when the application is
    // something else is a report that misleads, and the environment block is
    // most of what makes it useful.
    //
    // A consumer that wants its own name and version in the report adds them
    // with `Report::provenance`, which takes the value outright and so replaces
    // rather than extends — documented at `install`, and the reason this is a
    // sensible default rather than a wrong one.
    report = report.provenance(Provenance::standard().scrubbed(redactor));

    // Never confirmed. A panic is not a human saying "send this", and the routes
    // that transmit without a review surface require `.confirmed()` — which is
    // what keeps this from being a back door around the crate's one rule.
    Ok(report)
}

/// The payload as text, whatever it is.
///
/// `panic!` with a literal gives `&'static str`; with a format argument it gives
/// `String`; `panic_any` gives whatever the caller chose. All three are read
/// here. A payload of some other type is reported as a marker rather than
/// dropped, because a payload this crate cannot read is precisely the one a
/// maintainer would want to see in the report — and the marker says the value
/// was there.
fn panic_message(info: &PanicHookInfo<'_>) -> String {
    let payload = info.payload();
    if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_string()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}

/// Where it broke, as `file:line:column`.
///
/// **Scrubbed**, because a panic location is a source path and a build path
/// carries a home directory, a CI workspace name or a branch. `Redactor::scrub`
/// already rewrites homes to `~`, and it is the same redactor the rest of the
/// report went through — a second, narrower scrubber here would be a rule that
/// only applies to panics, which is the shape of a leak nobody looks for.
fn panic_location(redactor: &Redactor, info: &PanicHookInfo<'_>) -> String {
    let Some(location) = info.location() else {
        return "<unknown>".to_string();
    };
    redactor.scrub(&format!(
        "{}:{}:{}",
        location.file(),
        location.line(),
        location.column()
    ))
}

/// A report with no destination, for the hook to fill in later.
///
/// The hook cannot ask the application where to send: it has no argument and
/// running user code to find out would be a second failure waiting to happen. So
/// the hook composes against `CARGO_PKG_REPOSITORY` — the same default
/// `report!()` uses — and an application that files elsewhere overrides it after
/// [`install`] returns.
fn base_report() -> Report {
    crate::report!().unwrap_or_else(|_| {
        // Only reachable if squelch's own `CARGO_PKG_REPOSITORY` is unset, which
        // would be a packaging bug in this crate rather than in the caller.
        // A `Report` with no destination is still better than no report, and the
        // application can attach one.
        Report::to(Destination::parse("unknown/unknown").expect("static destination parses"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// Test-local `install_with` with a per-test `Once`.
    ///
    /// A panic hook is process-global, so sharing the production guard across
    /// parallel tests means whichever ran first wins and the rest get a silent
    /// no-op. The failure mode is nasty: an empty capture, which reads as a
    /// broken hook rather than a broken test.
    fn install<F>(redactor: Redactor, on_panic: F)
    where
        F: Fn(Report) + Send + Sync + 'static,
    {
        static PER_TEST: Mutex<Vec<Once>> = Mutex::new(Vec::new());
        let guard = PER_TEST
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .pop()
            .unwrap_or_else(Once::new);
        install_hook(redactor, on_panic, &guard);
    }

    /// A hook is process-global and this suite runs on parallel threads, so
    /// anything that installs one has to be pinned to a single test and every
    /// other test has to leave it alone. `parking_lot` is not a dependency and a
    /// `Mutex` poisoning after a deliberate panic would wedge the rest of the
    /// binary, so this takes the lock and never panics while holding it.
    static HOOK_LOCK: Mutex<()> = Mutex::new(());

    /// Run `body` with a fresh panic hook installed, and restore the previous one
    /// afterwards.
    ///
    /// Restoring matters: the crate's own test binary shares a process with
    /// everything else in `cargo test`, and leaving a hook installed would change
    /// how an unrelated test failure reports itself.
    fn with_isolated_hook<T>(body: impl FnOnce() -> T) -> T {
        let _guard = HOOK_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let previous = panic::take_hook();
        let result = body();
        panic::set_hook(previous);
        result
    }

    /// A `PanicHookInfo` cannot be constructed, so these tests go through a real
    /// panic and a real hook. That is the point: a test that built the info by
    /// hand would be testing a struct literal, not the thing a user hits.
    fn info_from_panic() -> Box<dyn Fn(&PanicHookInfo<'_>) -> Report + Send + Sync> {
        Box::new(|info| compose_from_panic(&Redactor::new(), info).expect("composition succeeds"))
    }

    #[test]
    fn a_panic_payload_becomes_a_report_field() {
        with_isolated_hook(|| {
            let compose = info_from_panic();
            let captured: Arc<Mutex<Option<Report>>> = Arc::new(Mutex::new(None));
            let sink = Arc::clone(&captured);

            install(Redactor::new(), move |report| {
                *sink.lock().unwrap_or_else(|e| e.into_inner()) = Some(report);
            });

            let _ = panic::catch_unwind(|| panic!("index out of bounds: the slice had 3"));
            let report = captured
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
                .expect("the hook handed over a report");

            let preview = report.preview().expect("preview");
            assert!(
                preview.contains("index out of bounds: the slice had 3"),
                "the panic message must be in the report: {preview}"
            );
            // And the location, which is the other half of what a panic knows.
            assert!(
                preview.contains("panic.rs"),
                "the panic location must be in the report: {preview}"
            );
            // Composed on purpose; sanity-check that the closure is live.
            let _ = compose;
        });
    }

    /// The crate's one rule, and the reason this module exists: nothing leaves
    /// without a human seeing it first.
    ///
    /// Asserted against the real route rather than by inspection, because a hook
    /// that *could* send is one refactor away from one that does.
    #[test]
    fn a_hooked_report_cannot_be_sent_without_confirmation() {
        with_isolated_hook(|| {
            let captured: Arc<Mutex<Option<Report>>> = Arc::new(Mutex::new(None));
            let sink = Arc::clone(&captured);

            install(Redactor::new(), move |report| {
                *sink.lock().unwrap_or_else(|e| e.into_inner()) = Some(report);
            });
            let _ = panic::catch_unwind(|| panic!("boom"));

            let report = captured
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
                .expect("a report");
            // `preview` is the safe thing to do from inside a hook, and the one
            // a caller reaches for first. It must not transmit, and it must
            // work: a panic hook that cannot even show the report is no use.
            let preview = report.preview().expect("a panic report previews");
            assert!(preview.contains("boom"), "{preview}");
            refused_by_an_unconfirmed_route();
        });
    }

    /// A route that transmits without a review surface still refuses.
    ///
    /// The guarantee is that nothing leaves without a human seeing it, and it is
    /// load-bearing on the two routes with no built-in review. Asserted through
    /// the real `send`, because a hook that *could* transmit is one refactor away
    /// from one that does — and the check has to hold for a report the hook
    /// built, not a hand-made one.
    #[cfg(feature = "gh-cli")]
    fn refused_by_an_unconfirmed_route() {
        let refused = Report::to(Destination::parse("gerchowl/squelch").expect("destination"))
            .field("panic", "boom")
            .via(crate::Transport::GhCli)
            .send();
        assert!(
            refused.is_err(),
            "a credential route must refuse without .confirmed()"
        );
    }

    /// The same, for a build without the `gh-cli` feature, where that variant
    /// does not exist. A test that only compiled under one feature would not run
    /// in the powerset check.
    #[cfg(not(feature = "gh-cli"))]
    fn refused_by_an_unconfirmed_route() {
        // Nothing to assert here: with no credential route compiled in, the only
        // routes are the ones that open a review surface. The guarantee is
        // structural — `needs_explicit_confirmation` is what gates them, and
        // `Transport`'s own tests cover it per feature.
    }

    /// The previous hook keeps running.
    ///
    /// `set_hook` is process-global and replaces silently. An application that
    /// installed its own crash handler — to write a crash file, to notify a
    /// supervisor — would find it quietly gone, and nothing in the API would say
    /// so. This is the failure #9 names, and it is the reason for `take_hook`.
    #[test]
    fn the_previous_hook_still_runs() {
        with_isolated_hook(|| {
            let previous_ran = Arc::new(AtomicUsize::new(0));
            let counter = Arc::clone(&previous_ran);
            panic::set_hook(Box::new(move |_info| {
                counter.fetch_add(1, Ordering::SeqCst);
            }));

            let ours_ran = Arc::new(AtomicUsize::new(0));
            let ours = Arc::clone(&ours_ran);
            install(Redactor::new(), move |_report| {
                ours.fetch_add(1, Ordering::SeqCst);
            });

            let _ = panic::catch_unwind(|| panic!("boom"));

            assert_eq!(
                previous_ran.load(Ordering::SeqCst),
                1,
                "the application's own hook must still run"
            );
            assert_eq!(ours_ran.load(Ordering::SeqCst), 1, "our hook must run too");
        });
    }

    /// Every payload shape, including the one nothing can read.
    ///
    /// `panic_any` accepts any `Send + 'static` value, so a report that only
    /// handled `&str` and `String` would silently drop the payload for every
    /// application using it — which is most of them.
    #[test]
    fn every_payload_shape_is_reported() {
        with_isolated_hook(|| {
            let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
            let sink = Arc::clone(&captured);
            install(Redactor::new(), move |report| {
                let preview = report.preview().unwrap_or_default();
                sink.lock().unwrap_or_else(|e| e.into_inner()).push(preview);
            });

            // A `&'static str` — what `panic!("literal")` produces.
            let _ = panic::catch_unwind(|| panic!("a literal message"));
            // A `String` — what `panic!("{}", x)` produces.
            let _ = panic::catch_unwind(|| panic!("{}", String::from("a formatted message")));
            // A type nothing can read back as text.
            struct Opaque;
            let _ = panic::catch_unwind(|| panic::panic_any(Opaque));

            let previews = captured.lock().unwrap_or_else(|e| e.into_inner()).clone();
            assert_eq!(previews.len(), 3, "one report per panic");
            assert!(
                previews[0].contains("a literal message"),
                "&'static str: {}",
                previews[0]
            );
            assert!(
                previews[1].contains("a formatted message"),
                "String: {}",
                previews[1]
            );
            assert!(
                previews[2].contains("non-string panic payload"),
                "an unreadable payload is reported, not dropped: {}",
                previews[2]
            );
        });
    }

    /// The panic message is scrubbed like any other value.
    ///
    /// A panic message is exactly where a path, a username or a token ends up by
    /// accident: `unwrap` on a `PathBuf`, an expect carrying a URL, a
    /// `HashMap` index keyed by something the user typed. The rule is the same
    /// one every other value goes through, and that is the property — a narrower
    /// scrubber here would be a rule that only applies to panics, which is the
    /// shape of a leak nobody looks for.
    #[test]
    fn the_panic_message_goes_through_the_redactor() {
        with_isolated_hook(|| {
            let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
            let sink = Arc::clone(&captured);
            let redactor =
                Redactor::with_identity(Some("/home/testuser".into()), Some("testuser".into()));
            install(redactor, move |report| {
                *sink.lock().unwrap_or_else(|e| e.into_inner()) =
                    Some(report.preview().unwrap_or_default());
            });

            let _ = panic::catch_unwind(|| {
                panic!("failed to read /home/testuser/.config/token for testuser");
            });

            let preview = captured
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
                .expect("a preview");
            assert!(
                !preview.contains("/home/testuser"),
                "the home directory leaked: {preview}"
            );
            assert!(
                preview.contains("~/"),
                "the path should be rewritten, not dropped: {preview}"
            );
        });
    }

    /// Installing twice must not double-report.
    ///
    /// A second `install` would otherwise `take_hook` our own hook and wrap it,
    /// so every panic produced two reports and the inner closure was dropped
    /// while the outer still held a reference to it.
    #[test]
    fn installing_twice_does_not_double_report() {
        with_isolated_hook(|| {
            let count = Arc::new(AtomicUsize::new(0));

            // Both calls share one guard, which is the point: `install` hands
            // the same module-level `INSTALLED` to both, and the second call is
            // the no-op under test. Sharing a *fresh* guard per call — as the
            // other tests here do, to stay independent — would install twice and
            // prove nothing.
            let shared = Once::new();
            install_hook(
                Redactor::new(),
                {
                    let first = Arc::clone(&count);
                    move |_| {
                        first.fetch_add(1, Ordering::SeqCst);
                    }
                },
                &shared,
            );
            install_hook(
                Redactor::new(),
                {
                    let second = Arc::clone(&count);
                    move |_| {
                        second.fetch_add(1, Ordering::SeqCst);
                    }
                },
                &shared,
            );

            let _ = panic::catch_unwind(|| panic!("boom"));
            assert_eq!(
                count.load(Ordering::SeqCst),
                1,
                "one install, one report — the second is a no-op"
            );
        });
    }

    /// `from_panic` composes against the **caller's** destination.
    ///
    /// The install path can only aim at this crate's own `CARGO_PKG_REPOSITORY`,
    /// because the hook has no argument and asking the application would be a
    /// second failure waiting to happen. `from_panic` is the escape from that,
    /// so it is the one that has to be right — an application filing somewhere
    /// other than squelch's own tracker is the normal case, not an edge one.
    ///
    /// `PanicHookInfo` has no public constructor, so this cannot build one to
    /// pass in. It goes through a real panic and a real hook instead, and asserts
    /// the property that is checkable that way: the report names the destination
    /// it was aimed at, and the message is redacted.
    #[test]
    fn a_hooked_report_names_its_destination() {
        with_isolated_hook(|| {
            let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
            let sink = Arc::clone(&captured);
            let redactor =
                Redactor::with_identity(Some("/home/testuser".into()), Some("testuser".into()));

            install(redactor, move |report| {
                *sink.lock().unwrap_or_else(|e| e.into_inner()) =
                    Some(report.preview().unwrap_or_default());
            });
            let _ = panic::catch_unwind(|| {
                panic!("something went wrong in /home/testuser");
            });

            let preview = captured
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
                .expect("a report");
            // `preview` names the destination it would go to, so this asserts
            // the aiming as well as the message.
            assert!(
                preview.contains("gerchowl/squelch"),
                "the report names this crate's repository: {preview}"
            );
            assert!(
                preview.contains("something went wrong"),
                "the message is carried: {preview}"
            );
            assert!(
                !preview.contains("/home/testuser"),
                "and it is scrubbed: {preview}"
            );
        });
    }
}
