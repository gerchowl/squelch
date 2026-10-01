//! The panic hook, end to end, against a process that actually dies.
//!
//! # Why a subprocess
//!
//! Two of the properties that matter here cannot be observed from inside the
//! test binary:
//!
//! - **A panic inside a panic hook aborts the process.** That is `std`'s
//!   behaviour, not this crate's, but it means the test would take itself down
//!   before it could assert. Running the demo as a child is the only way to see
//!   what reaches stderr and what the exit status is.
//! - **The guarantee is about what leaves the machine.** A hook that printed a
//!   report and also opened a browser would look identical from the inside. The
//!   assertion has to be on the far side of a process boundary — which is what
//!   every other route in this suite already does, and the same reasoning
//!   `docs/testing.md` gives for the fake receivers.
//!
//! The shim-based routes assert on a captured payload. This one asserts on a
//! *non*-payload: that no opener ran, that no `gh` ran, and that the process
//! died the way a panicking process dies rather than the way a reporting one
//! would.

mod common;

use common::{assert_nothing_leaked, run_demo, Shim, CANARY_WORKDIR};

/// The markers the demo prints around the composed report.
///
/// A printed block is the observable here, so its boundaries have to be
/// unambiguous: a bare `panic` message could contain either of these strings, and
/// a test that matched on a substring would pass for the wrong reason.
const BEGIN: &str = "--- squelch: report composed from the panic ---";
const END: &str = "--- end of composed report ---";

/// Pull the composed report out of the child's stderr, or `None` if it never
/// printed one.
fn composed_report(stderr: &str) -> Option<String> {
    let start = stderr.find(BEGIN)? + BEGIN.len();
    let rest = &stderr[start..];
    let end = rest.find(END)?;
    Some(rest[..end].to_string())
}

#[test]
fn a_crash_composes_a_report_and_sends_nothing() {
    // Both shims present so a send would be visible whichever route it took.
    let opener = Shim::install("open", 0);
    let gh = Shim::install("gh", 0);

    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_squelch-demo"));
    command.args([
        "panic",
        "--message",
        "cache eviction failed for /home/alice/work/acme-private",
    ]);
    command.env(
        "PATH",
        format!("{}:{}", opener.dir.display(), gh.dir.display()),
    );
    let output = command.output().expect("run squelch-demo panic");
    let stderr = String::from_utf8_lossy(&output.stderr);

    // The process died, which is the point: this is a crash, not a handled
    // error. A non-zero status is the contract; the report is the addition.
    assert!(
        !output.status.success(),
        "a panicking process must not exit successfully"
    );

    // A report was composed, and it says what broke and where.
    let report = composed_report(&stderr).unwrap_or_else(|| {
        panic!("no report was composed. stderr:\n{stderr}");
    });
    assert!(
        report.contains("cache eviction failed"),
        "the panic message must be in the report:\n{report}"
    );
    assert!(
        report.contains("panic-location") && report.contains("main.rs"),
        "the location must be in the report:\n{report}"
    );

    // Composed AND scrubbed. A panic message is where a path ends up by
    // accident, so this is the same rule every other value goes through.
    assert!(
        !report.contains("/home/alice"),
        "the home directory leaked into a panic report:\n{report}"
    );
    assert!(
        report.contains("### environment"),
        "a crash report with no environment block is half a report:\n{report}"
    );

    // **Nothing was sent.** The crate's one rule, and the reason the hook
    // composes rather than transmits. A reporter has approved nothing here, and
    // the process is already failing — opening a browser from a panic hook is
    // how a bug report becomes the reason a bug is unreportable.
    assert!(
        !opener.was_called(),
        "the hook opened a browser; a panic must never transmit"
    );
    assert!(
        !gh.was_called(),
        "the hook invoked gh; a panic must never transmit"
    );

    // And the previous hook still ran: the original panic message reached the
    // terminal, which is the one thing a user cannot afford to lose.
    assert!(
        stderr.contains("panicked at"),
        "the default hook must still print the panic:\n{stderr}"
    );
}

#[test]
fn a_crash_sends_nothing_even_when_a_browser_route_would() {
    // The first test proves no shim ran. This one proves the *default* would
    // have, so the assertion above is about the hook and not about a route that
    // happens to be unavailable — a browser is present in a real reporter's
    // environment, and `Transport::Browser` is the default.
    let (ok, stdout, _) = run_demo(&["preview"]);
    assert!(ok, "the browser route is the default and must be reachable");
    assert!(
        stdout.contains("destination:") || stdout.contains("gerchowl/squelch"),
        "sanity: the preview names a destination: {stdout}"
    );
}

#[test]
fn a_panicking_callback_still_lets_the_original_message_through() {
    // A panic inside a panic hook aborts the process. The assertion is on what
    // survived that: the *original* message, printed by the previous hook, must
    // still be on stderr. A crash reporter that swallows the crash it was
    // reporting is worse than no crash reporter.
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_squelch-demo"))
        .args([
            "panic",
            "--message",
            "the original failure",
            "--callback-panics",
        ])
        .output()
        .expect("run squelch-demo panic --callback-panics");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "a panicking process must not exit successfully"
    );
    assert!(
        stderr.contains("the original failure"),
        "the original panic message must survive a panicking callback:\n{stderr}"
    );
    // The report is NOT printed, and that is the correct outcome rather than a
    // gap: the previous hook runs first precisely so this message reaches the
    // terminal, and the application's callback — which is what prints the report
    // — then aborts the process before it gets there.
    //
    // So the trade is explicit: the crash is never swallowed, and a callback
    // that itself fails costs you the report. Composing *before* the previous
    // hook reverses it, and loses the original message instead — which the same
    // test caught when the order was the other way round.
    assert!(
        composed_report(&stderr).is_none(),
        "a panicking callback cannot deliver the report:\n{stderr}"
    );
}

#[test]
fn a_crash_report_carries_no_canary() {
    // The corpus check, applied to the panic path. Provenance is the interesting
    // part: a panic in a service environment is exactly where `HOME` and `USER`
    // are stripped, which is when the redactor falls back to `getpwuid`.
    let log = common::scratch("panic-canary");
    let _ = std::fs::create_dir_all(&log);
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_squelch-demo"))
        .args([
            "panic",
            "--message",
            "failed reading the credential for alice@example.com",
        ])
        .env("WORKDIR", CANARY_WORKDIR)
        .output()
        .expect("run squelch-demo panic");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let report = composed_report(&stderr).expect("a report was composed");
    assert_nothing_leaked("the panic report", &report);
}
