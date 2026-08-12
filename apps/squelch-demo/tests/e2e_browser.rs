//! `Transport::Browser`, end to end against a fake platform opener.
//!
//! This route is the default, so it is the one most consumers ship — and it
//! was the least testable, because exercising it meant launching a browser.
//! squelch spawns the platform opener (`open` on macOS, `xdg-open` elsewhere),
//! which makes it a `PATH` shim like any other.
//!
//! The assertion that matters here is not that the URL is well formed. It is
//! that the URL carries **no diagnostics** — GitHub records full request URLs
//! server-side, so anything in the query string is disclosed the moment the
//! browser opens, before the reporter has decided whether to submit. That is a
//! promise the README makes in prose and nothing enforced.

mod common;

use common::{
    assert_nothing_leaked, canary_log_file, run_demo, run_demo_with, scratch, Shim, BROWSER_OPENER,
    CANARY_WORKDIR,
};

#[test]
fn the_opened_url_carries_no_diagnostics_and_no_canary() {
    let shim = Shim::install(BROWSER_OPENER, 0);
    let dir = scratch("browser");
    let log = canary_log_file(&dir);

    let (ok, stdout, stderr) = run_demo_with(
        &shim,
        &[
            "--log",
            log.to_str().unwrap(),
            "--workdir",
            CANARY_WORKDIR,
            "browser",
        ],
    );
    assert!(ok, "browser route failed: stdout={stdout} stderr={stderr}");
    assert!(shim.was_called(), "the platform opener was never invoked");

    let argv = shim.argv();
    let url = argv
        .iter()
        .find(|a| a.starts_with("https://"))
        .unwrap_or_else(|| panic!("no URL in the opener's argv: {argv:?}"));

    assert!(
        url.contains("github.com/gerchowl/squelch/issues/new"),
        "the opener got the wrong destination: {url}"
    );
    assert!(
        url.contains("template=bug.yml"),
        "the form template must be selected, or the chooser opens instead: {url}"
    );

    assert_nothing_leaked("the browser URL", url);

    // The log block must not be in the URL at all — not redacted into it,
    // simply absent. `os error 2` survives redaction and appears in the body,
    // so its presence here would mean the diagnostics block had been placed
    // in the query string.
    assert!(
        !url.contains("os+error") && !url.contains("os%20error") && !url.contains("os error"),
        "the diagnostics block reached the URL, which GitHub logs server-side \
         before the reporter submits: {url}"
    );

    // macOS's `open` is passed `--` so a URL can never be read as an option.
    #[cfg(target_os = "macos")]
    assert_eq!(
        argv.first().map(String::as_str),
        Some("--"),
        "the opener must be given `--` before the URL: {argv:?}"
    );
}

#[test]
fn the_browser_route_needs_no_confirmation() {
    // GitHub's own form is the review surface, and the reporter still clicks
    // Submit there — so unlike gh and endpoint, this route sends unprompted.
    let shim = Shim::install(BROWSER_OPENER, 0);

    let (ok, _, stderr) = run_demo_with(&shim, &["browser"]);
    assert!(ok, "the default route must work unconfirmed: {stderr}");
    assert!(shim.was_called(), "the opener was never invoked");
}

#[test]
fn the_browser_route_refuses_rather_than_open_a_form_missing_a_section() {
    // End-to-end version of the contract this crate is named for: the reporter
    // approves a preview showing every section, so opening a form that silently
    // lacks one means they consented to something that never arrived — and the
    // maintainer closes an issue whose Reproduction section is blank.
    let shim = Shim::install(BROWSER_OPENER, 0);
    let huge = "x".repeat(40_000);

    let (ok, stdout, stderr) = run_demo_with(
        &shim,
        &["--current", &huge, "--repro", "run it twice", "browser"],
    );
    assert!(!ok, "the browser route must refuse: stdout={stdout}");
    assert!(
        !shim.was_called(),
        "no browser may be opened for a report that cannot be carried whole"
    );
    assert!(
        stderr.contains("reproduction"),
        "the refusal must name the section that would be missing: {stderr}"
    );
}

#[test]
fn a_route_that_carries_the_whole_report_is_unaffected() {
    // The report is fine; it is the URL that cannot hold it. Refusing the
    // browser must not make the report unfileable.
    let dir = common::scratch("oversized-file");
    let out = dir.join("report.md");
    let huge = "x".repeat(40_000);

    let (ok, _, stderr) = run_demo(&[
        "--current",
        &huge,
        "--repro",
        "run it twice",
        "file",
        out.to_str().unwrap(),
    ]);
    assert!(ok, "the file route must still work: {stderr}");
    let written = std::fs::read_to_string(&out).expect("report written");
    assert!(
        written.contains("run it twice"),
        "the whole report must reach the file"
    );
}
