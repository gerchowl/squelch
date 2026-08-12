//! `Transport::GhCli`, end to end against a fake `gh` on `PATH`.
//!
//! # Why a fake binary rather than a mocked GitHub API
//!
//! squelch never speaks to `api.github.com` on this route. It spawns `gh`, and
//! `gh` reads its own credential store and makes the request — which is the
//! crate's headline claim: the token never enters this process. Mocking the
//! GitHub API would test `gh`, not squelch.
//!
//! A stand-in binary that records its argv tests the claim directly, because
//! the argv *is* the entire interface squelch has to the outside world here.

mod common;

use common::{
    assert_nothing_leaked, assert_still_diagnostic, canary_log_file, run_demo_with, scratch, Shim,
    CANARIES, CANARY_WORKDIR,
};

#[test]
fn gh_is_invoked_with_a_clean_body_and_never_a_credential() {
    let shim = Shim::install("gh", 0);
    let dir = scratch("gh");
    let log = canary_log_file(&dir);

    let (ok, stdout, stderr) = run_demo_with(
        &shim,
        &[
            "--log",
            log.to_str().unwrap(),
            "--workdir",
            CANARY_WORKDIR,
            "gh",
            "--confirm",
        ],
    );
    assert!(ok, "gh route failed: stdout={stdout} stderr={stderr}");
    assert!(shim.was_called(), "gh was never invoked");

    let argv = shim.argv();
    let joined = argv.join(" ");

    assert_eq!(argv.first().map(String::as_str), Some("issue"));
    assert_eq!(argv.get(1).map(String::as_str), Some("create"));
    assert!(
        joined.contains("--repo") && joined.contains("gerchowl/squelch"),
        "gh must be told the repository; got: {argv:?}"
    );

    assert_nothing_leaked("gh's argv", &joined);
    assert_still_diagnostic("gh's argv", &joined);

    // The crate must not hand `gh` a credential: `gh` has its own. A token
    // flag appearing here would mean squelch had started carrying one.
    for forbidden in ["--token", "GH_TOKEN", "GITHUB_TOKEN", "ghp_"] {
        assert!(
            !joined.contains(forbidden),
            "squelch passed {forbidden:?} to gh — it must carry no credential; got: {argv:?}"
        );
    }
}

#[test]
fn a_failing_gh_is_reported_rather_than_swallowed() {
    // A route that reports success when the issue was never created is worse
    // than one that fails: the reporter walks away believing they filed.
    let shim = Shim::install("gh", 1);

    let (ok, stdout, stderr) = run_demo_with(&shim, &["gh", "--confirm"]);
    assert!(shim.was_called(), "gh was never invoked");
    assert!(
        !ok,
        "a non-zero gh must fail the send; stdout={stdout} stderr={stderr}"
    );
}

#[test]
fn the_gh_route_refuses_without_confirmation() {
    let shim = Shim::install("gh", 0);

    let (ok, _, stderr) = run_demo_with(&shim, &["gh"]);
    assert!(!ok, "unconfirmed gh send must fail");
    assert!(
        !shim.was_called(),
        "gh must not be spawned at all before confirmation"
    );
    assert!(
        stderr.contains("confirm"),
        "the refusal must say what is missing; got: {stderr}"
    );
}

#[test]
fn the_canary_corpus_is_actually_dangerous() {
    // A corpus whose canaries were never present would make every
    // assert_nothing_leaked above vacuous. Pin that the raw material really
    // does contain each one.
    let raw = format!("{}{}", common::canary_logs(), CANARY_WORKDIR);
    for (label, needle) in CANARIES {
        assert!(
            raw.contains(needle),
            "canary {label:?} is not in the corpus — the leak tests prove nothing"
        );
    }
}
