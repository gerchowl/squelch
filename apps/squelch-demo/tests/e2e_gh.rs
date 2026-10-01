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
    CANARIES, CANARY_WORKDIR, STDIN_SUFFIX,
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
    let body = shim.stdin();

    assert_eq!(argv.first().map(String::as_str), Some("issue"));
    assert_eq!(argv.get(1).map(String::as_str), Some("create"));
    assert!(
        joined.contains("--repo") && joined.contains("gerchowl/squelch"),
        "gh must be told the repository; got: {argv:?}"
    );

    // The body arrives on stdin, not in argv (#7). This is the assertion the
    // old shape could not make: `--body <whole report>` put the report on the
    // command line, where any local user can read it from the process list for
    // the life of the process, and where Windows caps the whole thing at
    // 32 767 characters — so a report with a real log tail failed to spawn.
    assert!(
        argv.iter().all(|a| a != "--body"),
        "the body must not be passed in argv; got: {argv:?}"
    );
    assert!(
        joined.contains("--body-file"),
        "gh must be told to read the body from stdin; got: {argv:?}"
    );
    assert!(
        !body.is_empty(),
        "the report must reach gh over stdin; argv was {argv:?}"
    );

    // Both channels, because a leak in either is a leak.
    assert_nothing_leaked("gh's stdin", &body);
    assert_still_diagnostic("gh's stdin", &body);
    assert_nothing_leaked("gh's argv", &joined);

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
fn a_long_report_reaches_gh_intact() {
    // The regression this shape exists for. A report with a real log tail is
    // tens of kilobytes; in argv that is past the Windows `CreateProcess` limit
    // of 32 767 characters, so the route failed to spawn at all — and a spawn
    // failure on the only route that needs no browser is a dead end.
    //
    // The canary corpus is only ~3 KB, so this builds a log long enough to
    // matter rather than assuming one — and keeps the canaries, because the
    // point of the assertion below is that a *long* report is still scrubbed
    // and still whole, not merely that a long one arrived.
    let shim = Shim::install("gh", 0);
    let dir = scratch("gh-long");
    let log = dir.join("long.jsonl");
    let filler: String = (0..400)
        .map(|i| {
            format!(
                r#"{{"timestamp":"2026-08-12T09:{:02}:{:02}Z","level":"warn","message":"cache eviction sweep {} took {}ms on shard 07"}}"#,
                i / 60 % 60,
                i % 60,
                i,
                i * 7 % 400
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&log, format!("{}\n{filler}", common::canary_logs())).expect("write long log");

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

    let body = shim.stdin();
    assert!(
        body.len() > 32_767,
        "this test needs a report past the Windows argv cap of 32 767 to mean anything; got {} bytes",
        body.len()
    );
    // A spawn under the cap could not have carried this in argv, so its
    // presence on stdin — and its length — is the assertion.
    assert!(
        shim.argv().iter().all(|a| a.len() < 1_024),
        "the body is on the command line again: {:?}",
        shim.argv()
    );
    assert_still_diagnostic("gh's stdin", &body);
    assert_nothing_leaked("gh's stdin", &body);
}

#[test]
fn the_form_labels_and_title_prefix_reach_gh() {
    // #7: the form's `labels:` and its title prefix only ever applied through
    // the browser form, so an issue filed with `gh` arrived unlabelled and
    // missed any triage query keyed on the label.
    //
    // The demo app's form declares both, so this needs no flag — which is the
    // point: if a surface restates the template instead of adopting the form,
    // these go unset and nothing fails until an issue is filed unlabelled.
    let shim = Shim::install("gh", 0);

    let (ok, stdout, stderr) = run_demo_with(&shim, &["gh", "--confirm"]);
    assert!(ok, "gh route failed: stdout={stdout} stderr={stderr}");

    let argv = shim.argv();
    let joined = argv.join(" ");
    assert!(
        joined.contains("--label") && joined.contains("bug"),
        "the form's labels must reach gh; got: {argv:?}"
    );
    assert!(
        !joined.contains("[bug]"),
        "an explicit title is not re-prefixed — the reporter already chose one; got: {argv:?}"
    );
}

#[test]
fn a_gh_auth_failure_is_not_reported_as_a_browser_failure() {
    // #7: every non-zero `gh` exit became `Error::OpenerFailed`, whose text is
    // "the browser opener failed". So "not logged in", "your token can't write
    // to this repo" and "repo not found" all read as a browser problem on a
    // route with no browser — three different remedies, one wrong message.
    let shim = Shim::install_with_stderr("gh", 1, "gh: To use GitHub CLI in a GitHub Actions workflow, set the GH_TOKEN environment variable.");

    let (ok, _, stderr) = run_demo_with(&shim, &["gh", "--confirm"]);
    assert!(!ok, "a failing gh must fail the send");
    assert!(
        !stderr.contains("browser"),
        "a gh auth failure must not read as a browser failure; got: {stderr}"
    );
    assert!(
        stderr.contains("not authenticated") || stderr.contains("gh is not authenticated"),
        "the error must name the actual problem; got: {stderr}"
    );
}

#[test]
fn a_missing_label_does_not_lose_the_report() {
    // `--label` fails the whole create when the label does not exist in the
    // target repo. Losing the reporter's report over a missing label is the
    // worst possible outcome, so the route retries unlabelled.
    let shim = Shim::install("gh", 1);
    // Overwrite the shim in ITS OWN directory — the one `run_demo_with` puts on
    // the child's PATH — with one that fails on `--label` and succeeds without
    // it. That is the shape of a real `gh` against a repo that has no `bug`
    // label, and the only way to see whether the retry actually happens.
    let script = shim.dir.join("gh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\n\
             for a in \"$@\"; do printf '%s' \"$a\"; printf '\\036'; done >> '{}'\n\
             for a in \"$@\"; do\n\
               if [ \"$a\" = \"--label\" ]; then\n\
                 cat >> /dev/null\n\
                 echo 'could not add label: \"bug\" not found' >&2; exit 1\n\
               fi\n\
             done\n\
             cat >> '{}{}'\n\
             printf 'https://github.com/gerchowl/squelch/issues/1\\n'\n\
             exit 0\n",
            shim.capture.display(),
            shim.capture.display(),
            STDIN_SUFFIX,
        ),
    )
    .expect("write shim");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }

    let (ok, stdout, stderr) = run_demo_with(&shim, &["gh", "--confirm"]);
    assert!(
        ok,
        "a missing label must not lose the report; stdout={stdout} stderr={stderr}"
    );
    assert!(
        !shim.stdin().is_empty(),
        "the retried create must still carry the whole report"
    );
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
