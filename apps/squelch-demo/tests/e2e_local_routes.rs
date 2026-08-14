//! The two routes whose receiver is the reporter themselves: `File` and
//! `Mailto`. No shim needed — the artefact *is* the payload.
//!
//! Also covers the surface every route shares: the preview, which is the
//! crate's central promise that what you are shown is what would leave.

mod common;

use common::{
    assert_nothing_leaked, assert_still_diagnostic, canary_log_file, run_demo, scratch,
    CANARY_WORKDIR,
};

fn compose(dir: &std::path::Path, route: &[&str]) -> (bool, String, String) {
    let log = canary_log_file(dir);
    let mut args = vec![
        "--log".to_string(),
        log.to_str().unwrap().to_string(),
        "--workdir".to_string(),
        CANARY_WORKDIR.to_string(),
    ];
    args.extend(route.iter().map(|s| s.to_string()));
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    run_demo(&borrowed)
}

#[test]
fn the_written_file_carries_no_canary_and_stays_diagnostic() {
    let dir = scratch("file");
    let out = dir.join("report.md");

    let (ok, stdout, stderr) = compose(&dir, &["file", out.to_str().unwrap()]);
    assert!(ok, "file route failed: stdout={stdout} stderr={stderr}");

    let written = std::fs::read_to_string(&out).expect("the report was not written");
    assert_nothing_leaked("the written file", &written);
    assert_still_diagnostic("the written file", &written);
    assert!(
        written.contains("every git operation fails"),
        "the reporter's own words must survive verbatim: {written}"
    );
}

#[test]
fn the_mailto_url_carries_the_report_and_no_canary() {
    let dir = scratch("mailto");

    let (ok, stdout, stderr) = compose(&dir, &["mailto", "bugs@example.com"]);
    assert!(ok, "mailto route failed: stderr={stderr}");
    assert!(
        stdout.contains("mailto:bugs@example.com"),
        "the mail draft must be addressed: {stdout}"
    );

    // Percent-encoding is not redaction: decode before asserting, or a leaked
    // `/home/alice` hides behind `%2Fhome%2Falice` and the test passes.
    let decoded = percent_decode(&stdout);
    assert_nothing_leaked("the mailto URL", &decoded);

    // The leak assertion above passes trivially on an EMPTY draft, and for a
    // while that is exactly what this route produced. A route that carries
    // nothing leaks nothing. Assert presence first, or the absence assertion
    // is measuring a route that does not work.
    assert!(
        decoded.contains("every git operation fails"),
        "the reporter's own words must reach the mail draft: {decoded}"
    );
    assert_still_diagnostic("the mailto URL", &decoded);
}

#[test]
fn the_preview_shows_what_would_leave_and_sends_nothing() {
    let dir = scratch("preview");

    let (ok, stdout, stderr) = compose(&dir, &["preview"]);
    assert!(ok, "preview failed: {stderr}");

    assert!(
        stdout.contains("destination: gerchowl/squelch"),
        "the preview must name where this is going: {stdout}"
    );
    assert_nothing_leaked("the preview", &stdout);
    assert_still_diagnostic("the preview", &stdout);
}

#[test]
fn a_report_missing_a_required_field_is_refused_before_anything_opens() {
    let dir = scratch("required");
    let log = canary_log_file(&dir);

    let (ok, _, stderr) = run_demo(&[
        "--log",
        log.to_str().unwrap(),
        "--repro",
        "   ",
        "file",
        dir.join("never.md").to_str().unwrap(),
    ]);
    assert!(!ok, "a blank required field must refuse the build");
    assert!(
        stderr.contains("reproduction"),
        "the refusal must name the missing field: {stderr}"
    );
    assert!(
        !dir.join("never.md").exists(),
        "nothing may be written when the report was refused"
    );
}

#[test]
fn a_hostile_mail_address_cannot_start_its_own_query() {
    // Spliced raw, the FIRST `?` in the URL belonged to the address, so a mail
    // client splitting there prefills the attacker's body and the report is
    // silently discarded.
    let dir = scratch("mailto-inject");
    let (ok, stdout, _) = compose(&dir, &["mailto", "bugs@example.com?body=fake&x=y"]);
    assert!(ok);
    let after_scheme = stdout.split("mailto:").nth(1).expect("a mailto url").trim();
    let first_query = after_scheme.find('?').expect("a query separator");
    let address = &after_scheme[..first_query];
    assert!(
        !address.contains("body=fake"),
        "the address carried its own query: {address}"
    );
    assert!(
        after_scheme[first_query..].starts_with("?subject="),
        "the first query component must be ours: {after_scheme}"
    );
}

/// Minimal `%XX` decoder — enough to unmask a leak hiding behind encoding.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&input[i + 1..i + 3], 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
