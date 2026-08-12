//! `Transport::Endpoint`, end to end against a real HTTP server.
//!
//! The endpoint route is the one that transmits with no review surface of its
//! own and no human at the far end, so it is the route where a leak would be
//! least likely to be noticed. Nothing exercised it before this file: the unit
//! tests stop at `Report::build`.

mod common;

use common::{
    assert_nothing_leaked, assert_still_diagnostic, canary_log_file, run_demo, scratch, Receiver,
    CANARY_WORKDIR,
};

#[test]
fn the_posted_body_carries_no_canary_and_stays_diagnostic() {
    let dir = scratch("endpoint");
    let log = canary_log_file(&dir);
    let receiver = Receiver::spawn();

    let (ok, stdout, stderr) = run_demo(&[
        "--log",
        log.to_str().unwrap(),
        "--workdir",
        CANARY_WORKDIR,
        "endpoint",
        &receiver.url,
        "--confirm",
    ]);
    assert!(ok, "send failed: stdout={stdout} stderr={stderr}");

    let received = receiver.received();
    assert_eq!(received.method, "POST");
    assert_eq!(
        received.header("content-type"),
        Some("application/json"),
        "headers: {:?}",
        received.headers
    );

    // The whole request, headers included — a credential or a hostname in a
    // header leaks exactly as thoroughly as one in the body.
    let whole = format!("{:?}\n{}", received.headers, received.body);
    assert_nothing_leaked("the endpoint", &whole);
    assert_still_diagnostic("the endpoint", &received.body);

    // The report itself must actually have arrived — a receiver that got an
    // empty body would pass every assertion above.
    assert!(
        received.body.contains("current-behavior") || received.body.contains("Current behavior"),
        "the endpoint got no report body: {}",
        received.body
    );
    assert!(
        received.body.contains("gerchowl/squelch"),
        "the endpoint was not told which repository: {}",
        received.body
    );
}

#[test]
fn a_bearer_token_reaches_the_endpoint_and_nothing_else_does() {
    let receiver = Receiver::spawn();

    let (ok, _, stderr) = run_demo(&[
        "endpoint",
        &receiver.url,
        "--confirm",
        "--token",
        "endpoint-token-abc",
    ]);
    assert!(ok, "send failed: {stderr}");

    let received = receiver.received();
    assert_eq!(
        received.header("authorization"),
        Some("Bearer endpoint-token-abc"),
        "the embedder's own credential must reach their own endpoint"
    );
}

#[test]
fn the_endpoint_route_refuses_without_confirmation() {
    // No receiver is spawned on purpose: if the refusal regressed, this test
    // would hang or fail on a connection rather than passing quietly.
    let (ok, stdout, stderr) = run_demo(&["endpoint", "http://127.0.0.1:1/reports"]);
    assert!(!ok, "unconfirmed endpoint send must fail; stdout={stdout}");
    assert!(
        stderr.contains("confirm"),
        "the refusal must say what is missing; got: {stderr}"
    );
}
