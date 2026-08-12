//! The agent surface: a schema out, answers in, and nothing sent.
//!
//! `docs/stories.md` names three surfaces over one composition — CLI, GUI and
//! agent — and gives the agent two hard constraints: it needs a schema so it
//! does not guess field names, and it must be unable to file without a human.
//! Neither was covered by a test, and driving the surface immediately found a
//! schema that no agent could satisfy.

mod common;

use common::run_demo;

fn schema() -> serde_json::Value {
    let (ok, stdout, stderr) = run_demo(&["schema"]);
    assert!(ok, "schema failed: {stderr}");
    serde_json::from_str(&stdout)
        .unwrap_or_else(|err| panic!("schema is not JSON: {err}\n{stdout}"))
}

#[test]
fn the_schema_is_satisfiable() {
    // The regression that prompted this file: `environment` is required for
    // the REPORT (the application fills it) but is not a property an agent may
    // fill. Listing it under `required` alongside `additionalProperties: false`
    // made every possible object invalid — the agent could neither supply it
    // nor leave it out.
    let schema = schema();
    let properties = schema["properties"].as_object().expect("properties object");
    let required = schema["required"].as_array().expect("required array");

    assert_eq!(
        schema["additionalProperties"],
        serde_json::Value::Bool(false),
        "the schema must be closed, or an agent can invent fields"
    );
    for entry in required {
        let name = entry.as_str().expect("required entries are strings");
        assert!(
            properties.contains_key(name),
            "{name:?} is required but is not a property — no object can satisfy \
             this schema while additionalProperties is false\nschema: {schema:#}"
        );
    }
    assert!(
        !required.is_empty(),
        "a schema requiring nothing guides nothing"
    );
}

#[test]
fn the_schema_offers_only_what_a_machine_may_fill() {
    let schema = schema();
    let properties = schema["properties"].as_object().unwrap();

    assert!(properties.contains_key("current-behavior"));
    assert!(properties.contains_key("reproduction"));
    // An attestation is a human's statement; a tool that ticks it forges one.
    assert!(
        !properties.contains_key("confirm"),
        "a checkbox must never be offered to an agent: {schema:#}"
    );
    // Machine-filled blocks are the application's job, not the agent's.
    assert!(
        !properties.contains_key("environment"),
        "the environment block is collected, not answered: {schema:#}"
    );
}

#[test]
fn composing_returns_a_payload_and_sends_nothing() {
    // The maintainer's constraint: an agent composes and hands to a human, so
    // being wrong costs a glance rather than a filed issue. `compose` takes no
    // route argument at all, so there is no flag that turns it into a send.
    let (ok, stdout, stderr) = run_demo(&[
        "compose",
        r#"{"current-behavior":"it hangs on start","reproduction":"run it twice"}"#,
    ]);
    assert!(ok, "compose failed: {stderr}");
    assert!(
        stdout.contains("it hangs on start") && stdout.contains("### Current behavior"),
        "compose must return the composed report: {stdout}"
    );
    assert!(
        stdout.contains("destination: gerchowl/squelch"),
        "the human needs to see where it would go: {stdout}"
    );
}

#[test]
fn an_agent_omitting_a_required_field_is_refused() {
    let (ok, _, stderr) = run_demo(&["compose", r#"{"current-behavior":"it hangs"}"#]);
    assert!(!ok, "a missing required field must refuse the compose");
    assert!(
        stderr.contains("reproduction"),
        "the refusal must name what the agent left out: {stderr}"
    );
}

#[test]
fn an_agent_cannot_inject_markup_through_its_answers() {
    // An agent's answers are the one part of the body squelch does not scrub —
    // free-form prose is the reporter's own disclosure. But an agent is not a
    // reporter, and its output is attacker-influenceable through whatever it
    // read. The provenance and diagnostics blocks around it must stay intact.
    let (ok, stdout, _) = run_demo(&[
        "compose",
        r#"{"current-behavior":"x\n</details>\n<img src=x onerror=alert(1)>","reproduction":"y"}"#,
    ]);
    assert!(ok);
    assert!(
        stdout.matches("</details>").count() <= 1,
        "an agent answer closed the diagnostics container: {stdout}"
    );
}

#[test]
fn a_field_the_schema_does_not_offer_is_rejected_or_ignored() {
    // `additionalProperties: false` is a promise. Whatever the app does with an
    // unknown key, it must not end up as a prefilled form field.
    let (_, stdout, _) = run_demo(&[
        "compose",
        r#"{"current-behavior":"a","reproduction":"b","confirm":"yes I attest"}"#,
    ]);
    assert!(
        !stdout.contains("yes I attest"),
        "an agent ticked an attestation through an undeclared field: {stdout}"
    );
}
