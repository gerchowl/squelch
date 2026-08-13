//! Markup injection: can a value read as markdown rather than as text?
//!
//! The README claims values "can't escape the markdown block", and names the
//! `bugreport` crate for getting this wrong. Two paths were open when these
//! tests were written, both found by driving the app rather than the library:
//!
//! 1. `Record::render` emitted `timestamp`, `level` and `source` raw — only
//!    field *values* were escaped, and only on the JSONL path. A log line whose
//!    timestamp carried a newline and a fence broke out of the block.
//! 2. `Provenance::to_markdown` rendered `- Label: value` with no escaping at
//!    all. That one is not even inside a fence, so an `<img src=x onerror=…>`
//!    was live HTML on sight.
//!
//! Both are fixed at the render choke points. These tests exist so they stay
//! fixed, and they assert on the report body a receiver would actually get.

mod common;

use common::{run_demo, scratch};

/// A payload that is hostile in every direction at once.
const HOSTILE: &str = "x\n```\n</details>\n<img src=x onerror=alert(1)>\n## heading\n~~~\n";

/// The diagnostics block must contain exactly one fence pair: the one
/// `render_block` opened and closed. Any third occurrence means a value broke
/// out, which is the whole failure mode.
fn assert_fence_intact(what: &str, body: &str) {
    let fences = body.matches("```").count();
    assert_eq!(
        fences, 2,
        "{what}: expected exactly one ```-fence pair, found {fences} — a value \
         escaped the block\n--- body ---\n{body}"
    );
}

/// Everything outside a fenced block. Inside one, markup is literal and inert —
/// the property that matters there is fence integrity, which
/// [`assert_fence_intact`] covers. Demanding escaped HTML inside the fence too
/// would be over-masking: the block has to stay readable to a triager.
fn outside_fences(body: &str) -> String {
    let mut out = String::new();
    let mut inside = false;
    for line in body.lines() {
        if line.trim_start().starts_with("```") {
            inside = !inside;
            continue;
        }
        if !inside {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// No raw HTML tag may reach the parts of the body that render as markdown.
fn assert_no_live_html(what: &str, body: &str) {
    let prose = outside_fences(body);
    for tag in ["<img", "<script", "<iframe"] {
        assert!(
            !prose.contains(tag),
            "{what}: {tag:?} is live HTML outside any fence\n--- outside fences ---\n{prose}"
        );
    }
    // `</details>` is the exception that must be escaped even inside the
    // fence: it closes the container the block itself is wrapped in.
    assert!(
        !body.contains("</details>\n</details>") && body.matches("</details>").count() <= 1,
        "{what}: a value closed the <details> container early\n--- body ---\n{body}"
    );
}

#[test]
fn a_hostile_jsonl_timestamp_cannot_escape_the_fence() {
    let dir = scratch("inject-ts");
    let log = dir.join("hostile.jsonl");
    // Serialised by hand so the hostile text lands inside the JSON string as
    // real newlines once parsed — which is what a logging stack would emit if
    // an attacker controlled a value it interpolated.
    let line = format!(
        "{{\"timestamp\":{},\"level\":\"error\",\"message\":\"boom\"}}",
        json_string(HOSTILE)
    );
    std::fs::write(&log, line).expect("write hostile log");

    let (ok, body, stderr) = run_demo(&["--log", log.to_str().unwrap(), "preview"]);
    assert!(ok, "preview failed: {stderr}");

    assert_fence_intact("a hostile timestamp", &body);
    assert_no_live_html("a hostile timestamp", &body);
    assert!(
        body.contains("onerror"),
        "the text should still be VISIBLE, just inert — over-masking is its own \
         failure\n--- body ---\n{body}"
    );
}

#[test]
fn a_hand_built_record_is_escaped_even_though_it_skipped_the_redactor() {
    // Record's fields are public and Report::diagnostics takes any iterator of
    // them, so this path is part of the supported API, not an abuse of it.
    let (ok, body, stderr) = run_demo(&["--raw-record", HOSTILE, "preview"]);
    assert!(ok, "preview failed: {stderr}");

    assert_fence_intact("a hand-built record", &body);
    assert_no_live_html("a hand-built record", &body);
}

#[test]
fn a_hostile_provenance_value_cannot_inject_markup() {
    let (ok, body, stderr) = run_demo(&["--workdir", HOSTILE, "preview"]);
    assert!(ok, "preview failed: {stderr}");

    assert_no_live_html("a provenance value", &body);
    assert!(
        !body.contains("\n## heading"),
        "a provenance value became a real heading\n--- body ---\n{body}"
    );
    // Escaped rather than dropped: a triager still needs to see the value.
    assert!(
        body.contains("&lt;img"),
        "the tag should be escaped and still legible\n--- body ---\n{body}"
    );
}

#[test]
fn the_environment_block_is_not_broken_by_a_hostile_value() {
    // Injection defences that mangle the surrounding structure trade one bug
    // for another: the block must still parse as the list it claims to be.
    let (ok, body, _) = run_demo(&["--workdir", HOSTILE, "preview"]);
    assert!(ok);
    let entries = body.lines().filter(|l| l.starts_with("- ")).count();
    assert!(
        entries >= 5,
        "the environment list collapsed to {entries} entries\n--- body ---\n{body}"
    );
}

/// Minimal JSON string encoder — enough to embed hostile text in a log line
/// without taking a serde dependency in the test crate.
fn json_string(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
