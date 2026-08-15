//! Observability closure, asserted as a property rather than by example.
//!
//! Closes gerchowl/squelch#3, which was deferred out of #2. Every defect #2
//! fixed was found by a person reading code, and the tests it added pin the
//! specific inputs that broke. None of them would catch the *next* instance of
//! the same shape — a fourth field stored as a `Vec` that should be a set, or
//! a second encoder that loses data without saying so.
//!
//! Three properties, one per shape that failed:
//!
//! 1. **Idempotence.** Doubling any adopt-style operation leaves the composed
//!    report identical. `field`, `label`, `require`, `form`, `provenance` and
//!    `template` all mean "install this named thing", and a builder that stores
//!    them in an append-only `Vec` accumulates instead. That is exactly how
//!    `MissingFields(["a","b","a","b"])` reached a reporter — a GUI reapplying
//!    its form on every keystroke.
//!
//!    `diagnostics` is deliberately excluded: it means "add these records", and
//!    two independent sources of the same warning must both survive. Encoding
//!    which operations are adopt-style is the point, not an exemption.
//!
//! 2. **Conservation.** Every difference between the body and the URL is named
//!    in the manifest, and everything the manifest names is really different.
//!    A lossy encoder reporting a single bit is what let a reporter approve a
//!    preview and submit a form with a section missing.
//!
//! 3. **Round-trip stability.** `skeleton` → `parse_skeleton` returns the
//!    answers it was given, for any values — including ones that imitate the
//!    delimiters the skeleton is built from.
//!
//! The oracle is written from the contract, not from `url::build`. A shadow
//! model that mirrors the implementation agrees with the bug.

use proptest::prelude::*;
use squelch::{Destination, Field, Form, Provenance, Record, Report, Value};

fn destination() -> Destination {
    Destination::parse("gerchowl/squelch").expect("a literal slug")
}

/// A builder operation. Every variant but `Diagnostics` is adopt-style: naming
/// the same thing twice must be indistinguishable from naming it once.
#[derive(Debug, Clone)]
enum Op {
    Field(String, String),
    Label(String, String),
    Require(Vec<String>),
    Template(String),
    Title(String),
    ProvenanceField(String),
    Provenance(Vec<(String, String)>),
    UseForm(Vec<(String, bool)>),
    /// The one operation that is NOT adopt-style, generated so the exclusion
    /// is enforced rather than asserted in a comment. Two independent sources
    /// of the same warning must both survive, so doubling this one is REQUIRED
    /// to be observable — property 1 checks that direction too.
    Diagnostics(Vec<String>),
}

impl Op {
    fn apply(&self, report: Report) -> Report {
        match self {
            Self::Field(id, value) => report.field(id, value),
            Self::Label(id, label) => report.label(id, label),
            Self::Require(ids) => report.require(ids.clone()),
            Self::Template(name) => report.template(name),
            Self::Title(title) => report.title(title),
            Self::ProvenanceField(id) => report.provenance_field(id),
            Self::Provenance(entries) => {
                let mut provenance = Provenance::new();
                for (label, value) in entries {
                    provenance = provenance.with(label, Value::known(value));
                }
                report.provenance(provenance)
            }
            Self::UseForm(fields) => {
                let form = Form::new(fields.iter().map(|(id, required)| {
                    let field = Field::textarea(id, format!("Label for {id}"));
                    if *required {
                        field.required()
                    } else {
                        field
                    }
                }))
                .template("bug.yml");
                report.form(&form)
            }
            Self::Diagnostics(messages) => {
                report.diagnostics(messages.iter().map(|message| Record {
                    timestamp: "2026-08-13T00:00:00Z".into(),
                    level: "error".into(),
                    source: None,
                    fields: vec![("message".into(), message.clone())],
                }))
            }
        }
    }

    fn is_adopt_style(&self) -> bool {
        !matches!(self, Self::Diagnostics(_))
    }
}

/// Field ids drawn from a small pool, so collisions — the interesting case —
/// actually happen. A generator over free-form identifiers would produce a
/// distinct id almost every time and never exercise the set semantics at all.
fn id() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("current-behavior".to_string()),
        Just("reproduction".to_string()),
        Just("expected-behavior".to_string()),
        Just("impact".to_string()),
        Just("environment".to_string()),
    ]
}

/// Values biased toward the URL budget rather than sampled uniformly.
///
/// `MAX_URL_LEN` is 7 500 characters. Drawing lengths evenly would put almost
/// every case far below it, and the boundary — where truncation and dropping
/// happen — would essentially never be reached.
fn value() -> impl Strategy<Value = String> {
    prop_oneof![
        4 => "[a-zA-Z0-9 .,:/'\"<>&%~-]{0,80}".prop_map(String::from),
        3 => (1usize..9_000).prop_map(|n| "x".repeat(n)),
        2 => (1usize..3_000).prop_map(|n| "é".repeat(n)),
        1 => Just(String::new()),
    ]
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (id(), value()).prop_map(|(i, v)| Op::Field(i, v)),
        (id(), "[a-zA-Z ]{1,20}").prop_map(|(i, l)| Op::Label(i, l)),
        prop::collection::vec(id(), 0..4).prop_map(Op::Require),
        prop_oneof![Just("bug.yml"), Just("crash.yml")].prop_map(|t| Op::Template(t.to_string())),
        "[a-zA-Z ]{0,30}".prop_map(Op::Title),
        id().prop_map(Op::ProvenanceField),
        prop::collection::vec(("[A-Za-z]{1,10}", "[A-Za-z0-9 .]{0,40}"), 0..4)
            .prop_map(Op::Provenance),
        prop::collection::vec((id(), any::<bool>()), 0..4).prop_map(Op::UseForm),
        prop::collection::vec("[a-z ]{1,30}", 1..3).prop_map(Op::Diagnostics),
    ]
}

/// Field operations that COMPETE for the URL budget.
///
/// The conservation property exists to catch a field that vanishes from the
/// URL while the reporter approved a preview containing it — and with only
/// arbitrary operations, that branch never ran: `dropped` was non-empty in
/// about one case in seventy, and never for an id the oracle knew about. A
/// property whose central assertion is unreachable is worse than a missing
/// test, because it is counted as coverage.
///
/// So the sequence always ends with two to four fields whose combined length
/// straddles `MAX_URL_LEN`, which is what makes truncation and dropping the
/// common case rather than the vanishing one.
fn competing_fields() -> impl Strategy<Value = Vec<Op>> {
    prop::collection::vec(
        (
            id(),
            prop_oneof![
                (2_000usize..6_000).prop_map(|n| "x".repeat(n)),
                (1usize..200).prop_map(|n| "y".repeat(n)),
                (500usize..2_500).prop_map(|n| "é".repeat(n)),
            ],
        ),
        2..5,
    )
    .prop_map(|fields| {
        fields
            .into_iter()
            .map(|(id, value)| Op::Field(id, value))
            .collect()
    })
}

/// `url::MAX_URL_LEN`, restated because it is not public.
///
/// Restating it is the point: if the crate raises its budget without this
/// following, the coverage assertion below starts failing, which is the right
/// way round — a silent divergence would make the assertion vacuous instead.
const MAX_URL_LEN: usize = 7_500;

/// The observable result of a sequence: everything a surface can see, and
/// everything that decides what the reporter believes they are sending.
#[derive(Debug, PartialEq, Eq)]
struct Observed {
    url: String,
    shortened: Vec<String>,
    dropped: Vec<String>,
    body: String,
    missing: Option<Vec<String>>,
}

impl Observed {
    fn is_lossy(&self) -> bool {
        !self.shortened.is_empty() || !self.dropped.is_empty()
    }
}

fn observe(ops: &[Op]) -> Observed {
    let mut report = Report::to(destination());
    for op in ops {
        report = op.apply(report);
    }
    match report.build() {
        Ok(composed) => Observed {
            url: composed.url.url,
            shortened: composed.url.shortened,
            dropped: composed.url.dropped,
            body: composed.body,
            missing: None,
        },
        Err(squelch::Error::MissingFields(ids)) => Observed {
            url: String::new(),
            shortened: Vec::new(),
            dropped: Vec::new(),
            body: String::new(),
            missing: Some(ids),
        },
        Err(other) => panic!("composition failed for a reason it should not: {other}"),
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// Property 1 — idempotence under operation doubling.
    #[test]
    fn doubling_any_adopt_style_operation_changes_nothing(
        ops in prop::collection::vec(op(), 0..8),
        at in 0usize..8,
    ) {
        prop_assume!(!ops.is_empty());
        let at = at % ops.len();

        let mut doubled = ops.clone();
        doubled.insert(at, ops[at].clone());

        if ops[at].is_adopt_style() {
            prop_assert_eq!(
                observe(&ops),
                observe(&doubled),
                "applying op {} twice was observable; adopt-style state is \
                 being appended to rather than replaced",
                at
            );
        } else {
            // `diagnostics` means "add these records", not "install this named
            // thing". Asserting the exclusion in this direction is what keeps
            // it from being quietly widened into the property above, which
            // would make the whole thing agree with an implementation that
            // deduplicated two independent reports of the same warning.
            //
            // Only when something was actually composed: a report refused for
            // a missing field carries no diagnostics either way, and that is
            // the refusal working, not a lost record.
            prop_assume!(observe(&ops).missing.is_none());
            prop_assert_ne!(
                observe(&ops),
                observe(&doubled),
                "doubling `diagnostics` was NOT observable; two independent \
                 sources of the same warning must both survive"
            );
        }
    }

    /// Property 1, corollary: a duplicated id is reported once.
    ///
    /// Separate from the property above because it survives even when the
    /// doubling IS invisible in the URL — `MissingFields` is the surface where
    /// the accumulation actually reached a human.
    #[test]
    fn a_missing_field_is_named_once(ops in prop::collection::vec(op(), 0..8)) {
        if let Some(missing) = observe(&ops).missing {
            let mut unique = missing.clone();
            unique.sort();
            unique.dedup();
            prop_assert_eq!(
                unique.len(),
                missing.len(),
                "a field was named more than once: {:?}",
                missing
            );
        }
    }

    /// Property 2 — conservation between body, URL and manifest.
    ///
    /// The oracle is the contract: `shortened` means "present in the URL, but
    /// not all of it", `dropped` means "not in the URL at all". Anything that
    /// is one and reported as the other, or is either and reported as neither,
    /// is a lossy encoder lying about its loss.
    #[test]
    fn every_loss_is_named_and_every_name_is_a_loss(
        prefix in prop::collection::vec(op(), 0..5),
        competing in competing_fields(),
    ) {
        let ops: Vec<Op> = prefix.into_iter().chain(competing).collect();
        let observed = observe(&ops);
        prop_assume!(observed.missing.is_none());

        // Recover what was asked for, independently of what the builder did
        // with it: the last write to each id wins, which is the contract
        // `Report::field` documents.
        let mut asked: Vec<(String, String)> = Vec::new();
        for op in &ops {
            if let Op::Field(id, value) = op {
                match asked.iter_mut().find(|(name, _)| name == id) {
                    Some((_, slot)) => value.clone_into(slot),
                    None => asked.push((id.clone(), value.clone())),
                }
            }
        }

        // The provenance field is not the reporter's to own: attaching a
        // `Provenance` replaces whatever is in it, which is documented and
        // deliberate — `environment` is a common form id, and appending
        // instead emitted the parameter twice, where GitHub takes the last and
        // the reporter's words lost. So the conservation check skips that one
        // id when provenance is attached; the oracle would otherwise be
        // asserting the crate breaks its own contract.
        //
        // Reconstructing the expected value here instead would mean
        // reimplementing `Provenance::to_markdown`, and a shadow model that
        // mirrors the implementation agrees with the bug.
        let provenance_field = ops
            .iter()
            .rev()
            .find_map(|op| match op {
                Op::ProvenanceField(id) => Some(id.clone()),
                _ => None,
            })
            .unwrap_or_else(|| "environment".to_string());
        let provenance_attached = ops.iter().any(|op| matches!(op, Op::Provenance(_)));

        for (id, value) in &asked {
            if provenance_attached && *id == provenance_field {
                continue;
            }
            let parameter = format!("&{id}=");
            let in_url = observed.url.contains(&parameter);
            let named_dropped = observed.dropped.contains(id);
            let named_short = observed.shortened.contains(id);

            prop_assert!(
                !(named_dropped && named_short),
                "{id} is reported as both shortened and dropped; those are \
                 different events and a surface has to tell them apart"
            );

            if !in_url {
                // An empty answer carries nothing, so its absence is not a
                // loss and naming it would be a false alarm — and a warning
                // that fires when nothing was lost is one nobody reads on the
                // occasion it matters.
                if value.trim().is_empty() {
                    prop_assert!(
                        !named_dropped && !named_short,
                        "{id} was blank and is reported as lost"
                    );
                    continue;
                }
                prop_assert!(
                    named_dropped,
                    "{id} is not in the URL and is not named in `dropped`. A \
                     reporter would approve a preview containing it and submit \
                     a form without it — silently, which is the whole failure \
                     #2 exists to close.\nurl: {}",
                    observed.url
                );
                continue;
            }

            // Whatever survived must still be text. Truncation cutting between
            // two `%XX` triples of the SAME character leaves a lead byte with
            // no continuation — a whole escape and a broken codepoint — and the
            // manifest reports that as "shortened", which is not what happened.
            let surviving = observed
                .url
                .find(&parameter)
                .map(|at| &observed.url[at + parameter.len()..])
                .and_then(|rest| rest.split('&').next())
                .unwrap_or("");
            let decoded = percent_decode(surviving);
            let text = std::str::from_utf8(&decoded);
            prop_assert!(
                text.is_ok(),
                "{id} was truncated between two bytes of one character: {:?}",
                text.err()
            );
            // Validity alone is not enough — a re-encoding that substituted a
            // replacement character would satisfy it. What survived has to be
            // a prefix of what was given.
            if let Ok(text) = text {
                let without_note = text.split("\n\n[shortened").next().unwrap_or(text);
                prop_assert!(
                    value.starts_with(without_note),
                    "{id} came back as something other than a prefix of itself"
                );
            }

            // Present. Either it survived whole, or it is a stub — and a stub
            // must say so.
            let fully_present =
                value.trim().is_empty() || carries_whole_value(&observed.url, id, value);
            prop_assert!(
                fully_present || named_short || named_dropped,
                "{id} reached the URL cut short, and neither list names it. \
                 The reporter is told the report is intact when it is not."
            );
            prop_assert!(
                !(fully_present && named_short),
                "{id} survived whole but is reported as shortened. A warning \
                 that fires when nothing was lost is a warning nobody reads on \
                 the one occasion it matters."
            );
        }

        // The BODY is the other half of "closure", and the property was
        // reading only the URL — a `render_body` regression that silently
        // dropped a section would have passed. The body is the route with no
        // size limit, so every answer belongs in it whatever the URL did.
        for (id, value) in &asked {
            if provenance_attached && *id == provenance_field {
                continue;
            }
            if value.trim().is_empty() {
                continue;
            }
            prop_assert!(
                observed.body.contains(value.trim_end()),
                "{id} is missing from the body. The URL is allowed to lose it \
                 — that is what `dropped` is for — but a File, mail, `gh` or \
                 endpoint report carries the whole thing, and those routes read \
                 the body."
            );
        }

        // Coverage, asserted rather than hoped for. If the generated fields
        // plainly exceed the budget and NOTHING is reported lost, either the
        // manifest is lying or the generators have drifted back to producing
        // values too small to reach the branch this property exists for.
        let total: usize = asked
            .iter()
            .filter(|(id, _)| !(provenance_attached && *id == provenance_field))
            .map(|(id, value)| id.len() + value.len() + 2)
            .sum();
        if total > 2 * MAX_URL_LEN {
            prop_assert!(
                observed.is_lossy(),
                "{total} characters of answers went into a {MAX_URL_LEN}-character \
                 budget and the manifest reports no loss at all"
            );
        }

        // Nothing may be named that was never asked for.
        for id in observed.shortened.iter().chain(observed.dropped.iter()) {
            prop_assert!(
                asked.iter().any(|(name, _)| name == id)
                    || ops.iter().any(|op| matches!(op, Op::Provenance(_)))
                    || ops.iter().any(|op| matches!(op, Op::ProvenanceField(i) if i == id)),
                "the manifest names {id}, which nothing put in the report"
            );
        }
    }
}

/// Whether the URL carries `value` for `id` in full.
///
/// Percent-encoding makes a substring test on the raw URL useless, so the
/// parameter is located and decoded back. Written against the contract — "the
/// query parameter's value decodes to what was supplied" — rather than by
/// calling the encoder, which would agree with an encoder that is wrong.
///
/// Raw BYTES, never `from_utf8_lossy`: that call repairs a truncation which
/// split a character, which is precisely the corruption worth catching. A
/// decoder returning a `String` cannot see the bug it is being used to find.
fn carries_whole_value(url: &str, id: &str, value: &str) -> bool {
    let needle = format!("&{id}=");
    let Some(start) = url.find(&needle) else {
        return false;
    };
    let rest = &url[start + needle.len()..];
    let encoded = rest.split('&').next().unwrap_or("");
    percent_decode(encoded) == value.as_bytes()
}

fn percent_decode(encoded: &str) -> Vec<u8> {
    let bytes = encoded.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes.get(index) {
            Some(b'%') if index + 2 < bytes.len() => {
                let hex = encoded.get(index + 1..index + 3).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    Err(_) => {
                        out.push(b'%');
                        index += 1;
                    }
                }
            }
            Some(byte) => {
                out.push(*byte);
                index += 1;
            }
            None => break,
        }
    }
    out
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// Property 3 — the skeleton round-trips, for values that imitate it.
    ///
    /// The generator deliberately produces `##` headings, fence markers and
    /// `-->` inside answers. Each of those broke the round trip when it was
    /// first tried, and each is something a reporter pasting a shell transcript
    /// writes without thinking about it.
    #[test]
    fn a_skeleton_returns_the_answers_it_was_given(
        answers in prop::collection::vec(
            (id(), prop_oneof![
                "[a-zA-Z0-9 .:/-]{0,60}".prop_map(String::from),
                Just("## not a heading".to_string()),
                Just("```\nfenced\n```".to_string()),
                Just("~~~\ntilde fenced\n~~~".to_string()),
                Just("an arrow --> here".to_string()),
                Just("    ## indented heading".to_string()),
                Just("<!-- a comment -->".to_string()),
            ]),
            1..5,
        ),
    ) {
        // Last write wins, so the expectation is the deduped tail.
        let mut expected: Vec<(String, String)> = Vec::new();
        for (id, answer) in &answers {
            match expected.iter_mut().find(|(name, _)| name == id) {
                Some((_, slot)) => answer.clone_into(slot),
                None => expected.push((id.clone(), answer.clone())),
            }
        }

        let form = Form::new(
            expected
                .iter()
                .map(|(id, _)| Field::textarea(id, format!("Label for {id}")).describe("Help --> text")),
        );

        // Fill the skeleton the way a reporter's editor would: replace each
        // section's placeholder with the answer.
        let mut filled = String::new();
        for (id, answer) in &expected {
            filled.push_str(&format!("## {id}\n\n{answer}\n\n"));
        }

        let parsed = form.parse_skeleton(&filled);
        let parsed_map: Vec<(String, String)> = parsed
            .into_iter()
            .map(|(id, answer)| (id, answer.trim().to_string()))
            .collect();
        let expected_trimmed: Vec<(String, String)> = expected
            .iter()
            .map(|(id, answer)| (id.clone(), answer.trim().to_string()))
            .filter(|(_, answer)| !answer.is_empty())
            .collect();

        prop_assert_eq!(
            parsed_map,
            expected_trimmed,
            "the skeleton did not return what was written into it; a delimiter \
             in the reporter's own text was read as structure"
        );

        // And the guidance the skeleton emits must not be able to end its own
        // comment, whatever the description contains.
        let skeleton = form.skeleton();
        prop_assert!(
            !skeleton.contains("--> text"),
            "a `-->` in a field description closed the guidance comment early; \
             the rest renders as literal text in the reporter's editor"
        );
    }
}
