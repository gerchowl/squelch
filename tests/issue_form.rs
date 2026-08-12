//! squelch's own issue form, checked against the code that prefills it.
//!
//! Every example, doctest and demo route in this repo builds a report against
//! `gerchowl/squelch` with `template("bug.yml")`. A prefilled GitHub URL only
//! lands an answer when its query parameter matches a field `id` declared in
//! that template — a parameter naming no field is dropped without complaint,
//! by GitHub, after the reporter has already approved the preview.
//!
//! So the failure this pins is silent on both ends: the crate reports success,
//! the browser opens a form, and the section the reporter wrote is simply not
//! there. Nothing else in the suite can see it, because every other test
//! checks the URL squelch *built* rather than the template it points at.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Field ids declared by the checked-in issue form.
///
/// Deliberately a line scan rather than a YAML parse: the crate takes no
/// format dependency (that is a design position, see `form`'s module docs) and
/// a test is a poor place to acquire one. The shape being read — `id:` at a
/// list-item's indent — is stable in GitHub's issue-form schema.
fn declared_ids(form: &str) -> BTreeSet<String> {
    form.lines()
        .filter_map(|line| line.trim().strip_prefix("id:"))
        .map(|id| id.trim().trim_matches('"').to_string())
        .collect()
}

/// Field ids this repo's own code prefills or requires.
///
/// Scanning the sources rather than restating the list keeps the check
/// load-bearing: a new `.field("...")` in the demo app is caught even though
/// whoever wrote it never opened this file.
fn prefilled_ids(source: &str) -> BTreeSet<String> {
    let call = regex::Regex::new(
        r#"(?:\.field|\.provenance_field|Field::textarea|Field::input|Field::new)\(\s*\n?\s*"([a-z0-9][a-z0-9-]*)""#,
    )
    .expect("literal pattern");
    let require = regex::Regex::new(r#"\.require\(\[([^\]]*)\]\)"#).expect("literal pattern");
    let quoted = regex::Regex::new(r#""([a-z0-9][a-z0-9-]*)""#).expect("literal pattern");

    let mut ids: BTreeSet<String> = call
        .captures_iter(source)
        .map(|caps| caps[1].to_string())
        .collect();
    for list in require.captures_iter(source) {
        ids.extend(quoted.captures_iter(&list[1]).map(|caps| caps[1].to_string()));
    }
    ids
}

/// The files that teach a reader — or a consumer — which ids to use.
const SURFACES: [&str; 4] = [
    "src/lib.rs",
    "README.md",
    "examples/file_a_bug.rs",
    "apps/squelch-demo/src/main.rs",
];

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

#[test]
fn the_repo_ships_the_template_its_own_links_point_at() {
    let form = repo_root().join(".github/ISSUE_TEMPLATE/bug.yml");
    assert!(
        form.exists(),
        "every example in this repo builds `template(\"bug.yml\")` against \
         gerchowl/squelch, so {} has to exist or those links open a form with \
         no fields to land in",
        form.display()
    );
}

#[test]
fn every_id_the_repo_prefills_is_declared_by_the_template() {
    let root = repo_root();
    let declared = declared_ids(&read(&root.join(".github/ISSUE_TEMPLATE/bug.yml")));
    assert!(
        !declared.is_empty(),
        "no ids parsed out of the issue form — the scan is vacuous, not passing"
    );

    for surface in SURFACES {
        let used = prefilled_ids(&read(&root.join(surface)));
        assert!(
            !used.is_empty(),
            "{surface} named no field ids; the scanner has drifted from the \
             code and is now asserting nothing"
        );
        let undeclared: Vec<&String> = used.difference(&declared).collect();
        assert!(
            undeclared.is_empty(),
            "{surface} prefills {undeclared:?}, which .github/ISSUE_TEMPLATE/bug.yml \
             does not declare. GitHub drops an unmatched parameter silently, so a \
             reporter would approve a preview containing those answers and submit a \
             form without them. Declared: {declared:?}"
        );
    }
}

#[test]
fn the_default_provenance_field_is_declared() {
    // `Report` writes the environment block into `environment` unless told
    // otherwise, and that default is invisible at the call site — nothing in
    // the examples mentions it, so nothing else would catch its absence.
    let declared = declared_ids(&read(&repo_root().join(".github/ISSUE_TEMPLATE/bug.yml")));
    assert!(
        declared.contains("environment"),
        "`Report::provenance_field` defaults to `environment`; the template \
         must declare it. Declared: {declared:?}"
    );
}

/// The crate's own GitHub parser, run against a real GitHub issue form.
///
/// `form`'s module docs claim you can deserialize a [`squelch::Form`] straight
/// from "the YAML you already keep in `.github/ISSUE_TEMPLATE/`", and
/// `form::github` exists to make that true. Until this test the only coverage
/// was a hand-written JSON blob, which exercises serde's derive and none of
/// the syntax GitHub actually emits — block scalars, `render:`, `validations:`,
/// per-option `required` on a checkbox. A consumer following that advice with
/// an ordinary template would have been the first to find out.
#[cfg(feature = "serde")]
#[test]
fn the_crate_parses_its_own_issue_form() {
    use squelch::form::github::IssueForm;

    let yaml = read(&repo_root().join(".github/ISSUE_TEMPLATE/bug.yml"));
    let parsed: IssueForm =
        serde_yaml_ng::from_str(&yaml).expect("squelch parses a real GitHub issue form");
    let form: squelch::Form = parsed.into();

    // The line scan and the real parser must agree about which fields can hold
    // an answer. If they disagree, one of them is wrong about the file, and the
    // id checks above are resting on whichever it is.
    //
    // Answerable only: GitHub lets an element omit `id`, and `form::github`
    // synthesises `field-<n>` so a surface still has a key. The `markdown`
    // intro block in this template has no id and gets one, which the line scan
    // cannot see and should not — it carries no answer.
    let scanned = declared_ids(&yaml);
    let answerable: BTreeSet<String> = form
        .fields
        .iter()
        .filter(|f| f.kind.is_answerable())
        .map(|f| f.id.clone())
        .collect();
    assert_eq!(
        scanned, answerable,
        "the line scan and `form::github` disagree about which fields this \
         template offers an answer for"
    );

    // Round-trip the property the whole file exists for: `required` has to
    // survive the conversion, or a Form built from a real template would let a
    // report through with its mandatory sections empty.
    let required: BTreeSet<&str> = form
        .fields
        .iter()
        .filter(|f| f.required)
        .map(|f| f.id.as_str())
        .collect();
    assert!(
        required.contains("current-behavior") && required.contains("reproduction"),
        "`validations: required: true` did not survive the conversion: {required:?}"
    );
}

#[test]
fn the_confirmation_is_a_checkbox_no_url_can_reach() {
    // The crate's stated refusal — a tool that ticks a "yes, I reproduced
    // this" box forges a human's statement — only holds if the form actually
    // asks for the attestation as `checkboxes`. As a `dropdown` or `input` it
    // becomes prefillable, and the refusal quietly stops being enforced by
    // anything.
    let form = read(&repo_root().join(".github/ISSUE_TEMPLATE/bug.yml"));
    let confirm = form
        .split("- type: ")
        .find(|block| block.contains("id: confirm"))
        .expect("the form declares a `confirm` field");
    assert!(
        confirm.starts_with("checkboxes"),
        "`confirm` is a `{}` — the attestation must be `checkboxes`, which \
         GitHub cannot prefill, or the crate's promise not to tick it is \
         enforced by nothing",
        confirm.lines().next().unwrap_or("")
    );
}
