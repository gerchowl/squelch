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
