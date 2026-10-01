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
//!
//! # Also here: the documentation links
//!
//! The last two tests are the same idea applied to `docs/`. A decision record
//! nobody can navigate to is not a decision record, and a broken relative link
//! is invisible to everything else in the suite — the ADRs are not compiled and
//! nothing here renders markdown. The failure is silent in the same way the
//! missing field id is, which is the only reason it belongs in this file rather
//! than in a test of its own.

use std::collections::BTreeSet;

/// The files are baked in at COMPILE time, not read at run time.
///
/// `std::fs` plus `CARGO_MANIFEST_DIR` looks equivalent and is not: it depends
/// on the source tree still being where it was when the binary was built. Under
/// `nix flake check` it is not, and the whole suite failed with "No such file
/// or directory" on Linux while passing locally — which reads as a broken test
/// rather than as the environment difference it is.
///
/// `include_str!` also makes a missing file a **compile** error, so this test
/// cannot quietly stop asserting anything.
const FORM: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/.github/ISSUE_TEMPLATE/bug.yml"
));

/// The files that teach a reader — or a consumer — which ids to use.
const SURFACES: [(&str, &str); 4] = [
    (
        "src/lib.rs",
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs")),
    ),
    (
        "README.md",
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md")),
    ),
    (
        "examples/file_a_bug.rs",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/file_a_bug.rs"
        )),
    ),
    (
        "apps/squelch-demo/src/main.rs",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/apps/squelch-demo/src/main.rs"
        )),
    ),
];

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
        ids.extend(
            quoted
                .captures_iter(&list[1])
                .map(|caps| caps[1].to_string()),
        );
    }
    ids
}

#[test]
fn the_repo_ships_the_template_its_own_links_point_at() {
    // Its absence is a compile error — see `FORM`. What is still worth
    // asserting is that it is not empty, which `include_str!` would accept.
    assert!(
        !FORM.trim().is_empty(),
        "every example in this repo builds `template(\"bug.yml\")` against \
         gerchowl/squelch, so the form has to have fields for those links to \
         land in"
    );
}

#[test]
fn every_id_the_repo_prefills_is_declared_by_the_template() {
    let declared = declared_ids(FORM);
    assert!(
        !declared.is_empty(),
        "no ids parsed out of the issue form — the scan is vacuous, not passing"
    );

    for (surface, source) in SURFACES {
        let used = prefilled_ids(source);
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
    let declared = declared_ids(FORM);
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

    let parsed: IssueForm =
        serde_yaml_ng::from_str(FORM).expect("squelch parses a real GitHub issue form");
    let form: squelch::Form = parsed.into();

    // The line scan and the real parser must agree about which fields can hold
    // an answer. If they disagree, one of them is wrong about the file, and the
    // id checks above are resting on whichever it is.
    //
    // Answerable only: GitHub lets an element omit `id`, and `form::github`
    // synthesises `field-<n>` so a surface still has a key. The `markdown`
    // intro block in this template has no id and gets one, which the line scan
    // cannot see and should not — it carries no answer.
    let scanned = declared_ids(FORM);
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
    let confirm = FORM
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

// ---------------------------------------------------------------------------
// Documentation links
// ---------------------------------------------------------------------------

/// The ADR index, baked in at compile time for the same reason `FORM` is.
///
/// A decision record is only useful if a reader can find the next one, and a
/// broken relative link in an index is the failure that makes a directory look
/// abandoned. Nothing else in the suite would notice: the ADRs are not compiled
/// and the README is not rendered by anything here.
const ADR_INDEX: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/adr/README.md"));

/// Every markdown file that can carry a relative link a reader is expected to
/// follow. Baked in rather than globbed at run time, so a new file that is not
/// listed cannot escape the check — which is the same trade `include_str!` makes
/// everywhere else in this file, and the reason a run-time walk is not used: a
/// `read_dir` would find today's files and a new ADR added tomorrow would be
/// unlisted until someone noticed, which is the drift the index is meant to
/// prevent.
const LINKED_DOCS: [(&str, &str); 12] = [
    ("README.md", include_str!("../README.md")),
    ("docs/testing.md", include_str!("../docs/testing.md")),
    ("docs/adr/README.md", ADR_INDEX),
    (
        "docs/adr/0001-extracted-from-flock-adr-0010.md",
        include_str!("../docs/adr/0001-extracted-from-flock-adr-0010.md"),
    ),
    (
        "docs/adr/0002-the-msrv-is-set-by-the-dependency-tree.md",
        include_str!("../docs/adr/0002-the-msrv-is-set-by-the-dependency-tree.md"),
    ),
    (
        "docs/adr/0003-no-git-hook-layer.md",
        include_str!("../docs/adr/0003-no-git-hook-layer.md"),
    ),
    (
        "docs/adr/0004-the-browser-route-refuses-rather-than-truncate.md",
        include_str!("../docs/adr/0004-the-browser-route-refuses-rather-than-truncate.md"),
    ),
    (
        "docs/adr/0005-the-host-rule-is-a-prior.md",
        include_str!("../docs/adr/0005-the-host-rule-is-a-prior.md"),
    ),
    (
        "docs/adr/0006-field-provenance-and-host-position.md",
        include_str!("../docs/adr/0006-field-provenance-and-host-position.md"),
    ),
    (
        "docs/adr/0007-the-url-budget-is-under-the-measured-failure-point.md",
        include_str!("../docs/adr/0007-the-url-budget-is-under-the-measured-failure-point.md"),
    ),
    (
        "docs/adr/0008-form-parse-skeleton-takes-self.md",
        include_str!("../docs/adr/0008-form-parse-skeleton-takes-self.md"),
    ),
    ("docs/stories.md", include_str!("../docs/stories.md")),
];

/// Pull the target out of a markdown link.
///
/// Only the `[text](target)` inline form, which is the only one these files use
/// for repository paths. A bare URL, a reference-style link or an image is not
/// followed, because following those would need the network and this test runs in
/// a sandbox that has none.
fn link_target(line: &str) -> Option<&str> {
    let open = line.find("](")? + 2;
    let rest = &line[open..];
    let close = rest.find(')')?;
    Some(&rest[..close])
}

#[test]
fn every_relative_doc_link_resolves() {
    for (name, text) in LINKED_DOCS {
        for (number, line) in text.lines().enumerate() {
            let Some(target) = link_target(line) else {
                continue;
            };
            // Absolute URLs, anchors within the same file, and mailto are not
            // repository paths and are not checked here.
            if target.starts_with("http://")
                || target.starts_with("https://")
                || target.starts_with("mailto:")
                || target.starts_with('#')
            {
                continue;
            }
            // Resolve relative to the file holding the link, then strip any
            // `#fragment` — a link to `docs/adr/README.md#index` is a link to the
            // file, and the fragment is not a path.
            //
            // A leading `./` is normalised away rather than treated as
            // repository-root relative. `Path::new("/docs/adr")` is an *absolute*
            // path, so a naive leading-slash strip turns a relative link into one
            // that resolves against the filesystem root and quietly passes for
            // any directory that happens to exist there. The first version of
            // this test did exactly that and asserted nothing at all — the same
            // failure `docs/testing.md` records for the property suite.
            let base = name.rsplit_once('/').map_or("", |(dir, _)| dir);
            let path = target.split('#').next().unwrap_or(target);
            let path = path.strip_prefix("./").unwrap_or(path);
            let resolved = format!("{base}/{path}");

            let full = concat!(env!("CARGO_MANIFEST_DIR"), "/");
            let on_disk = format!("{full}{resolved}");
            assert!(
                std::path::Path::new(&on_disk).exists(),
                "{name}:{} links to {target:?}, which resolves to {resolved:?} — \
                 no such path in the repository",
                number + 1
            );
        }
    }
}

#[test]
fn the_adr_index_lists_every_record_that_exists() {
    // The index is the only way a reader finds the next decision, so a record
    // that is not listed is a record nobody will read. The inverse — an index
    // entry with no file — is the broken-link case above; this is the one where
    // the file exists and the index forgot it.
    // Links in the index are relative to the file holding them, so they are bare
    // filenames rather than `docs/adr/…` paths. Accept both, and reject anything
    // that is not a markdown file in the same directory.
    let mut listed: Vec<&str> = ADR_INDEX
        .lines()
        .filter_map(link_target)
        .filter(|t| t.ends_with(".md") && !t.starts_with("http") && !t.contains('/'))
        .collect();
    listed.sort_unstable();
    listed.dedup();

    assert!(
        listed.len() >= 8,
        "the index lists only {} records: {listed:?}",
        listed.len()
    );

    // Every listed entry is a real file, and every real file is listed. The first
    // half is the broken-link case restated for the index specifically; the
    // second is this one.
    for entry in &listed {
        let full = concat!(env!("CARGO_MANIFEST_DIR"), "/docs/adr/");
        assert!(
            std::path::Path::new(&format!("{full}{entry}")).exists(),
            "the index lists {entry:?}, which does not exist"
        );
    }
}
