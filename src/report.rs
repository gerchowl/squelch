//! Composing a report and sending it.

use crate::destination::Destination;
use crate::error::{Error, Result};
use crate::form::Form;
use crate::provenance::Provenance;
use crate::redact::{render_block, Record};
use crate::transport::Transport;
use crate::url::{self, PrefilledUrl};

/// A report under construction.
///
/// Composition is pure: nothing is read, spawned or sent until [`Report::send`]
/// or one of the explicit accessors is called. That is what makes the preview
/// trustworthy — [`Report::preview`] renders exactly what would leave.
#[derive(Debug, Clone)]
pub struct Report {
    destination: Destination,
    template: String,
    title: Option<String>,
    fields: Vec<(String, String)>,
    /// Human labels per field id. GitHub's own form rendering emits
    /// `### <label>`, so carrying the label lets a route that posts a body
    /// produce an issue indistinguishable from a browser-submitted one.
    labels: Vec<(String, String)>,
    required: Vec<String>,
    provenance: Option<Provenance>,
    provenance_field: String,
    /// Labels to apply to the issue, from the form definition (e.g. `["bug"]`).
    /// Not the field labels above — these become `--label` on the `gh` CLI.
    issue_labels: Vec<String>,
    /// Title prefix from the form (e.g. `[bug] `), for the `gh` route to
    /// prepend to the title.
    title_prefix: Option<String>,
    diagnostics: Vec<Record>,
    transport: Transport,
    confirmed: bool,
}

impl Report {
    /// Start a report aimed at a repository.
    ///
    /// Prefer [`crate::report!`], which fills the destination from the calling
    /// crate's `repository` field.
    pub fn to(destination: Destination) -> Self {
        Self {
            destination,
            template: "bug.yml".into(),
            title: None,
            fields: Vec::new(),
            labels: Vec::new(),
            required: Vec::new(),
            provenance: None,
            provenance_field: "environment".into(),
            issue_labels: Vec::new(),
            title_prefix: None,
            diagnostics: Vec::new(),
            transport: Transport::default(),
            confirmed: false,
        }
    }

    /// The issue-form file to open, e.g. `bug.yml`.
    ///
    /// Not optional in practice: a repository with `blank_issues_enabled:
    /// false` shows the chooser rather than a form when this is absent.
    pub fn template(mut self, template: impl Into<String>) -> Self {
        self.template = template.into();
        self
    }

    /// Set a field by its issue-form `id`.
    pub fn field(mut self, id: impl Into<String>, value: impl Into<String>) -> Self {
        let id = id.into();
        let value = value.into();
        match self.fields.iter_mut().find(|(name, _)| *name == id) {
            Some((_, slot)) => *slot = value,
            None => self.fields.push((id, value)),
        }
        self
    }

    /// Adopt a [`Form`]: its template, labels, and required ids in one call.
    ///
    /// This is the seam that lets one composition serve a CLI, a GUI and an
    /// agent tool. The surface renders or prompts from `form.prompts()`, hands
    /// the answers back with [`Report::fields`], and everything else — which
    /// fields are mandatory, what heading each answer gets, which template to
    /// open — comes from the same definition rather than being restated per
    /// surface and drifting.
    pub fn form(mut self, form: &Form) -> Self {
        if let Some(template) = &form.template {
            self.template = template.clone();
        }
        if let Some(labels) = &form.labels {
            self.issue_labels = labels.clone();
        }
        if let Some(prefix) = &form.title_prefix {
            self.title_prefix = Some(prefix.clone());
        }
        for field in &form.fields {
            if field.kind.is_answerable() {
                self = self.label(field.id.clone(), field.label.clone());
            }
        }
        self = self.require(form.required_ids());
        self
    }

    /// Give a field the human label GitHub's form shows for it.
    ///
    /// Verified against repositories using issue forms: a form submission
    /// renders `### <label>` above each answer. Without the label a posted body
    /// falls back to the field id, and maintainers get two visually different
    /// issue shapes depending on which route the reporter used.
    pub fn label(mut self, id: impl Into<String>, label: impl Into<String>) -> Self {
        let id = id.into();
        let label = label.into();
        match self.labels.iter_mut().find(|(name, _)| *name == id) {
            Some((_, slot)) => *slot = label,
            None => self.labels.push((id, label)),
        }
        self
    }

    /// Set several fields at once.
    pub fn fields<I, K, V>(mut self, fields: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        for (id, value) in fields {
            self = self.field(id, value);
        }
        self
    }

    /// Mark fields as required, so [`Report::build`] refuses while they are
    /// empty and names them.
    ///
    /// GitHub enforces `required: true` in the browser, but only after the form
    /// has opened. Checking here means the reporter is told what is missing
    /// before anything is launched.
    pub fn require<I, S>(mut self, ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for id in ids {
            let id = id.into();
            // Deduped on insert. Both this and `form` used to extend blindly,
            // so a GUI re-applying its form per keystroke accumulated ids and
            // `MissingFields` came back as ["a","b","a","b"].
            if !self.required.contains(&id) {
                self.required.push(id);
            }
        }
        self
    }

    /// Attach the collected environment block.
    pub fn provenance(mut self, provenance: Provenance) -> Self {
        self.provenance = Some(provenance);
        self
    }

    /// The form field the environment block is written into. Defaults to
    /// `environment`.
    pub fn provenance_field(mut self, id: impl Into<String>) -> Self {
        self.provenance_field = id.into();
        self
    }

    /// Attach redacted log records.
    ///
    /// These are deliberately **not** placed in the URL — see [`crate::url`].
    /// They are rendered into [`Composed::diagnostics`] for the reporter to
    /// paste, or sent in the body on routes that have one.
    pub fn diagnostics(mut self, records: impl IntoIterator<Item = Record>) -> Self {
        self.diagnostics.extend(records);
        self
    }

    /// An issue title. Only used by routes that carry one separately from the
    /// form; the browser route lets the template's own title prefix apply.
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Choose a route. Defaults to [`Transport::Browser`].
    pub fn via(mut self, transport: Transport) -> Self {
        self.transport = transport;
        self
    }

    /// Record that a human has seen the preview and agreed to send.
    ///
    /// Required by routes that would otherwise transmit with no review surface
    /// in between. Calling it without actually showing anyone the preview
    /// defeats the only safeguard those routes have.
    pub fn confirmed(mut self) -> Self {
        self.confirmed = true;
        self
    }

    /// Assemble without sending.
    pub fn build(&self) -> Result<Composed> {
        // The provenance field counts as answered once provenance is attached.
        // It is filled below rather than through `field()`, so checking only
        // `self.fields` made a required machine-filled field permanently
        // unsatisfiable: `Report::form` adopts it from `Form::required_ids`,
        // the application supplies it as provenance, and `build` still
        // reported it missing. A consumer had no way out — the field is not
        // theirs to type.
        let provenance_supplied = self.provenance.is_some();
        let missing: Vec<String> = self
            .required
            .iter()
            .filter(|id| !(provenance_supplied && **id == self.provenance_field))
            .filter(|id| {
                self.fields
                    .iter()
                    .find(|(name, _)| name == *id)
                    .map(|(_, value)| value.trim().is_empty())
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        if !missing.is_empty() {
            return Err(Error::MissingFields(missing));
        }

        let mut values: Vec<(&str, String)> = self
            .fields
            .iter()
            .map(|(id, value)| (id.as_str(), value.clone()))
            .collect();

        if let Some(provenance) = &self.provenance {
            // Replace rather than append when the id is already present.
            // Pushing unconditionally emitted the parameter twice and rendered
            // two `### <label>` sections — and since a GitHub prefill takes the
            // last value, the reporter's own words were overwritten by the
            // environment block the moment the form opened. `environment` is a
            // common field id, so a form declaring one collided by default.
            let rendered = provenance.to_markdown();
            match values
                .iter_mut()
                .find(|(id, _)| *id == self.provenance_field)
            {
                // …but never replace something with nothing. A `Provenance`
                // that collected no entries renders empty, and overwriting a
                // reporter's own words with it deleted them — the field then
                // carried no value, so it never reached the URL and nothing
                // named it as dropped. Replacing an answer with a better one
                // is the documented behaviour; replacing it with silence is
                // not a version of that.
                Some((_, slot)) if !rendered.trim().is_empty() => *slot = rendered,
                Some(_) => {}
                None => values.push((self.provenance_field.as_str(), rendered)),
            }
        }

        let url = url::build(&self.destination, &self.template, &values);

        let diagnostics = (!self.diagnostics.is_empty()).then(|| {
            format!(
                "<details><summary>diagnostics ({} records, redacted)</summary>\n\n{}\n</details>\n",
                self.diagnostics.len(),
                render_block(&self.diagnostics)
            )
        });

        let body = render_body(&values, &self.labels, diagnostics.as_deref());

        Ok(Composed {
            destination: self.destination.clone(),
            title: self.title.clone(),
            url,
            body,
            diagnostics,
            labels: self.issue_labels.clone(),
            title_prefix: self.title_prefix.clone(),
        })
    }

    /// Render exactly what would leave the machine, without sending it.
    pub fn preview(&self) -> Result<String> {
        let composed = self.build()?;
        let mut out = format!(
            "destination: {}\nroute:       {}\n\n",
            composed.destination,
            self.transport.describe()
        );
        out.push_str(&composed.body);
        // The alarm is reserved for whole-field loss. It used to fire whenever
        // anything was shortened, which for a long log tail is nearly always —
        // and a warning that fires on almost every report teaches the reporter
        // to skip it on the one occasion it matters.
        if !composed.url.dropped.is_empty() {
            out.push_str(&format!(
                "\n! this report is too long to send through the browser, so \
                 these sections would NOT reach GitHub: {}\n  \
                 send it another way, or shorten what you wrote.\n",
                composed.url.dropped.join(", ")
            ));
        } else if !composed.url.shortened.is_empty() {
            out.push_str(&format!(
                "\n(some text was shortened to fit the link: {})\n",
                composed.url.shortened.join(", ")
            ));
        }
        Ok(out)
    }

    /// Compose and dispatch.
    pub fn send(&self) -> Result<Sent> {
        let composed = self.build()?;

        if self.transport.needs_explicit_confirmation() && !self.confirmed {
            return Err(Error::ConfirmationRequired(self.transport.describe()));
        }

        match &self.transport {
            Transport::Browser => {
                // Refuse rather than open a form the reporter has already
                // approved in a preview that showed MORE than will arrive.
                // Showing less than leaves is a privacy failure; showing more
                // corrupts what the reporter believes they consented to send,
                // and the maintainer closes an issue whose Reproduction
                // section is simply blank.
                //
                // Refused here rather than in `build`, because `build` is
                // route-agnostic: a File or Mailto report carries the whole
                // body and is perfectly valid. The crate also does not pick a
                // fallback route itself — which route to use is the surface's
                // decision (docs/stories.md).
                if !composed.url.dropped.is_empty() {
                    return Err(Error::FieldsDropped(composed.url.dropped.clone()));
                }
                #[cfg(feature = "browser")]
                {
                    crate::transport::open_in_browser(&composed.url.url)?;
                    Ok(Sent::Opened {
                        url: composed.url.url,
                        diagnostics: composed.diagnostics,
                    })
                }
                #[cfg(not(feature = "browser"))]
                {
                    Ok(Sent::Prepared {
                        url: composed.url.url,
                        diagnostics: composed.diagnostics,
                    })
                }
            }
            Transport::Mailto(to) => {
                let subject = composed
                    .title
                    .clone()
                    .unwrap_or_else(|| "Bug report".into());
                // Spliced raw, a `to` of `bugs@example.com?body=fake` produced
                // a URL whose FIRST `?` belongs to the attacker, so a mail
                // client splitting there prefills their body and drops the
                // report entirely.
                // `composed.body` and not a subset: mail is a body route.
                // README and `Error::FieldsDropped` both point a reporter
                // whose report was too long for the browser link at "a file,
                // mail, `gh`, or your endpoint", so this one has to carry the
                // whole thing — diagnostics included — or that advice is a
                // dead end.
                Ok(Sent::Mailto(format!(
                    "mailto:{}?subject={}&body={}",
                    percent_address(to),
                    percent(&subject),
                    percent(&composed.body)
                )))
            }
            Transport::File(path) => {
                std::fs::write(path, &composed.body)?;
                Ok(Sent::Written(path.clone()))
            }
            #[cfg(feature = "gh-cli")]
            Transport::GhCli => {
                let title = match (&composed.title, &composed.title_prefix) {
                    (Some(title), _) => title.clone(),
                    (None, Some(prefix)) => format!("{}Bug report", prefix),
                    (None, None) => "Bug report".into(),
                };

                // Pipe the body over stdin via `--body-file -`, so a 32 KB
                // report doesn't blow the Windows command-line limit and a
                // local user cannot read it from the process list.
                let run_gh = |labels: &[String]| -> Result<std::process::Output> {
                    let mut child = std::process::Command::new("gh")
                        .args([
                            "issue",
                            "create",
                            "--repo",
                            &composed.destination.slug(),
                            "--title",
                            &title,
                            // The body over stdin, never in argv.
                            "--body-file",
                            "-",
                        ])
                        .args(labels.iter().flat_map(|l| ["--label", l]))
                        .stdin(std::process::Stdio::piped())
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::piped())
                        .spawn()
                        .map_err(|err| Error::Spawn {
                            program: "gh".into(),
                            source: err,
                        })?;
                    // A closed pipe is not an error: `gh` may reject the request
                    // and exit before draining stdin, and the write we care
                    // about is the report, which it has already rejected.
                    if let Some(mut stdin) = child.stdin.take() {
                        use std::io::Write;
                        let _ = stdin.write_all(composed.body.as_bytes());
                    }
                    child.wait_with_output().map_err(|err| Error::Spawn {
                        program: "gh".into(),
                        source: err,
                    })
                };

                // Try with labels first; if a label doesn't exist in the
                // repo, `gh` fails the whole create. Retry without labels in
                // that case — a report with the wrong labels beats no report.
                let output = run_gh(&composed.labels)?;
                if output.status.success() {
                    return Ok(Sent::Created(
                        String::from_utf8_lossy(&output.stdout).trim().to_string(),
                    ));
                }

                let stderr = String::from_utf8_lossy(&output.stderr);
                if !composed.labels.is_empty() && is_missing_label(&stderr) {
                    // Deliberately narrow. A bare "not found" also covers a
                    // repository that does not exist, and retrying that would
                    // re-run a create that may already have succeeded on the
                    // server — filing the reporter's issue twice because their
                    // repo is misspelled.
                    let retry = run_gh(&[])?;
                    if retry.status.success() {
                        return Ok(Sent::Created(
                            String::from_utf8_lossy(&retry.stdout).trim().to_string(),
                        ));
                    }
                    return Err(gh_failed(&retry.stderr));
                }

                Err(gh_failed(&output.stderr))
            }
            #[cfg(feature = "endpoint")]
            Transport::Endpoint { url, auth } => {
                let mut request = ureq::post(url).set("content-type", "application/json");
                for (name, value) in auth.headers()? {
                    request = request.set(&name, &value);
                }
                let payload = serde_json::json!({
                    "title": composed.title.clone().unwrap_or_else(|| "Bug report".into()),
                    "body": composed.body,
                    "repository": composed.destination.slug(),
                });
                match request.send_json(payload) {
                    Ok(response) => Ok(Sent::Posted(
                        response
                            .into_string()
                            .unwrap_or_default()
                            .trim()
                            .to_string(),
                    )),
                    Err(ureq::Error::Status(code, response)) => Err(Error::Endpoint {
                        status: Some(code),
                        message: response.into_string().unwrap_or_default(),
                    }),
                    Err(err) => Err(Error::Endpoint {
                        status: None,
                        message: err.to_string(),
                    }),
                }
            }
        }
    }
}

/// Whether `gh` failed specifically because a label does not exist.
///
/// Narrow on purpose. The alternative — treating any "not found" as a missing
/// label — also catches a repository that does not exist or is misspelled, and
/// the retry would then re-run a create that may already have landed on the
/// server. Filing the same issue twice because a repo is misspelled is worse
/// than filing it unlabelled.
///
/// `gh`'s stderr is not a stable interface, so this is a heuristic and not a
/// contract: it exists to make the common case work, and the unlabelled retry
/// is the backstop when it does not.
#[cfg(feature = "gh-cli")]
fn is_missing_label(stderr: &str) -> bool {
    let lower = stderr.to_lowercase();
    lower.contains("label") && (lower.contains("not found") || lower.contains("does not exist"))
}

/// Classify a failed `gh` invocation, keeping its raw stderr.
///
/// The raw text travels with the error because the classification is
/// best-effort: a `gh` upgrade can change the wording, and a reporter staring
/// at "gh reported an error" has nothing to act on.
#[cfg(feature = "gh-cli")]
fn gh_failed(stderr: &[u8]) -> Error {
    let stderr = String::from_utf8_lossy(stderr);
    Error::GhFailed {
        kind: crate::error::classify_gh_stderr(&stderr),
        stderr: stderr.trim().to_string(),
    }
}

/// An assembled report.
#[derive(Debug, Clone)]
pub struct Composed {
    /// Where it is addressed.
    pub destination: Destination,
    /// The issue title, for routes that carry one separately from the form.
    pub title: Option<String>,
    /// The prefilled form URL, and an account of anything it could not carry.
    pub url: PrefilledUrl,
    /// The full markdown body, for routes that carry one.
    pub body: String,
    /// The fenced diagnostics block, when records were attached. Never part of
    /// the URL.
    pub diagnostics: Option<String>,
    /// Labels to apply to the issue, from the form definition. Only the `gh`
    /// route uses these; `Browser` gets them through the prefill URL.
    pub labels: Vec<String>,
    /// Title prefix from the form (e.g. `[bug] `), for the `gh` route to
    /// prepend when building the title.
    pub title_prefix: Option<String>,
}

/// What happened.
#[derive(Debug, Clone)]
pub enum Sent {
    /// The browser was opened. `diagnostics` still needs pasting by the human.
    Opened {
        /// What the browser was handed.
        url: String,
        /// The block the URL deliberately does not carry, for the reporter to
        /// paste into the open form.
        diagnostics: Option<String>,
    },
    /// Built but not opened — the `browser` feature is off.
    Prepared {
        /// Ready for whatever you use to open it.
        url: String,
        /// As for [`Sent::Opened`].
        diagnostics: Option<String>,
    },
    /// A `mailto:` URL carrying the whole report, for the reporter's mail
    /// client. Nothing has been sent: they still press Send.
    Mailto(String),
    /// The report was written here, and nothing left the machine.
    Written(std::path::PathBuf),
    /// `gh` created the issue. The URL it printed.
    Created(String),
    /// Your endpoint accepted the report. Whatever it answered with.
    Posted(String),
}

fn render_body(
    values: &[(&str, String)],
    labels: &[(String, String)],
    diagnostics: Option<&str>,
) -> String {
    let mut out = String::new();
    for (id, value) in values {
        // `### <label>` is what GitHub emits for a form submission; falling
        // back to the id keeps the body readable when no label was supplied.
        let heading = labels
            .iter()
            .find(|(name, _)| name == id)
            .map(|(_, label)| label.as_str())
            .unwrap_or(id);
        out.push_str(&format!("### {heading}\n\n{}\n\n", value.trim_end()));
    }
    if let Some(block) = diagnostics {
        out.push_str(block);
    }
    out
}

/// Percent-encode a mail address, keeping the characters an address is made
/// of so an ordinary one is unchanged.
///
/// `percent` is wrong here: it escapes `@`, which mangles every real address.
/// What has to be escaped is anything that could end the address and start a
/// new URL component — `?`, `&`, `#`, whitespace — per RFC 6068's addr-spec.
fn percent_address(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' => out.push(*byte as char),
            b'-' | b'_' | b'.' | b'~' | b'@' | b'+' | b'!' | b'$' | b'*' | b'\'' | b'(' | b')'
            | b',' | b';' | b':' => out.push(*byte as char),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn percent(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provenance::{Provenance, Value};

    fn report() -> Report {
        Report::to(Destination::parse("gerchowl/squelch").unwrap())
            .field("current-behavior", "it crashes")
            .field("reproduction", "run it twice")
    }

    #[test]
    fn refuses_while_required_fields_are_empty() {
        let err = report()
            .require(["current-behavior", "impact"])
            .build()
            .expect_err("should refuse");
        match err {
            Error::MissingFields(fields) => assert_eq!(fields, vec!["impact"]),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn provenance_lands_in_its_own_field() {
        let composed = report()
            .provenance(Provenance::new().with("Shell", Value::known("zsh")))
            .build()
            .unwrap();
        assert!(composed.url.url.contains("&environment="));
        assert!(composed.body.contains("- Shell: zsh"));
    }

    #[test]
    fn diagnostics_never_enter_the_url() {
        let composed = report()
            .diagnostics([Record {
                timestamp: "t".into(),
                level: "ERROR".into(),
                source: None,
                fields: vec![("program".into(), "zzmarkerzz".into())],
            }])
            .build()
            .unwrap();
        assert!(
            !composed.url.url.contains("zzmarkerzz"),
            "{}",
            composed.url.url
        );
        assert!(composed.diagnostics.unwrap().contains("zzmarkerzz"));
    }

    #[test]
    fn preview_names_the_destination_and_route() {
        let preview = report().preview().unwrap();
        assert!(preview.contains("destination: gerchowl/squelch"));
        assert!(preview.contains("browser"));
    }

    #[test]
    fn file_route_writes_the_body() {
        let path = std::env::temp_dir().join(format!("squelch-{}.md", std::process::id()));
        let sent = report().via(Transport::File(path.clone())).send().unwrap();
        assert!(matches!(sent, Sent::Written(_)));
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.contains("it crashes"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn mailto_route_encodes_the_body() {
        let sent = report()
            .title("crash on split")
            .via(Transport::Mailto("bugs@example.com".into()))
            .send()
            .unwrap();
        match sent {
            Sent::Mailto(url) => {
                assert!(url.starts_with("mailto:bugs@example.com?"));
                assert!(url.contains("subject=crash%20on%20split"));
                // The whole point of the route. This test was named
                // `..._encodes_the_body` while asserting only the subject, so
                // when the body was replaced with `percent("")` in a stray
                // edit it stayed green — a draft with an address, a subject,
                // and nothing to send.
                assert!(
                    url.contains(&percent("it crashes")),
                    "the composed body must be in the draft: {url}"
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn mailto_carries_the_whole_report_including_diagnostics() {
        // README and `Error::FieldsDropped`'s own text both send a reporter
        // whose report was too long for the browser link to "a file, mail,
        // `gh`, or your endpoint" — the routes that carry it whole. Mail has
        // to actually be one of those or that advice sends them nowhere.
        let sent = report()
            .diagnostics([Record {
                timestamp: "2026-08-12T00:00:00Z".into(),
                level: "error".into(),
                source: None,
                fields: vec![("message".into(), "zzmarkerzz".into())],
            }])
            .via(Transport::Mailto("bugs@example.com".into()))
            .send()
            .unwrap();
        match sent {
            Sent::Mailto(url) => assert!(
                url.contains(&percent("zzmarkerzz")),
                "diagnostics are excluded from the GitHub URL by design, but \
                 mail is a body route and carries them: {url}"
            ),
            other => panic!("{other:?}"),
        }
    }

    #[cfg(feature = "gh-cli")]
    #[test]
    fn credential_routes_refuse_without_confirmation() {
        let err = report().via(Transport::GhCli).send().expect_err("refuse");
        assert!(matches!(err, Error::ConfirmationRequired(_)));
    }

    #[test]
    fn a_form_supplies_labels_template_and_required_ids() {
        use crate::form::{Field, Form};

        let form = Form::new([
            Field::textarea("current-behavior", "Current behavior").required(),
            Field::textarea("reproduction", "Reproduction").required(),
        ])
        .template("crash.yml");

        // Only one of the two required fields is answered.
        let report = Report::to(Destination::parse("gerchowl/squelch").unwrap())
            .form(&form)
            .field("current-behavior", "it crashes");

        match report.build() {
            Err(Error::MissingFields(missing)) => assert_eq!(missing, vec!["reproduction"]),
            other => panic!("{other:?}"),
        }

        let composed = report.field("reproduction", "run twice").build().unwrap();
        // The label from the form became the heading, matching GitHub's own
        // rendering of a form submission.
        assert!(
            composed.body.contains("### Current behavior"),
            "{}",
            composed.body
        );
        assert!(composed.url.url.contains("template=crash.yml"));
    }

    #[test]
    fn setting_a_field_twice_replaces_rather_than_duplicates() {
        let composed = report()
            .field("current-behavior", "actually it hangs")
            .build()
            .unwrap();
        assert!(composed.body.contains("actually it hangs"));
        assert!(!composed.body.contains("it crashes"));
    }

    #[test]
    fn the_provenance_field_does_not_duplicate_a_form_field() {
        use crate::form::{Field, Form};

        // `environment` is a common field id, and it is also the default
        // provenance field, so a form declaring one collided by default. The
        // parameter was emitted twice; since a GitHub prefill takes the last
        // value, the reporter's own words were overwritten the moment the form
        // opened.
        let form = Form::new([
            Field::textarea("current-behavior", "Current behavior"),
            Field::textarea("environment", "Environment"),
        ]);
        let composed = Report::to(Destination::parse("gerchowl/squelch").unwrap())
            .form(&form)
            .field("current-behavior", "it crashes")
            .field("environment", "typed by the reporter")
            .provenance(Provenance::new().with("Shell", Value::known("zsh")))
            .build()
            .unwrap();

        assert_eq!(
            composed.url.url.matches("&environment=").count(),
            1,
            "environment was sent twice: {}",
            composed.url.url
        );
        assert_eq!(
            composed.body.matches("### Environment").count(),
            1,
            "the body carries two Environment sections: {}",
            composed.body
        );
    }

    #[test]
    fn applying_the_same_form_twice_changes_nothing() {
        use crate::form::{Field, Form};

        // A GUI re-applies its form on every keystroke. Both `form` and
        // `require` used to extend blindly, so required ids accumulated and
        // `MissingFields` came back as ["a","b","a","b"] — confusing, and
        // O(n^2) over a session.
        let form = Form::new([
            Field::textarea("current-behavior", "Current behavior").required(),
            Field::textarea("reproduction", "Reproduction").required(),
        ]);
        let once = Report::to(Destination::parse("gerchowl/squelch").unwrap()).form(&form);
        let twice = Report::to(Destination::parse("gerchowl/squelch").unwrap())
            .form(&form)
            .form(&form);

        let missing = |report: &Report| match report.build() {
            Err(Error::MissingFields(fields)) => fields,
            other => panic!("expected MissingFields, got {other:?}"),
        };
        assert_eq!(missing(&once), missing(&twice));
        assert_eq!(missing(&twice), vec!["current-behavior", "reproduction"]);
    }

    #[test]
    fn the_browser_route_refuses_a_report_it_cannot_carry_whole() {
        // The reporter approves a preview showing every section, so opening a
        // form that silently lacks one breaks the only promise the tool makes.
        let report = report()
            .field("current-behavior", "x".repeat(40_000))
            .field("reproduction", "run it twice")
            .via(Transport::Browser);

        match report.send() {
            Err(Error::FieldsDropped(fields)) => {
                assert_eq!(fields, vec!["reproduction".to_string()]);
            }
            other => panic!("browser send must refuse a mutilated payload: {other:?}"),
        }

        // A route that carries the whole body is unaffected — the report is
        // fine, it is the URL that cannot hold it.
        let path = std::env::temp_dir().join(format!("squelch-drop-{}.md", std::process::id()));
        let sent = report.via(Transport::File(path.clone())).send();
        assert!(sent.is_ok(), "the file route must still work: {sent:?}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_preview_names_dropped_sections_and_stays_quiet_about_trimming() {
        let dropped = report()
            .field("current-behavior", "x".repeat(40_000))
            .field("reproduction", "run it twice")
            .preview()
            .unwrap();
        assert!(dropped.contains("would NOT reach GitHub"), "{dropped}");
        assert!(dropped.contains("reproduction"), "{dropped}");

        // Shortening alone is routine. It gets a parenthetical, not an alarm —
        // a warning that fires on every long log is one nobody reads.
        // A fresh report with ONE field: the helper above sets two, and a
        // second field would be dropped rather than shortened.
        let shortened = Report::to(Destination::parse("gerchowl/squelch").unwrap())
            .field("current-behavior", "x".repeat(40_000))
            .preview()
            .unwrap();
        assert!(!shortened.contains("would NOT reach GitHub"), "{shortened}");
        assert!(shortened.contains("shortened to fit"), "{shortened}");
    }
}
