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
        for field in &form.fields {
            if field.kind.is_answerable() {
                self = self.label(field.id.clone(), field.label.clone());
            }
        }
        self.required.extend(form.required_ids());
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
        self.required.extend(ids.into_iter().map(Into::into));
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
        let missing: Vec<String> = self
            .required
            .iter()
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
            values.push((self.provenance_field.as_str(), provenance.to_markdown()));
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
        if composed.url.truncated {
            out.push_str(
                "\n! some text was shortened to fit GitHub's URL limit — \
                 the full text is NOT in the link\n",
            );
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
                Ok(Sent::Mailto(format!(
                    "mailto:{to}?subject={}&body={}",
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
                let title = composed
                    .title
                    .clone()
                    .unwrap_or_else(|| "Bug report".into());
                let output = std::process::Command::new("gh")
                    .args([
                        "issue",
                        "create",
                        "--repo",
                        &composed.destination.slug(),
                        "--title",
                        &title,
                        "--body",
                        &composed.body,
                    ])
                    .output()
                    .map_err(|err| Error::Spawn {
                        program: "gh".into(),
                        source: err,
                    })?;
                if !output.status.success() {
                    return Err(Error::OpenerFailed(
                        String::from_utf8_lossy(&output.stderr).trim().to_string(),
                    ));
                }
                Ok(Sent::Created(
                    String::from_utf8_lossy(&output.stdout).trim().to_string(),
                ))
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

/// An assembled report.
#[derive(Debug, Clone)]
pub struct Composed {
    pub destination: Destination,
    pub title: Option<String>,
    pub url: PrefilledUrl,
    /// The full markdown body, for routes that carry one.
    pub body: String,
    /// The fenced diagnostics block, when records were attached. Never part of
    /// the URL.
    pub diagnostics: Option<String>,
}

/// What happened.
#[derive(Debug, Clone)]
pub enum Sent {
    /// The browser was opened. `diagnostics` still needs pasting by the human.
    Opened {
        url: String,
        diagnostics: Option<String>,
    },
    /// Built but not opened — the `browser` feature is off.
    Prepared {
        url: String,
        diagnostics: Option<String>,
    },
    Mailto(String),
    Written(std::path::PathBuf),
    Created(String),
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
            }
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
}
