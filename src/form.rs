//! What a report asks for — the field definitions every surface needs.
//!
//! # squelch does not choose your format
//!
//! A [`Form`] is a plain data structure. How you obtain one is your business:
//! declare it in Rust, deserialize it from the YAML you already keep in
//! `.github/ISSUE_TEMPLATE/`, or from JSON, TOML, RON, or anything else with a
//! serde implementation. Enable the `serde` feature and bring your own parser.
//!
//! This crate takes **no format dependency**, because every consumer already
//! has a format and a deserializer, and inheriting ours would be a tax.
//!
//! ```ignore
//! // whichever of these you already depend on
//! let form: Form = serde_yaml::from_str::<github::IssueForm>(&yaml)?.into();
//! let form: Form = serde_json::from_str(&json)?;
//! let form: Form = ron::from_str(&ron)?;
//! ```
//!
//! # Why a form model exists at all
//!
//! A CLI can get by with "here is a field id and a value". A GUI cannot — it
//! has to *render* the inputs, which means it needs labels, help text, which
//! fields are required, and whether each is one line or many. An agent surface
//! needs the same information as a schema so it does not guess at field names.
//!
//! Without this, the crate would be a CLI library wearing a general-purpose
//! name.

/// A field's input shape, so a surface knows how to present it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum FieldKind {
    /// One line.
    Input,
    /// Many lines.
    Textarea,
    /// One of a fixed set.
    Dropdown { options: Vec<String> },
    /// Zero or more of a fixed set.
    ///
    /// Cannot be prefilled from a GitHub URL, and should not be filled
    /// programmatically anyway: a "yes, I confirm" box is an attestation, and
    /// a tool that ticks it forges a human's statement.
    Checkboxes { options: Vec<String> },
    /// Static text shown to the reporter. Carries no answer.
    Markdown,
}

impl FieldKind {
    /// Whether this field can hold an answer at all.
    pub fn is_answerable(&self) -> bool {
        !matches!(self, Self::Markdown)
    }

    /// Whether a machine may fill this in on the reporter's behalf.
    pub fn is_machine_fillable(&self) -> bool {
        matches!(self, Self::Input | Self::Textarea)
    }
}

/// One field of a report form.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Field {
    /// The form's `id`, used as the URL query parameter and the answer key.
    pub id: String,
    /// The human label. GitHub renders `### <label>` above the answer, so
    /// carrying it lets a posted body match a form-submitted one.
    pub label: String,
    /// Help text shown under the label.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub description: Option<String>,
    #[cfg_attr(feature = "serde", serde(default))]
    pub required: bool,
    pub kind: FieldKind,
    /// This field is filled by the application, not the reporter — an
    /// environment block, for instance. Surfaces should not prompt for it.
    #[cfg_attr(feature = "serde", serde(default))]
    pub machine_filled: bool,
}

impl Field {
    pub fn new(id: impl Into<String>, label: impl Into<String>, kind: FieldKind) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            description: None,
            required: false,
            kind,
            machine_filled: false,
        }
    }

    pub fn textarea(id: impl Into<String>, label: impl Into<String>) -> Self {
        Self::new(id, label, FieldKind::Textarea)
    }

    pub fn input(id: impl Into<String>, label: impl Into<String>) -> Self {
        Self::new(id, label, FieldKind::Input)
    }

    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }

    pub fn machine_filled(mut self) -> Self {
        self.machine_filled = true;
        self
    }

    pub fn describe(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }
}

/// A report form: the fields, in the order they should be presented.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Form {
    /// The issue-form file this corresponds to, e.g. `bug.yml`. Needed to open
    /// the right form in a browser.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub template: Option<String>,
    /// A title prefix the template applies, e.g. `[bug] `.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub title_prefix: Option<String>,
    pub fields: Vec<Field>,
}

impl Form {
    pub fn new(fields: impl IntoIterator<Item = Field>) -> Self {
        Self {
            template: None,
            title_prefix: None,
            fields: fields.into_iter().collect(),
        }
    }

    pub fn template(mut self, template: impl Into<String>) -> Self {
        self.template = Some(template.into());
        self
    }

    pub fn field(&self, id: &str) -> Option<&Field> {
        self.fields.iter().find(|field| field.id == id)
    }

    /// Fields a human is expected to answer: answerable, not machine-filled,
    /// and not an attestation the tool must not tick.
    pub fn prompts(&self) -> impl Iterator<Item = &Field> {
        self.fields
            .iter()
            .filter(|field| field.kind.is_machine_fillable() && !field.machine_filled)
    }

    /// Ids of the fields that must be answered.
    pub fn required_ids(&self) -> Vec<String> {
        self.fields
            .iter()
            .filter(|field| field.required && field.kind.is_machine_fillable())
            .map(|field| field.id.clone())
            .collect()
    }

    /// An editable markdown skeleton, for a CLI that opens `$EDITOR`.
    ///
    /// Guidance rides in HTML comments so it can be left in place and still be
    /// stripped on the way back by [`Form::parse_skeleton`].
    pub fn skeleton(&self) -> String {
        // Guidance rides in an HTML comment, so any text interpolated into it
        // must not be able to close it. A description containing `-->` ended
        // the comment early and the remainder rendered as literal text in the
        // reporter's editor; a description containing a newline escaped it
        // entirely and became content in the parsed answer.
        //
        // Escaped rather than re-mechanised. Switching to git's `#`-prefixed
        // convention was considered and rejected: with `## <id>` as the heading
        // syntax, stripping `# ` lines would silently swallow a reporter's own
        // markdown headings — the same silent-loss failure this guards against.
        fn guidance(text: &str) -> String {
            let flattened: String = text
                .chars()
                .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
                .collect();
            flattened.replace("-->", "--\u{200b}>")
        }
        let mut out = String::new();
        for field in &self.fields {
            match &field.kind {
                FieldKind::Markdown => continue,
                FieldKind::Checkboxes { .. } => {
                    out.push_str(&format!(
                        "\n<!-- \"{}\" is confirmed by you, not by this tool. -->\n",
                        guidance(&field.label)
                    ));
                }
                _ if field.machine_filled => {
                    out.push_str(&format!(
                        "\n<!-- \"{}\" is filled in automatically. -->\n",
                        guidance(&field.label)
                    ));
                }
                _ => {
                    out.push_str(&format!("\n## {}\n", field.id));
                    if let Some(description) = &field.description {
                        out.push_str(&format!("<!-- {} -->\n", guidance(description)));
                    } else {
                        out.push_str(&format!("<!-- {} -->\n", guidance(&field.label)));
                    }
                    out.push('\n');
                }
            }
        }
        out
    }

    /// Read a filled skeleton back into `(id, value)` pairs.
    ///
    /// Headings inside a fenced code block are content, not structure —
    /// reproduction steps routinely paste shell transcripts, and treating a
    /// `##` inside a fence as a new section silently truncates the report.
    pub fn parse_skeleton(text: &str) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = Vec::new();
        let mut current: Option<String> = None;
        // Which marker opened the current fence, so a ``` block is closed by
        // ``` and not by a stray ~~~ inside it. One flag for both let a
        // legitimate `~~~` in a shell transcript close the block early, after
        // which the next `##` split the content across sections it never
        // belonged to.
        let mut fence: Option<&str> = None;

        for line in text.lines() {
            let trimmed = line.trim();
            // Four-space indentation is a code block in CommonMark, so a `##`
            // there is content. Treating it as a heading invented a section and
            // silently emptied the real one.
            let indented = line.starts_with("    ") || line.starts_with('\t');
            let marker = if trimmed.starts_with("```") {
                Some("```")
            } else if trimmed.starts_with("~~~") {
                Some("~~~")
            } else {
                None
            };
            if let Some(marker) = marker {
                match fence {
                    Some(open) if open == marker => fence = None,
                    Some(_) => {}
                    None => fence = Some(marker),
                }
            } else if fence.is_none() && !indented {
                if let Some(heading) = trimmed.strip_prefix("## ") {
                    current = Some(heading.trim().to_string());
                    continue;
                }
                if trimmed.starts_with("<!--") {
                    continue;
                }
            }
            if let Some(id) = &current {
                match out.iter_mut().find(|(name, _)| name == id) {
                    Some((_, value)) => {
                        value.push_str(line);
                        value.push('\n');
                    }
                    None => out.push((id.clone(), format!("{line}\n"))),
                }
            }
        }

        out.into_iter()
            .map(|(id, value)| (id, value.trim().to_string()))
            .filter(|(_, value)| !value.is_empty())
            .collect()
    }

    /// A JSON Schema for the answerable fields, for an agent tool surface.
    ///
    /// Deliberately describes only what a machine may fill: attestations and
    /// machine-filled blocks are excluded, so an agent cannot be asked to tick
    /// a confirmation box.
    #[cfg(feature = "schema")]
    pub fn json_schema(&self) -> serde_json::Value {
        let mut properties = serde_json::Map::new();
        for field in self.prompts() {
            let mut spec = serde_json::Map::new();
            spec.insert("type".into(), "string".into());
            let description = field
                .description
                .clone()
                .unwrap_or_else(|| field.label.clone());
            spec.insert("description".into(), description.into());
            properties.insert(field.id.clone(), spec.into());
        }
        // Required is derived from `prompts()`, NOT from `required_ids()`.
        // The two answer different questions: `required_ids` is what the
        // REPORT must carry before it may be built, which includes
        // machine-filled blocks like `environment` — the application supplies
        // those. `properties` here lists only what an agent may fill.
        //
        // Using `required_ids` made the schema unsatisfiable: `environment`
        // appeared under `required` but not under `properties`, and with
        // `additionalProperties: false` an agent could neither omit it nor
        // supply it. Every conforming object was rejected.
        let required: Vec<String> = self
            .prompts()
            .filter(|field| field.required)
            .map(|field| field.id.clone())
            .collect();

        serde_json::json!({
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": false,
        })
    }
}

/// GitHub's issue-form schema, for consumers who keep their form in
/// `.github/ISSUE_TEMPLATE/`.
///
/// These mirror [GitHub's documented syntax][syntax] rather than any particular
/// project's template, so they cannot drift from a file we do not control.
/// Bring your own deserializer:
///
/// ```ignore
/// let yaml = std::fs::read_to_string(".github/ISSUE_TEMPLATE/bug.yml")?;
/// let form: Form = serde_yaml::from_str::<github::IssueForm>(&yaml)?.into();
/// ```
///
/// [syntax]: https://docs.github.com/en/communities/using-templates-to-encourage-useful-issues-and-pull-requests/syntax-for-issue-forms
#[cfg(feature = "serde")]
pub mod github {
    use super::{Field, FieldKind, Form};

    #[derive(Debug, Clone, serde::Deserialize)]
    pub struct IssueForm {
        pub name: Option<String>,
        pub description: Option<String>,
        /// A title prefix, e.g. `[bug] `.
        pub title: Option<String>,
        pub body: Vec<Element>,
    }

    #[derive(Debug, Clone, serde::Deserialize)]
    #[serde(tag = "type", rename_all = "lowercase")]
    pub enum Element {
        Markdown {
            #[serde(default)]
            id: Option<String>,
            attributes: MarkdownAttributes,
        },
        Input {
            id: Option<String>,
            attributes: InputAttributes,
            #[serde(default)]
            validations: Validations,
        },
        Textarea {
            id: Option<String>,
            attributes: InputAttributes,
            #[serde(default)]
            validations: Validations,
        },
        Dropdown {
            id: Option<String>,
            attributes: ChoiceAttributes,
            #[serde(default)]
            validations: Validations,
        },
        Checkboxes {
            id: Option<String>,
            attributes: CheckboxAttributes,
            #[serde(default)]
            validations: Validations,
        },
    }

    #[derive(Debug, Clone, serde::Deserialize)]
    pub struct MarkdownAttributes {
        pub value: String,
    }

    #[derive(Debug, Clone, serde::Deserialize)]
    pub struct InputAttributes {
        pub label: String,
        pub description: Option<String>,
    }

    #[derive(Debug, Clone, serde::Deserialize)]
    pub struct ChoiceAttributes {
        pub label: String,
        pub description: Option<String>,
        #[serde(default)]
        pub options: Vec<String>,
    }

    #[derive(Debug, Clone, serde::Deserialize)]
    pub struct CheckboxAttributes {
        pub label: String,
        pub description: Option<String>,
        #[serde(default)]
        pub options: Vec<CheckboxOption>,
    }

    #[derive(Debug, Clone, serde::Deserialize)]
    pub struct CheckboxOption {
        pub label: String,
        #[serde(default)]
        pub required: bool,
    }

    #[derive(Debug, Clone, Default, serde::Deserialize)]
    pub struct Validations {
        #[serde(default)]
        pub required: bool,
    }

    impl From<IssueForm> for Form {
        fn from(source: IssueForm) -> Self {
            let mut fields = Vec::new();
            for (index, element) in source.body.into_iter().enumerate() {
                // GitHub allows an element to omit `id`; synthesise a stable one
                // so a surface still has a key, even though such a field cannot
                // be prefilled by URL.
                let fallback = format!("field-{index}");
                let field = match element {
                    Element::Markdown { id, attributes } => Field {
                        id: id.unwrap_or(fallback),
                        label: attributes.value.chars().take(60).collect(),
                        description: None,
                        required: false,
                        kind: FieldKind::Markdown,
                        machine_filled: false,
                    },
                    Element::Input {
                        id,
                        attributes,
                        validations,
                    } => build(
                        id,
                        fallback,
                        attributes,
                        validations.required,
                        FieldKind::Input,
                    ),
                    Element::Textarea {
                        id,
                        attributes,
                        validations,
                    } => build(
                        id,
                        fallback,
                        attributes,
                        validations.required,
                        FieldKind::Textarea,
                    ),
                    Element::Dropdown {
                        id,
                        attributes,
                        validations,
                    } => Field {
                        id: id.unwrap_or(fallback),
                        label: attributes.label,
                        description: attributes.description,
                        required: validations.required,
                        kind: FieldKind::Dropdown {
                            options: attributes.options,
                        },
                        machine_filled: false,
                    },
                    Element::Checkboxes {
                        id,
                        attributes,
                        validations,
                    } => {
                        let any_required =
                            validations.required || attributes.options.iter().any(|o| o.required);
                        Field {
                            id: id.unwrap_or(fallback),
                            label: attributes.label,
                            description: attributes.description,
                            required: any_required,
                            kind: FieldKind::Checkboxes {
                                options: attributes
                                    .options
                                    .into_iter()
                                    .map(|option| option.label)
                                    .collect(),
                            },
                            machine_filled: false,
                        }
                    }
                };
                fields.push(field);
            }

            Form {
                template: None,
                title_prefix: source.title,
                fields,
            }
        }
    }

    fn build(
        id: Option<String>,
        fallback: String,
        attributes: InputAttributes,
        required: bool,
        kind: FieldKind,
    ) -> Field {
        Field {
            id: id.unwrap_or(fallback),
            label: attributes.label,
            description: attributes.description,
            required,
            kind,
            machine_filled: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form() -> Form {
        Form::new([
            Field::textarea("current-behavior", "Current behavior").required(),
            Field::textarea("reproduction", "Reproduction").required(),
            Field::textarea("environment", "Environment")
                .required()
                .machine_filled(),
            Field::new(
                "confirm",
                "Is this reproducible?",
                FieldKind::Checkboxes {
                    options: vec!["I confirm".into()],
                },
            )
            .required(),
        ])
        .template("bug.yml")
    }

    #[test]
    fn prompts_exclude_attestations_and_machine_blocks() {
        let form = form();
        let ids: Vec<&str> = form.prompts().map(|field| field.id.as_str()).collect();
        assert_eq!(ids, vec!["current-behavior", "reproduction"]);
    }

    #[test]
    fn required_ids_skip_the_checkbox() {
        // The tool must never be asked to satisfy an attestation.
        let required = form().required_ids();
        assert!(!required.contains(&"confirm".to_string()));
        assert!(required.contains(&"reproduction".to_string()));
    }

    #[test]
    fn skeleton_round_trips() {
        let filled = form().skeleton().replace(
            "## current-behavior\n<!-- Current behavior -->\n",
            "## current-behavior\nit crashes\n",
        );
        let parsed = Form::parse_skeleton(&filled);
        assert_eq!(
            parsed
                .iter()
                .find(|(id, _)| id == "current-behavior")
                .map(|(_, v)| v.as_str()),
            Some("it crashes")
        );
    }

    #[test]
    fn skeleton_omits_checkboxes_and_machine_fields() {
        let out = form().skeleton();
        assert!(!out.contains("## confirm"), "{out}");
        assert!(!out.contains("## environment"), "{out}");
        assert!(out.contains("## reproduction"), "{out}");
    }

    #[test]
    fn headings_inside_a_fence_are_content() {
        let parsed = Form::parse_skeleton(
            "## reproduction\nRun:\n```sh\n## install\nmake test\n```\nThen it dies.\n",
        );
        let repro = &parsed
            .iter()
            .find(|(id, _)| id == "reproduction")
            .unwrap()
            .1;
        assert!(repro.contains("## install"), "{repro}");
        assert!(repro.contains("Then it dies."), "{repro}");
        assert!(!parsed.iter().any(|(id, _)| id == "install"));
    }

    #[cfg(feature = "schema")]
    #[test]
    fn json_schema_describes_only_fillable_fields() {
        let schema = form().json_schema();
        let properties = schema["properties"].as_object().unwrap();
        assert!(properties.contains_key("reproduction"));
        assert!(!properties.contains_key("confirm"));
        assert!(!properties.contains_key("environment"));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn parses_githubs_own_issue_form_schema() {
        // Deliberately JSON: it is serde, so the same structs accept the YAML a
        // consumer keeps in .github/ — squelch takes no format dependency.
        let json = r#"{
          "name": "Bug report",
          "title": "[bug] ",
          "body": [
            {"type": "markdown", "attributes": {"value": "Thanks for filing!"}},
            {"type": "textarea", "id": "current-behavior",
             "attributes": {"label": "Current behavior", "description": "What happens now?"},
             "validations": {"required": true}},
            {"type": "checkboxes", "id": "confirm",
             "attributes": {"label": "Confirm", "options": [{"label": "I confirm", "required": true}]}}
          ]
        }"#;
        let parsed: github::IssueForm = serde_json::from_str(json).expect("parse");
        let form: Form = parsed.into();

        assert_eq!(form.title_prefix.as_deref(), Some("[bug] "));
        assert_eq!(form.fields.len(), 3);

        let current = form.field("current-behavior").expect("field");
        assert_eq!(current.label, "Current behavior");
        assert!(current.required);
        assert_eq!(current.kind, FieldKind::Textarea);

        // The attestation survives as a checkbox, and is excluded from prompts.
        let confirm = form.field("confirm").expect("field");
        assert!(matches!(confirm.kind, FieldKind::Checkboxes { .. }));
        assert!(confirm.required);
        assert!(!form.required_ids().contains(&"confirm".to_string()));

        // Markdown blocks carry no answer.
        assert!(form.fields.iter().any(|f| f.kind == FieldKind::Markdown));
    }

    #[test]
    fn a_tilde_fence_does_not_close_a_backtick_fence() {
        // A shell transcript containing `~~~` closed the ``` block early, and
        // the next `##` then split the reporter's content across sections it
        // never belonged to.
        let parsed = Form::parse_skeleton(
            "## reproduction\nRun:\n```sh\n~~~\n## not a heading\n```\nThen it dies.\n",
        );
        let repro = &parsed
            .iter()
            .find(|(id, _)| id == "reproduction")
            .expect("reproduction survived")
            .1;
        assert!(repro.contains("## not a heading"), "{repro}");
        assert!(repro.contains("Then it dies."), "{repro}");
        assert!(!parsed.iter().any(|(id, _)| id == "not a heading"));
    }

    #[test]
    fn an_indented_heading_is_code_not_structure() {
        // Four spaces is a code block in CommonMark. Treating the `##` there as
        // a heading invented a section and silently emptied the real one.
        let parsed = Form::parse_skeleton("## reproduction\n    ## indented\nreal content\n");
        assert!(
            parsed.iter().any(|(id, _)| id == "reproduction"),
            "the real section was emptied: {parsed:?}"
        );
        assert!(!parsed.iter().any(|(id, _)| id == "indented"), "{parsed:?}");
    }

    #[test]
    fn a_description_cannot_close_the_comment_it_rides_in() {
        // `-->` inside guidance ended the comment early, so the rest rendered
        // as literal text in the reporter's editor — and a newline escaped it
        // altogether, turning guidance into the reporter's answer.
        let form =
            Form::new([Field::textarea("repro", "Repro")
                .describe("hostile --> escape\nand a newline --> too")]);
        let skeleton = form.skeleton();

        let guidance: Vec<&str> = skeleton
            .lines()
            .filter(|line| line.trim_start().starts_with("<!--"))
            .collect();
        assert_eq!(guidance.len(), 1, "guidance split across lines: {skeleton}");
        assert_eq!(
            guidance[0].matches("-->").count(),
            1,
            "the comment is closed more than once: {skeleton}"
        );

        // And the reporter's own answer is unaffected by it.
        let filled = skeleton.replace("## repro\n", "## repro\nit crashes\n");
        let parsed = Form::parse_skeleton(&filled);
        assert_eq!(
            parsed
                .iter()
                .find(|(id, _)| id == "repro")
                .map(|(_, value)| value.as_str()),
            Some("it crashes")
        );
    }
}
