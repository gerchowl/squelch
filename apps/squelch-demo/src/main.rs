//! A minimal application embedding squelch.
//!
//! This is the reporter surface from `docs/stories.md`: the human describes
//! what broke, and the machine supplies everything else. It exists to be
//! *driven* — the end-to-end tests run this binary against fake receivers and
//! assert on what arrived, which is the only place the transport layer is
//! exercised for real.
//!
//! Deliberately not a general-purpose tool. The destination and the form are
//! the embedder's decision, hardcoded here the way a real application would
//! hardcode its own.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use squelch::{provenance, Destination, Redactor, Report, Transport, Value};

#[derive(Parser, Debug)]
#[command(name = "squelch-demo", about = "File a bug report about this app")]
struct Cli {
    /// Where the issue goes. A real app would not expose this.
    #[arg(long, default_value = "gerchowl/squelch", global = true)]
    repo: String,

    /// What the reporter observed.
    #[arg(long, global = true, default_value = "every git operation fails")]
    current: String,

    /// How to reproduce it.
    #[arg(long, global = true, default_value = "run `demo sync` twice")]
    repro: String,

    /// A JSONL log file to attach, redacted.
    #[arg(long, global = true)]
    log: Option<PathBuf>,

    /// Stand in for a value the application knows and the reporter does not.
    /// Present so the tests can prove provenance is scrubbed on the way out.
    #[arg(long, global = true)]
    workdir: Option<String>,

    /// Attach a `Record` built by hand from this text, rather than parsed from
    /// JSONL by the redactor.
    ///
    /// Not a contrivance: `Record`'s fields are all public and
    /// `Report::diagnostics` accepts any `IntoIterator<Item = Record>`, so an
    /// application that already holds structured logs in memory — a `tracing`
    /// layer, a ring buffer — is expected to build them directly. That path
    /// never touches `Redactor`, so it is the one that has to prove it still
    /// cannot inject markup.
    #[arg(long, global = true)]
    raw_record: Option<String>,

    #[command(subcommand)]
    route: Route,
}

#[derive(Subcommand, Debug)]
enum Route {
    /// Render exactly what would leave, and send nothing.
    Preview,
    /// Write the report to a file.
    File { out: PathBuf },
    /// Build a mailto: URL for the reporter's mail client.
    Mailto { to: String },
    /// Open GitHub's prefilled form in a browser.
    Browser,
    /// Create the issue with the reporter's own `gh`.
    Gh {
        /// Stand in for the human having seen the preview and agreed.
        #[arg(long)]
        confirm: bool,
    },
    /// Print the JSON schema of the fields an agent may fill.
    ///
    /// The agent surface from docs/stories.md. Deliberately describes only
    /// machine-fillable fields, so an agent is never asked to tick an
    /// attestation checkbox.
    Schema,
    /// Compose from an agent-supplied JSON object and return the payload.
    ///
    /// Sends nothing, ever, and takes no route argument — an agent composes
    /// and hands to a human. That is the property the maintainer story asks
    /// for: "an agent must be unable to file without a human".
    Compose {
        /// A JSON object of `{ "field-id": "answer" }`.
        json: String,
    },
    /// POST to an endpoint the project operates.
    Endpoint {
        url: String,
        #[arg(long)]
        confirm: bool,
        /// Send a per-request credential, exercising `Auth::Bearer`.
        #[arg(long)]
        token: Option<String>,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            // A report path that fails must say why. Writing to stderr and
            // returning non-zero is what lets the e2e tests assert on refusals
            // as precisely as on successes.
            eprintln!("squelch-demo: {err}");
            ExitCode::FAILURE
        }
    }
}

/// The form this application reports against.
///
/// One definition, read by all three surfaces: the CLI prompts from it, the
/// agent surface turns it into a schema, and a GUI would render it. `Report`
/// takes its template, labels and required ids from the same value, so no
/// surface restates them and drifts.
fn form() -> squelch::Form {
    use squelch::{Field, FieldKind};
    squelch::Form::new([
        Field::textarea("current-behavior", "Current behavior")
            .required()
            .describe("What happens now?"),
        Field::textarea("reproduction", "Reproduction")
            .required()
            .describe("Steps that trigger it."),
        Field::textarea("environment", "Environment")
            .required()
            .machine_filled(),
        Field::new(
            "confirm",
            "Is this reproducible?",
            FieldKind::Checkboxes {
                options: vec!["I can reproduce this".into()],
            },
        )
        .required(),
    ])
    .template("bug.yml")
}

fn run() -> Result<String, Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let redactor = Redactor::new();

    // Answered before anything is collected: neither surface reads a log file
    // or touches the environment.
    match &cli.route {
        Route::Schema => {
            return Ok(serde_json::to_string_pretty(&form().json_schema())?);
        }
        Route::Compose { json } => {
            let answers: serde_json::Value = serde_json::from_str(json)?;
            let object = answers
                .as_object()
                .ok_or("the agent payload must be a JSON object of field answers")?;

            // `additionalProperties: false` is a promise the surface has to
            // keep. Silently passing an undeclared key through would let an
            // agent write into a field the schema never offered it — an
            // attestation checkbox, say — which is the one thing this surface
            // exists to prevent.
            let form = form();
            let offered: Vec<&str> = form.prompts().map(|field| field.id.as_str()).collect();
            if let Some(unknown) = object.keys().find(|id| !offered.contains(&id.as_str())) {
                return Err(format!(
                    "field {unknown:?} is not offered by the schema; allowed: {}",
                    offered.join(", ")
                )
                .into());
            }

            let mut report = Report::to(cli.repo.parse::<Destination>()?).form(&form);
            for (id, value) in object {
                let text = value
                    .as_str()
                    .ok_or_else(|| format!("field {id:?} must be a string"))?;
                report = report.field(id, text);
            }
            report = report.provenance(provenance!().scrubbed(&redactor));
            // preview(), never send(). There is no route argument on this
            // subcommand precisely so that no flag can turn it into one.
            return Ok(report.preview()?);
        }
        _ => {}
    }

    let destination: Destination = cli.repo.parse()?;

    let mut provenance = provenance!()
        .build("x86_64-unknown-linux-gnu", "release")
        .commit(option_env!("GIT_COMMIT"));
    if let Some(workdir) = &cli.workdir {
        provenance = provenance.with("Workdir", Value::known(workdir));
    }

    let mut diagnostics = match &cli.log {
        Some(path) => {
            let text = std::fs::read_to_string(path)?;
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
            redactor.records(&text, name.as_deref())
        }
        None => Vec::new(),
    };

    if let Some(text) = &cli.raw_record {
        // Every part hostile on purpose, and none of it passed through the
        // redactor — the shape an embedding application produces when it maps
        // its own log events onto `Record`.
        diagnostics.push(squelch::Record {
            timestamp: text.clone(),
            level: text.clone(),
            source: Some(text.clone()),
            fields: vec![(text.clone(), text.clone())],
        });
    }

    let transport = match &cli.route {
        Route::Preview => Transport::Browser,
        Route::File { out } => Transport::File(out.clone()),
        Route::Mailto { to } => Transport::Mailto(to.clone()),
        Route::Browser => Transport::Browser,
        Route::Gh { .. } => Transport::GhCli,
        Route::Endpoint { url, token, .. } => Transport::Endpoint {
            url: url.clone(),
            auth: match token {
                Some(token) => squelch::Auth::Bearer(token.clone()),
                None => squelch::Auth::None,
            },
        },
        // Returned above. Listed rather than caught by a wildcard so that
        // adding a route cannot silently acquire a transport it never meant
        // to have — the agent surface in particular must never reach one.
        Route::Schema | Route::Compose { .. } => unreachable!("handled before collection"),
    };

    let mut report = Report::to(destination)
        .template("bug.yml")
        .title("demo report")
        .field("current-behavior", &cli.current)
        .field("reproduction", &cli.repro)
        .require(["current-behavior", "reproduction"])
        .provenance(provenance.scrubbed(&redactor))
        .diagnostics(diagnostics)
        .via(transport);

    let confirmed = matches!(
        cli.route,
        Route::Gh { confirm: true } | Route::Endpoint { confirm: true, .. }
    );
    if confirmed {
        report = report.confirmed();
    }

    if matches!(cli.route, Route::Preview) {
        return Ok(report.preview()?);
    }

    Ok(format!("{:?}", report.send()?))
}
