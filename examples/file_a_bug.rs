//! A complete report, composed and previewed without sending anything.
//!
//! ```text
//! cargo run --example file_a_bug
//! ```
//!
//! Nothing leaves the machine: this uses the `File` route and prints the
//! preview. Swap in `Transport::Browser` to open GitHub's form for real.

use squelch::{provenance, Provenance, Redactor, Report, Transport, Value};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let redactor = Redactor::new();

    // Stand in for your application's real log file. Note that `args` carries
    // a path and a private repository name, and neither survives.
    let logs = r#"
{"timestamp":"2026-08-06T13:05:12.7Z","level":"info","message":"starting","event":"boot","version":"1.4.0"}
{"timestamp":"2026-08-06T13:05:14.1Z","level":"error","message":"exec failed","event":"process.exec","program":"git","args":"-C /home/alice/work/acme-private remote get-url origin","err":"No such file or directory (os error 2)"}
"#;

    let report = Report::to("gerchowl/squelch".parse::<squelch::Destination>()?)
        .template("bug.yml")
        .field(
            "current-behavior",
            "every git operation fails with os error 2",
        )
        .field(
            "expected-behavior",
            "it works, or it names the missing program",
        )
        .field(
            "reproduction",
            "run `myapp sync` with the daemon under systemd",
        )
        .field("impact", "the tool is unusable on that host")
        .require(["current-behavior", "reproduction"])
        .provenance(
            provenance!()
                .build("x86_64-unknown-linux-gnu", "release")
                .commit(option_env!("GIT_COMMIT"))
                .with(
                    "Binary",
                    Value::known(std::env::current_exe()?.display().to_string()),
                )
                .scrubbed(&redactor),
        )
        .diagnostics(redactor.records(logs, Some("myapp.jsonl")))
        .via(Transport::File("/tmp/squelch-example.md".into()));

    println!("{}", report.preview()?);

    println!("--- what the redactor kept, and dropped ---");
    for record in redactor.records(logs, None) {
        println!("{}", record.render());
    }
    println!(
        "\nnote: `args` held /home/alice/work/acme-private and is gone entirely —\n\
         it is not on the allowlist, so it was never read."
    );

    // Demonstrate that required fields are checked before anything opens.
    let incomplete = Report::to("gerchowl/squelch".parse::<squelch::Destination>()?)
        .field("current-behavior", "it broke")
        .require(["current-behavior", "reproduction"]);
    match incomplete.build() {
        Err(err) => println!("\nincomplete report refused: {err}"),
        Ok(_) => println!("\nunexpected: the incomplete report was accepted"),
    }

    let _ = Provenance::standard();
    Ok(())
}
