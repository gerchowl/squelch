//! Fixtures for the end-to-end tests: a canary corpus, and fake receivers
//! standing in for the far end of each route that transmits.
//!
//! # Why receivers rather than assertions on the builder
//!
//! `Report::build` is already covered by unit tests. What was not covered is
//! everything *after* it — the process spawn, the argv, the HTTP body. A leak
//! introduced there would pass every existing test, because no test has ever
//! looked at what actually left the machine.
//!
//! So each fake receiver captures the real payload and the tests assert on
//! that: the URL `open` was handed, the argv `gh` was called with, the bytes
//! `POST`ed to the endpoint.
//!
//! # No new dependencies
//!
//! The HTTP receiver is a `TcpListener` and about forty lines, and the process
//! shims are `sh` scripts on `PATH`. That is deliberate: these tests run inside
//! `nix flake check`, whose sandbox has loopback but no network and no
//! container runtime.

#![allow(dead_code)]
// each test binary uses a different subset
// `mod common;` is compiled separately into every test binary, so from any one
// of them these items look unreachable. They are not: they are the shared
// fixture surface, and the alternative is copying it per binary.
#![allow(unreachable_pub)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

/// Values that must never appear in anything that leaves the machine.
///
/// Each is planted somewhere the report is assembled from — a log field, a
/// provenance value — and asserted absent from the received payload. This is
/// the end-to-end counterpart to the crate's `canary_record_leaks_nothing`
/// unit test, which only ever inspected a `Record`.
pub const CANARIES: &[(&str, &str)] = &[
    ("github token", "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"),
    ("another account's home", "/home/alice"),
    ("email address", "alice@example.com"),
    ("private ipv4", "10.1.2.3"),
    ("internal hostname", "build01.internal.acme.corp"),
    ("private org and repo", "acme-private"),
    ("labelled secret value", "s3cr3t-value-here"),
    // Added after an adversarial review pass; each one leaked when written.
    ("compressed ipv6", "fe80::1"),
    ("compressed ipv6 with tail", "2001::abcd"),
    ("underscored hostname label", "build01.foo_bar.example.com"),
    ("root home path", "/root/.ssh"),
    ("macos per-user temp", "/private/var/folders/x1"),
    ("tilde-user path", "~alice/.bashrc"),
    ("aws session key id", "ASIAIOSFODNN7EXAMPLE"),
    ("stripe live key", "sk_live_51H2xxABCDeFghIjKlMnO"),
    ("bearer token", "op4qYzKmVXpN2ABgH8fWmLtestFoo"),
    ("quoted secret tail", "hunter 2 stuff"),
    ("session cookie value", "s3ss10nvalueXYZ"),
    ("json-embedded token", "json_embedded_secret_v1"),
    // Added after a second adversarial review pass. Each one leaked when
    // written, and the first is the sharpest: the private-key rule matched
    // nothing at all, because `(?x)` strips whitespace inside a character
    // class and `[A-Z ]*` had compiled as `[A-Z]*`.
    ("private key armour", "BEGIN OPENSSH PRIVATE KEY"),
    ("forge url without .git", "prod-vault"),
    ("google api key", "AIzaSyD-1234567890abcdefghijklmnopqrstu"),
    ("slack app-level token", "xapp-1-A00000000-1234567890"),
    ("telegram bot token", "AAG1234567890abcdefghijklmnopqrstuv"),
    // The account name, not the path shape: the corpus carries this inside a
    // JSON string, where the separators are escaped, and a needle with a
    // backslash in it would never be found by the vacuity check.
    ("driveless windows account", "bobtestuser"),
    ("unc path", "fileserver"),
    ("mac address", "aa-bb-cc-dd-ee-ff"),
];

/// Text that must SURVIVE. Over-masking makes the block worthless just as
/// surely as under-masking makes it dangerous, so the corpus pins both ends.
pub const SURVIVORS: &[&str] = &[
    "No such file or directory (os error 2)",
    // A stack frame is the single most useful line in a bug report, and the
    // FQDN rule was eating every one of them: a dotted lowercase run is the
    // shape of a hostname AND of a Python, Java or Kotlin module path.
    "django.contrib.auth.models",
    "org.jetbrains.kotlin.compiler",
    // The tilde-home rule had no left boundary, so every revision in a pasted
    // git command came out as `HEAD<path>`.
    "HEAD~1",
];

/// A JSONL log corpus with a canary in every position that matters:
/// in scrubbed fields (`message`, `err`), where the value rules must catch it;
/// and in unlisted fields (`args`, `remote`), where the allowlist must drop
/// the field unread.
pub fn canary_logs() -> String {
    [
        r#"{"timestamp":"2026-08-12T09:00:00Z","level":"info","message":"starting","event":"boot","version":"1.4.0"}"#,
        r#"{"timestamp":"2026-08-12T09:00:01Z","level":"error","event":"process.exec","program":"git","args":"-C /home/alice/work/acme-private remote get-url origin","err":"No such file or directory (os error 2)"}"#,
        r#"{"timestamp":"2026-08-12T09:00:02Z","level":"warn","event":"auth.refresh","message":"refresh_token=s3cr3t-value-here rejected for alice@example.com"}"#,
        r#"{"timestamp":"2026-08-12T09:00:03Z","level":"error","event":"net.dial","message":"dial build01.internal.acme.corp (10.1.2.3) failed","remote":"git@github.com:acme-private/secret-thing.git"}"#,
        r#"{"timestamp":"2026-08-12T09:00:04Z","level":"error","event":"token.use","message":"using ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"}"#,
        // A timestamp is not a safe field: it was rendered verbatim, so
        // anything a logging stack interpolated into it was published.
        r#"{"timestamp":"2026-08-12T09:00:05Z host=build01.internal.acme.corp","level":"error","event":"e","message":"m"}"#,
        r#"{"timestamp":"2026-08-12T09:00:06Z","level":"error","event":"net","message":"peer fe80::1 and 2001::abcd unreachable"}"#,
        r#"{"timestamp":"2026-08-12T09:00:07Z","level":"error","event":"dns","message":"resolve build01.foo_bar.example.com failed"}"#,
        r#"{"timestamp":"2026-08-12T09:00:08Z","level":"error","event":"fs","message":"open /root/.ssh/id_rsa and /private/var/folders/x1/abc/T/f and ~alice/.bashrc"}"#,
        r#"{"timestamp":"2026-08-12T09:00:09Z","level":"error","event":"aws","message":"creds ASIAIOSFODNN7EXAMPLE and sk_live_51H2xxABCDeFghIjKlMnO rejected"}"#,
        r#"{"timestamp":"2026-08-12T09:00:10Z","level":"error","event":"http","message":"Authorization: Bearer op4qYzKmVXpN2ABgH8fWmLtestFoo denied"}"#,
        r#"{"timestamp":"2026-08-12T09:00:11Z","level":"error","event":"cfg","message":"password=\"hunter 2 stuff\" invalid"}"#,
        // Framework session cookies are named `SESSIONID`/`session_id`, which a
        // label list ending at `session` never matched.
        r#"{"timestamp":"2026-08-12T09:00:13Z","level":"error","event":"web","message":"SESSIONID=s3ss10nvalueXYZ rejected"}"#,
        // `err` and `message` routinely carry JSON from downstream services,
        // where the separator is `":"` rather than `=`.
        r#"{"timestamp":"2026-08-12T09:00:14Z","level":"error","event":"api","message":"upstream said {\"token\":\"json_embedded_secret_v1\"}"}"#,
        // A zero-width space inside a credential broke every character class,
        // and renders as nothing, so a human reviewing the preview saw an
        // intact token and no reason to object.
        &format!(r#"{{"timestamp":"2026-08-12T09:00:12Z","level":"error","event":"zw","message":"using ghp_ZeroWidth{}SplitTokenAbcdefghij now"}}"#, "\u{200b}"),
        // The armour rule matched nothing any tool emits, so the base64 body
        // after it — which matches no other rule either — was publishable in
        // full.
        r#"{"timestamp":"2026-08-12T09:00:15Z","level":"error","event":"key","message":"failed to parse -----BEGIN OPENSSH PRIVATE KEY----- block"}"#,
        // The forge rule wanted a trailing `.git`, which is the one form a
        // human reading git's own error never sees.
        r#"{"timestamp":"2026-08-12T09:00:16Z","level":"error","event":"git","message":"repository 'https://github.com/acmecorp/prod-vault/' not found"}"#,
        r#"{"timestamp":"2026-08-12T09:00:17Z","level":"error","event":"gcp","message":"key AIzaSyD-1234567890abcdefghijklmnopqrstu rejected"}"#,
        r#"{"timestamp":"2026-08-12T09:00:18Z","level":"error","event":"slack","message":"xapp-1-A00000000-1234567890-abcdefabcdefabcdef expired"}"#,
        r#"{"timestamp":"2026-08-12T09:00:19Z","level":"error","event":"tg","message":"bot 123456789:AAG1234567890abcdefghijklmnopqrstuv unauthorized"}"#,
        r#"{"timestamp":"2026-08-12T09:00:20Z","level":"error","event":"fs","message":"cannot open Users\\bobtestuser\\Documents\\notes.txt or \\\\fileserver\\share\\q.docx"}"#,
        r#"{"timestamp":"2026-08-12T09:00:21Z","level":"error","event":"net","message":"iface aa-bb-cc-dd-ee-ff down"}"#,
        // The survivors. A block scrubbed into uselessness costs the
        // maintainer the same round trip as no block at all, so the corpus
        // pins both ends of the rule.
        r#"{"timestamp":"2026-08-12T09:00:22Z","level":"error","event":"trace","message":"at django.contrib.auth.models.User.save and org.jetbrains.kotlin.compiler.plugin"}"#,
        r#"{"timestamp":"2026-08-12T09:00:23Z","level":"info","event":"git","message":"ran git reset --hard HEAD~1"}"#,
    ]
    .join("\n")
}

/// A provenance value the application supplies and the reporter never sees.
/// Proves scrubbing reaches provenance, not just the log block.
pub const CANARY_WORKDIR: &str = "/home/alice/work/acme-private";

/// Assert that nothing from [`CANARIES`] survived into `payload`.
///
/// `what` names the receiver, so a failure says which route leaked rather
/// than only that something did.
pub fn assert_nothing_leaked(what: &str, payload: &str) {
    let mut leaked = Vec::new();
    for (label, needle) in CANARIES {
        if payload.contains(needle) {
            leaked.push(format!("{label} ({needle})"));
        }
    }
    assert!(
        leaked.is_empty(),
        "{what} received {} canaries:\n  {}\n\n--- payload ---\n{payload}",
        leaked.len(),
        leaked.join("\n  ")
    );
}

/// Assert the block is still diagnostic — a report scrubbed into uselessness
/// costs the same triage round trip as no report at all.
pub fn assert_still_diagnostic(what: &str, payload: &str) {
    for survivor in SURVIVORS {
        assert!(
            payload.contains(survivor),
            "{what} lost {survivor:?}, which must survive redaction\n\
             --- payload ---\n{payload}"
        );
    }
}

// ---------------------------------------------------------------------------
// Scratch directories
// ---------------------------------------------------------------------------

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A unique empty directory under the system temp dir.
pub fn scratch(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("squelch-e2e-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// Write the canary log corpus to a file and return its path.
pub fn canary_log_file(dir: &Path) -> PathBuf {
    let path = dir.join("app.jsonl");
    std::fs::write(&path, canary_logs()).expect("write log corpus");
    path
}

// ---------------------------------------------------------------------------
// Process shims — the fake `gh`, and the fake browser opener
// ---------------------------------------------------------------------------

/// Separator between captured argv entries. A report body contains newlines,
/// so the capture file cannot be line-delimited.
const ARG_SEP: char = '\u{1e}';

/// A stand-in binary on `PATH` that records the argv it was called with.
pub struct Shim {
    pub dir: PathBuf,
    pub capture: PathBuf,
}

impl Shim {
    /// Create a shim named `name` in its own directory.
    ///
    /// Deliberately does NOT touch this process's `PATH`. Tests in one binary
    /// run on parallel threads, and `set_var` is process-global: two of them
    /// racing corrupts the environment badly enough that the panic machinery
    /// itself fails (`failed to initiate panic`), which turns an ordinary
    /// assertion failure into an unreadable abort.
    ///
    /// [`run_demo_with`] puts the directory on the *child's* `PATH` instead,
    /// which is race-free and closer to what a real invocation looks like.
    pub fn install(name: &str, exit_code: i32) -> Self {
        let dir = scratch(&format!("shim-{name}"));
        let capture = dir.join("argv");
        let script = dir.join(name);

        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\n\
                 for a in \"$@\"; do printf '%s' \"$a\"; printf '\\036'; done >> '{}'\n\
                 printf 'https://github.com/gerchowl/squelch/issues/1\\n'\n\
                 exit {exit_code}\n",
                capture.display()
            ),
        )
        .expect("write shim");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
                .expect("chmod shim");
        }

        Self { dir, capture }
    }

    /// The argv the shim was called with, or an empty vec if never invoked.
    pub fn argv(&self) -> Vec<String> {
        let raw = std::fs::read_to_string(&self.capture).unwrap_or_default();
        raw.split(ARG_SEP)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    }

    pub fn was_called(&self) -> bool {
        self.capture.exists()
    }
}

/// The program squelch spawns to open a URL, per platform.
pub const BROWSER_OPENER: &str = if cfg!(target_os = "macos") {
    "open"
} else {
    "xdg-open"
};

// ---------------------------------------------------------------------------
// HTTP receiver — the far end of Transport::Endpoint
// ---------------------------------------------------------------------------

/// What the endpoint actually received.
pub struct Received {
    pub method: String,
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Received {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// A one-shot HTTP server on loopback.
pub struct Receiver {
    pub url: String,
    handle: std::thread::JoinHandle<Option<Received>>,
}

impl Receiver {
    /// Bind port 0 and accept exactly one request in the background.
    pub fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let url = format!("http://{addr}/reports");

        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().ok()?;
            let mut reader = BufReader::new(stream);

            let mut request_line = String::new();
            reader.read_line(&mut request_line).ok()?;
            let mut parts = request_line.split_whitespace();
            let method = parts.next()?.to_string();
            let target = parts.next()?.to_string();

            let mut headers = Vec::new();
            let mut length = 0usize;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).ok()? == 0 {
                    break;
                }
                let line = line.trim_end();
                if line.is_empty() {
                    break;
                }
                if let Some((name, value)) = line.split_once(':') {
                    let (name, value) = (name.trim().to_string(), value.trim().to_string());
                    if name.eq_ignore_ascii_case("content-length") {
                        length = value.parse().unwrap_or(0);
                    }
                    headers.push((name, value));
                }
            }

            let mut body = vec![0u8; length];
            if length > 0 {
                reader.read_exact(&mut body).ok()?;
            }

            let response = b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 26\r\n\r\n{\"url\":\"https://x/issue/1\"}";
            let _ = reader.get_mut().write_all(&response[..]);
            let _ = reader.get_mut().flush();

            Some(Received {
                method,
                target,
                headers,
                body: String::from_utf8_lossy(&body).into_owned(),
            })
        });

        Self { url, handle }
    }

    /// Block until the request has been served, and return it.
    pub fn received(self) -> Received {
        self.handle
            .join()
            .expect("receiver thread panicked")
            .expect("no request reached the endpoint")
    }
}

// ---------------------------------------------------------------------------
// Driving the app
// ---------------------------------------------------------------------------

/// Run the demo binary, returning (success, stdout, stderr).
///
/// Driving the real binary rather than calling the library is the point: it
/// crosses a process boundary and a crate boundary, so it exercises the public
/// API a consumer actually has.
pub fn run_demo(args: &[&str]) -> (bool, String, String) {
    run_demo_inner(None, args)
}

/// Run the demo binary with `shim`'s directory first on its `PATH`, so the
/// stand-in is what gets spawned instead of the real `gh` or platform opener.
pub fn run_demo_with(shim: &Shim, args: &[&str]) -> (bool, String, String) {
    run_demo_inner(Some(&shim.dir), args)
}

fn run_demo_inner(path_prefix: Option<&Path>, args: &[&str]) -> (bool, String, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_squelch-demo"));
    command.args(args);
    if let Some(prefix) = path_prefix {
        let inherited = std::env::var("PATH").unwrap_or_default();
        command.env("PATH", format!("{}:{inherited}", prefix.display()));
    }
    let output = command.output().expect("run squelch-demo");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}
