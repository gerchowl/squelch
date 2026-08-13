//! How a composed report leaves the machine.
//!
//! The routes are ordered by the infrastructure they demand. [`Browser`] needs
//! none and is the default; everything below it trades a guarantee away for
//! convenience, and each is explicit about which one.
//!
//! [`Browser`]: Transport::Browser
//!
//! # The guarantees, and where they are lost
//!
//! | route | validates the form | human reviews before send | needs a credential |
//! | --- | --- | --- | --- |
//! | `Browser` | yes — GitHub's own | yes — the form *is* the review | no |
//! | `Endpoint` | no | only if you confirm first | server-side |
//! | `GhCli` | no | only if you confirm first | the user's `gh` |
//! | `Mailto` | no | yes — their mail client | no |
//! | `File` | no | yes — they open it | no |
//!
//! Posting a body through an API bypasses issue-form validation entirely:
//! `required: true` never runs, and a confirmation checkbox is never ticked by
//! a human. That is not a bug in this crate — it is what the GitHub API does —
//! but it means a form is advisory on every route except `Browser`.
//!
//! Because `Browser` is the only route where the review surface is built in,
//! [`crate::Report::send`] requires an explicit confirmation on the others.

use std::path::PathBuf;

// `browser` only: every `Error::*` use in this file is in `open_in_browser`.
// The endpoint route needs `Result` (imported below) but never names `Error`,
// so including it here produced an unused-import warning for any consumer
// building with `endpoint` and not `browser` — which breaks anyone compiling
// with `#![deny(warnings)]`.
#[cfg(feature = "browser")]
use crate::error::Error;
#[allow(unused_imports)]
use crate::error::Result;

/// Where to send a composed report.
#[derive(Debug, Clone)]
pub enum Transport {
    /// Open GitHub's prefilled issue form in the user's browser.
    ///
    /// The default, and the only route that costs nothing to operate and keeps
    /// the reporter as the author of their own issue.
    Browser,

    /// POST to an endpoint the project operates, which holds the credential.
    ///
    /// # This is an open gateway unless you gate it
    ///
    /// A CLI cannot solve a CAPTCHA, so the browser-based abuse protection a
    /// web app would use is unavailable. An unauthenticated endpoint that
    /// creates issues is a spam target the moment its URL is discovered — and
    /// it will be discovered, because it ships inside your binary.
    ///
    /// Realistic mitigations, roughly in order of preference: rate limiting by
    /// address at the edge; a proof-of-work stamp the client computes; or real
    /// per-user authentication, if your project already has accounts.
    ///
    /// A shared token compiled into the binary has a smaller blast radius than
    /// a GitHub token — it reaches only your endpoint, not your repository —
    /// but it is still extractable, and the end state is still spam.
    ///
    /// # Not available on wasm
    ///
    /// This route uses a blocking HTTP client, which `wasm32-unknown-unknown`
    /// has no way to provide. In a browser or Tauri webview, compose with
    /// squelch and POST with the platform's own fetch — the composed body and
    /// destination are both public on [`crate::Composed`].
    #[cfg(feature = "endpoint")]
    Endpoint {
        /// Where to POST.
        url: String,
        /// How to authenticate, if at all.
        auth: Auth,
    },

    /// Create the issue with the `gh` CLI, using the reporter's own credentials.
    ///
    /// Not a contributor-only path — for anyone who already has `gh`
    /// authenticated this is the *best* route, not a fallback. It files without
    /// leaving the terminal: no browser launch, no context switch, no form to
    /// re-read. Check [`gh_available`] and prefer it when it returns true.
    ///
    /// What it gives up versus [`Transport::Browser`] is smaller than it looks.
    /// Required fields are already checked by `Report::require`, so the loss is
    /// the template's confirmation checkbox, which `Report::confirmed` covers in
    /// substance. Authorship stays correct because it is the reporter's own
    /// token, and rate limiting lands on their account rather than a shared
    /// relay — better than an endpoint on both counts.
    ///
    /// The token never enters this process: `gh` reads its own credential store
    /// and makes the request. That is the reason this is a separate route
    /// rather than [`Transport::Endpoint`] pointed at `api.github.com` with a
    /// token from `gh auth token` — the latter would pull a personal access
    /// token through a crate whose whole claim is that it carries none.
    #[cfg(feature = "gh-cli")]
    GhCli,

    /// Hand the report to the user's mail client.
    Mailto(String),

    /// Write the report to a file for the user to attach or paste.
    ///
    /// The route that works with no browser and no network, which is a state
    /// some bugs put the machine in.
    File(PathBuf),
}

impl Default for Transport {
    /// [`Transport::Browser`]: the only route that needs no infrastructure and
    /// keeps GitHub's form as the review surface. Written out rather than
    /// derived so the default is a stated decision, not a field order.
    fn default() -> Self {
        Self::Browser
    }
}

/// A callback producing request headers, for credentials the crate must not
/// cache — short-lived tokens, or ones fetched from a keychain per request.
#[cfg(feature = "endpoint")]
pub type DynamicAuth = std::sync::Arc<dyn Fn() -> Result<Vec<(String, String)>> + Send + Sync>;

/// Credentials for [`Transport::Endpoint`].
///
/// The crate never holds a credential of its own and never ships a default
/// endpoint. Both are supplied by the embedding application at runtime.
#[cfg(feature = "endpoint")]
pub enum Auth {
    /// Send nothing. Read the abuse warning on [`Transport::Endpoint`] first:
    /// an unauthenticated issue-creating endpoint is a spam target the moment
    /// its URL is found, and it ships inside your binary.
    None,
    /// `Authorization: Bearer <token>`.
    Bearer(String),
    /// An arbitrary header, for schemes that are not bearer tokens.
    Header {
        /// The header name.
        name: String,
        /// Its value.
        value: String,
    },
    /// Computed per request, for short-lived tokens the crate must not cache.
    Dynamic(DynamicAuth),
}

#[cfg(feature = "endpoint")]
impl Clone for Auth {
    fn clone(&self) -> Self {
        match self {
            Self::None => Self::None,
            Self::Bearer(token) => Self::Bearer(token.clone()),
            Self::Header { name, value } => Self::Header {
                name: name.clone(),
                value: value.clone(),
            },
            Self::Dynamic(f) => Self::Dynamic(f.clone()),
        }
    }
}

#[cfg(feature = "endpoint")]
impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the credential itself — Debug output ends up in logs.
        match self {
            Self::None => write!(f, "Auth::None"),
            Self::Bearer(_) => write!(f, "Auth::Bearer(<redacted>)"),
            Self::Header { name, .. } => write!(f, "Auth::Header {{ name: {name:?}, .. }}"),
            Self::Dynamic(_) => write!(f, "Auth::Dynamic(..)"),
        }
    }
}

#[cfg(feature = "endpoint")]
impl Auth {
    pub(crate) fn headers(&self) -> Result<Vec<(String, String)>> {
        Ok(match self {
            Self::None => Vec::new(),
            Self::Bearer(token) => vec![("Authorization".into(), format!("Bearer {token}"))],
            Self::Header { name, value } => vec![(name.clone(), value.clone())],
            Self::Dynamic(build) => build()?,
        })
    }
}

/// Whether this route sends without a human seeing the result first.
impl Transport {
    pub(crate) fn needs_explicit_confirmation(&self) -> bool {
        match self {
            // GitHub's form is the review surface, and the user still clicks
            // Submit there.
            Self::Browser => false,
            // The user's own mail client and file viewer are review surfaces.
            Self::Mailto(_) | Self::File(_) => false,
            #[cfg(feature = "endpoint")]
            Self::Endpoint { .. } => true,
            #[cfg(feature = "gh-cli")]
            Self::GhCli => true,
        }
    }

    pub(crate) fn describe(&self) -> String {
        match self {
            Self::Browser => "open GitHub's issue form in your browser".into(),
            Self::Mailto(to) => format!("open a mail draft to {to}"),
            Self::File(path) => format!("write the report to {}", path.display()),
            #[cfg(feature = "endpoint")]
            Self::Endpoint { url, .. } => format!("POST the report to {url}"),
            #[cfg(feature = "gh-cli")]
            Self::GhCli => "create the issue with `gh`".into(),
        }
    }
}

/// Open a URL in the user's browser.
///
/// Refuses anything [`crate::url::is_safe_to_open`] rejects, and passes `--`
/// where the platform opener supports it, so a URL can never be read as an
/// option.
#[cfg(feature = "browser")]
pub fn open_in_browser(url: &str) -> Result<()> {
    if !crate::url::is_safe_to_open(url) {
        return Err(Error::UnsafeUrl(url.to_string()));
    }

    let (program, args): (&str, Vec<&str>) = if cfg!(target_os = "macos") {
        ("open", vec!["--", url])
    } else if cfg!(target_os = "windows") {
        ("cmd", vec!["/C", "start", "", url])
    } else {
        ("xdg-open", vec![url])
    };

    let status = std::process::Command::new(program)
        .args(&args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|err| Error::Spawn {
            program: program.into(),
            source: err,
        })?;

    if status.success() {
        Ok(())
    } else {
        Err(Error::OpenerFailed(status.to_string()))
    }
}

/// Whether a browser can plausibly be launched.
///
/// False over SSH: there is no display worth opening on the far end, and the
/// URL belongs on the machine the human is sitting at.
pub fn browser_available() -> bool {
    if std::env::var_os("SSH_CONNECTION").is_some() || std::env::var_os("SSH_TTY").is_some() {
        return false;
    }
    if cfg!(target_os = "linux") {
        return std::env::var_os("DISPLAY").is_some()
            || std::env::var_os("WAYLAND_DISPLAY").is_some();
    }
    true
}

impl Transport {
    /// The best route available on this machine, ranked by reporter effort.
    ///
    /// `gh` first — filing without leaving the terminal beats a browser round
    /// trip — then a browser, then a file the reporter can attach. Never
    /// selects the `Endpoint` route (`endpoint` feature), which needs a URL
    /// only the embedder has.
    ///
    /// This probes the environment, so call it once and reuse the result.
    /// Note that a route it picks may still require [`crate::Report::confirmed`]
    /// before it will send.
    pub fn best_available(fallback_file: impl Into<PathBuf>) -> Self {
        #[cfg(feature = "gh-cli")]
        if gh_available() {
            return Self::GhCli;
        }
        if browser_available() {
            return Self::Browser;
        }
        Self::File(fallback_file.into())
    }
}

/// Whether `gh` is installed and authenticated.
#[cfg(feature = "gh-cli")]
pub fn gh_available() -> bool {
    std::process::Command::new("gh")
        .args(["auth", "status"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_route_does_not_need_extra_confirmation() {
        assert!(!Transport::Browser.needs_explicit_confirmation());
        assert!(!Transport::File("/tmp/x".into()).needs_explicit_confirmation());
    }

    #[cfg(feature = "gh-cli")]
    #[test]
    fn credential_routes_need_confirmation() {
        assert!(Transport::GhCli.needs_explicit_confirmation());
    }

    #[cfg(feature = "browser")]
    #[test]
    fn refuses_to_open_an_unsafe_url() {
        assert!(matches!(
            open_in_browser("-a/Applications/Calculator.app"),
            Err(Error::UnsafeUrl(_))
        ));
        assert!(matches!(
            open_in_browser("file:///etc/passwd"),
            Err(Error::UnsafeUrl(_))
        ));
    }

    #[cfg(feature = "endpoint")]
    #[test]
    fn auth_debug_never_prints_the_credential() {
        let auth = Auth::Bearer("super-secret-value".into());
        assert!(!format!("{auth:?}").contains("super-secret"));
    }

    #[test]
    fn best_available_always_returns_something_usable() {
        // Whatever the machine offers, there is always a route.
        let route = Transport::best_available("/tmp/report.md");
        assert!(!route.describe().is_empty());
    }

    #[test]
    fn describe_names_the_destination() {
        assert!(Transport::Mailto("bugs@example.com".into())
            .describe()
            .contains("bugs@example.com"));
    }
}
