//! The crate's error type.

use std::fmt;

/// This crate's `Result`, with [`Error`] already applied.
pub type Result<T> = std::result::Result<T, Error>;

/// Everything that can go wrong composing or sending a report.
///
/// Every variant's `Display` is written for the *reporter* rather than the
/// developer: it is shown to a person who is already having a bad day with
/// your software, and it says what they can do next.
#[derive(Debug)]
pub enum Error {
    /// No destination could be determined.
    Destination(crate::destination::DestinationError),
    /// A required form field was left empty.
    MissingFields(Vec<String>),
    /// A URL was refused before being handed to a platform opener.
    UnsafeUrl(String),
    /// A route that sends without a review surface was used without
    /// [`crate::Report::confirmed`].
    ConfirmationRequired(String),
    /// An external program could not be started.
    Spawn {
        /// The program that could not be run, e.g. `gh`.
        program: String,
        /// What the operating system said.
        source: std::io::Error,
    },
    /// The platform's URL opener ran and reported failure.
    OpenerFailed(String),
    /// The prefilled URL could not carry these fields, so opening the form
    /// would submit a report missing whole sections.
    FieldsDropped(Vec<String>),
    /// Reading or writing failed — the `File` route, mostly.
    Io(std::io::Error),
    /// The endpoint you operate refused the report.
    #[cfg(feature = "endpoint")]
    Endpoint {
        /// The HTTP status, when the request got far enough to have one.
        status: Option<u16>,
        /// What the server said, or what went wrong before it could answer.
        message: String,
    },
    /// Raised by an `Auth::Dynamic` callback (`endpoint` feature). Not an
    /// intra-doc link: the target does not exist on a default build, and a
    /// link that only resolves under one feature breaks `cargo doc` on every
    /// other.
    Auth(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Destination(err) => write!(f, "{err}"),
            Self::MissingFields(fields) => {
                write!(f, "these sections are still empty: {}", fields.join(", "))
            }
            Self::FieldsDropped(fields) => write!(
                f,
                "too long for a browser link — these sections would not reach \
                 GitHub: {}. Use a route that carries the whole report \
                 (a file, mail, `gh`, or your endpoint), or shorten them",
                fields.join(", ")
            ),
            Self::UnsafeUrl(url) => write!(
                f,
                "refusing to open {url:?}: only https://github.com/ links are opened"
            ),
            Self::ConfirmationRequired(route) => write!(
                f,
                "this route would {route} without anyone reviewing it first; \
                 call .confirmed() once the reporter has seen the preview"
            ),
            Self::Spawn { program, source } => write!(f, "could not run {program}: {source}"),
            Self::OpenerFailed(status) => write!(f, "the browser opener failed: {status}"),
            Self::Io(err) => write!(f, "{err}"),
            #[cfg(feature = "endpoint")]
            Self::Endpoint { status, message } => match status {
                Some(code) => write!(f, "endpoint returned {code}: {message}"),
                None => write!(f, "endpoint request failed: {message}"),
            },
            Self::Auth(message) => write!(f, "could not build credentials: {message}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Destination(err) => Some(err),
            Self::Spawn { source, .. } => Some(source),
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<crate::destination::DestinationError> for Error {
    fn from(err: crate::destination::DestinationError) -> Self {
        Self::Destination(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_fields_names_them() {
        let err = Error::MissingFields(vec!["reproduction".into(), "impact".into()]);
        assert!(err.to_string().contains("reproduction, impact"));
    }

    #[test]
    fn confirmation_error_says_what_to_do() {
        let err = Error::ConfirmationRequired("POST the report".into());
        assert!(err.to_string().contains(".confirmed()"));
    }
}
