//! Where a report goes, and how that is decided.

use std::fmt;

/// GitHub's own limits. Without a ceiling, an absurd repository reference makes
/// the URL base alone exceed the length cap while every field is silently
/// dropped for want of budget.
const MAX_OWNER: usize = 39;
const MAX_NAME: usize = 100;

/// A GitHub repository, as `owner/name`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    owner: String,
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DestinationError {
    /// The crate declares no `repository` and none was supplied.
    Unknown,
    /// A value that is not a recognisable `owner/name` or GitHub URL.
    Malformed(String),
}

impl fmt::Display for DestinationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => write!(
                f,
                "no destination: set `repository` in Cargo.toml, or pass one explicitly"
            ),
            Self::Malformed(value) => write!(f, "expected owner/name, got {value:?}"),
        }
    }
}

impl std::error::Error for DestinationError {}

impl Destination {
    /// Parse `owner/name`, a GitHub HTTPS URL, or an SSH remote.
    pub fn parse(value: &str) -> Result<Self, DestinationError> {
        Self::normalize(value).ok_or_else(|| DestinationError::Malformed(value.to_string()))
    }

    /// The repository the *calling* crate declares in its `Cargo.toml`.
    ///
    /// Callers should prefer the [`crate::report!`] macro,
    /// which captures this at the call site. Reading it here would yield
    /// `squelch`'s own repository, which is never what you want.
    #[doc(hidden)]
    pub fn from_cargo_repository(value: Option<&str>) -> Result<Self, DestinationError> {
        match value.map(str::trim).filter(|v| !v.is_empty()) {
            Some(value) => Self::parse(value),
            None => Err(DestinationError::Unknown),
        }
    }

    pub fn owner(&self) -> &str {
        &self.owner
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn slug(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }

    fn normalize(value: &str) -> Option<Self> {
        let value = value.trim().trim_end_matches('/');
        let value = value.strip_suffix(".git").unwrap_or(value);

        let tail = value
            .rsplit_once("github.com")
            .map(|(_, tail)| tail.trim_start_matches(['/', ':']))
            .unwrap_or(value);

        let mut parts = tail.split('/').filter(|part| !part.is_empty());
        let owner = parts.next()?;
        let name = parts.next()?;
        if parts.next().is_some() {
            return None;
        }

        let valid = |part: &str, max: usize| {
            !part.is_empty()
                && part.len() <= max
                && part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        };
        if !valid(owner, MAX_OWNER) || !valid(name, MAX_NAME) {
            return None;
        }

        Some(Self {
            owner: owner.to_string(),
            name: name.to_string(),
        })
    }
}

impl std::str::FromStr for Destination {
    type Err = DestinationError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.owner, self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_every_shape_of_reference() {
        for input in [
            "https://github.com/gerchowl/squelch",
            "https://github.com/gerchowl/squelch.git",
            "https://github.com/gerchowl/squelch/",
            "git@github.com:gerchowl/squelch.git",
            "gerchowl/squelch",
        ] {
            assert_eq!(
                Destination::parse(input).unwrap().slug(),
                "gerchowl/squelch"
            );
        }
    }

    #[test]
    fn rejects_malformed_and_oversized() {
        for input in ["squelch", "a/b/c", "", "owner/na me", "owner/na;me"] {
            assert!(Destination::parse(input).is_err(), "{input}");
        }
        assert!(Destination::parse(&format!("{}/r", "a".repeat(40))).is_err());
        assert!(Destination::parse(&format!("o/{}", "b".repeat(101))).is_err());
    }

    #[test]
    fn parses_from_str() {
        let destination: Destination = "gerchowl/squelch".parse().unwrap();
        assert_eq!(destination.owner(), "gerchowl");
        assert_eq!(destination.name(), "squelch");
    }

    #[test]
    fn missing_repository_is_its_own_error() {
        assert_eq!(
            Destination::from_cargo_repository(None),
            Err(DestinationError::Unknown)
        );
        assert_eq!(
            Destination::from_cargo_repository(Some("  ")),
            Err(DestinationError::Unknown)
        );
    }
}
