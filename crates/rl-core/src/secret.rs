//! Secrets in the configuration (doc §14, F10): a value may name where its
//! secret is instead of holding it, so the TOML file can be shared and
//! kept in version control.
//!
//! `${env:NAME}` is replaced by environment variable NAME and
//! `${file:/path}` by the file's contents (one trailing line break
//! removed). Both may appear inside a longer value, e.g.
//! `url = "https://ntfy.sh/${env:NTFY_TOPIC}"`. A `$` not followed by `{`
//! is kept as it is.

use std::fmt;

/// A value that must not show up in logs or messages: `Debug` prints
/// `<secret>`.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<secret>")
    }
}

/// Replace every `${env:…}` and `${file:…}` in `s`. Errors name the
/// variable or file, never its contents.
pub fn expand(s: &str) -> Result<String, String> {
    expand_with(s, &|name| std::env::var(name).ok(), &|path| {
        std::fs::read_to_string(path).map_err(|e| e.to_string())
    })
}

fn expand_with(
    s: &str,
    env: &dyn Fn(&str) -> Option<String>,
    file: &dyn Fn(&str) -> Result<String, String>,
) -> Result<String, String> {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(at) = rest.find("${") {
        out.push_str(&rest[..at]);
        let inner = &rest[at + 2..];
        let end = inner.find('}').ok_or("has a ${ without its closing }")?;
        let reference = &inner[..end];
        if let Some(name) = reference.strip_prefix("env:") {
            if name.is_empty() {
                return Err("has ${env:} without a variable name".into());
            }
            match env(name) {
                Some(v) => out.push_str(&v),
                None => return Err(format!("environment variable {name} is not set")),
            }
        } else if let Some(path) = reference.strip_prefix("file:") {
            if path.is_empty() {
                return Err("has ${file:} without a path".into());
            }
            let v = file(path).map_err(|e| format!("cannot read {path}: {e}"))?;
            let v = v
                .strip_suffix("\r\n")
                .or_else(|| v.strip_suffix('\n'))
                .unwrap_or(&v);
            out.push_str(v);
        } else {
            return Err(format!(
                "has ${{{reference}}}; use ${{env:NAME}} or ${{file:/path}}"
            ));
        }
        rest = &inner[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn x(s: &str) -> Result<String, String> {
        expand_with(
            s,
            &|n| (n == "TOKEN").then(|| "t0k".to_string()),
            &|p| match p {
                "/run/secret" => Ok("s3cret\n".into()),
                _ => Err("no such file".into()),
            },
        )
    }

    #[test]
    fn references_are_replaced() {
        assert_eq!(x("plain $5 value").unwrap(), "plain $5 value");
        assert_eq!(x("${env:TOKEN}").unwrap(), "t0k");
        assert_eq!(x("${file:/run/secret}").unwrap(), "s3cret");
        assert_eq!(
            x("https://ntfy.sh/${env:TOKEN}?k=${file:/run/secret}").unwrap(),
            "https://ntfy.sh/t0k?k=s3cret"
        );
    }

    #[test]
    fn mistakes_name_the_reference_not_a_value() {
        assert_eq!(
            x("${env:NOPE}").unwrap_err(),
            "environment variable NOPE is not set"
        );
        assert!(x("${file:/x}").unwrap_err().starts_with("cannot read /x"));
        assert!(x("${env:TOKEN").unwrap_err().contains("closing"));
        assert!(x("${vault:k}").unwrap_err().contains("${vault:k}"));
        assert!(x("${env:}").is_err());
        assert_eq!(format!("{:?}", Secret::new("t0k")), "<secret>");
    }
}
