use anyhow::{bail, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{path::Path, sync::OnceLock};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileFormat {
    Json,
    Toml,
    Text,
}

impl FileFormat {
    pub fn for_path(path: &Path) -> Self {
        match path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase()
            .as_str()
        {
            "json" | "jsonc" | "code-workspace" | "kiro" => Self::Json,
            "toml" => Self::Toml,
            _ => Self::Text,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceKind {
    Existing,
    RebindRequired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretReference {
    /// JSON pointer for structured files; line number for text files.
    pub location: String,
    /// Existing reference, or a generated environment variable placeholder.
    pub reference: String,
    pub kind: ReferenceKind,
}

#[derive(Clone)]
pub struct SanitizedContent {
    /// Semantic changes, including removed history, independent of secret references.
    pub modified: bool,
    pub bytes: Vec<u8>,
    pub secret_references: Vec<SecretReference>,
}

impl std::fmt::Debug for SanitizedContent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SanitizedContent")
            .field("byte_count", &self.bytes.len())
            .field("reference_count", &self.secret_references.len())
            .finish()
    }
}

fn regex(pattern: &'static str, cell: &'static OnceLock<Regex>) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("static regular expression"))
}

fn is_reference(value: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    regex(r"^(\$[A-Za-z_][A-Za-z0-9_]*|\$\{(?:env:|input:)?[A-Za-z_][A-Za-z0-9_.-]*\}|(?:env|vault|op|secret)://[A-Za-z0-9_./#-]+)$", &RE).is_match(value)
}

fn normalized_key(key: &str) -> String {
    key.chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect()
}

fn secret_key(key: &str) -> bool {
    let key = normalized_key(key);
    [
        "password",
        "passwd",
        "secret",
        "token",
        "apikey",
        "accesskey",
        "privatekey",
        "authorization",
        "credential",
        "cookie",
        "clientkey",
        "sessionkey",
    ]
    .iter()
    .any(|term| key.contains(term))
        || matches!(key.as_str(), "auth" | "key" | "pwd" | "pat")
}

fn suspicious_value(value: &str) -> bool {
    // Any query or userinfo can carry credentials, independent of parameter name.
    if value.split_once("://").is_some_and(|(_, rest)| {
        rest.contains('?')
            || rest
                .split('/')
                .next()
                .is_some_and(|authority| authority.contains('@'))
    }) {
        return true;
    }
    if contains_sensitive_assignment(value) {
        return true;
    }
    static RE: OnceLock<Regex> = OnceLock::new();
    if regex(r"(?i)(-----BEGIN[^\r\n]*PRIVATE KEY-----|\b(?:sk-|sk_|gh[pousr]_|github_pat_|glpat-|xox[baprs]-|AKIA)[A-Za-z0-9_-]+|\b(?:bearer|basic)\s+\S+|[a-z][a-z0-9+.-]*://[^\s/@]+:[^\s/@]+@|[?&](?:api[_-]?key|token|secret|password|access[_-]?token)=|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)", &RE).is_match(value) { return true }
    // Catch common opaque tokens even when hidden under an innocuous field name.
    value
        .split(|c: char| !c.is_ascii_alphanumeric() && !"_-/+=".contains(c))
        .any(|word| {
            word.len() >= 24
                && word.chars().any(|c| c.is_ascii_digit())
                && word.chars().any(|c| c.is_ascii_alphabetic())
                && (word.chars().any(|c| c.is_ascii_uppercase()) || word.len() >= 32)
        })
}

fn pointer(parent: &str, key: &str) -> String {
    format!("{}/{}", parent, key.replace('~', "~0").replace('/', "~1"))
}

fn replace(value: &mut Value, location: &str, references: &mut Vec<SecretReference>) {
    if value.is_null() {
        return;
    }
    let (reference, kind) = match value.as_str().filter(|v| is_reference(v)) {
        Some(existing) => (existing.to_owned(), ReferenceKind::Existing),
        None => (
            format!("${{BUNKER_SECRET_{}}}", references.len() + 1),
            ReferenceKind::RebindRequired,
        ),
    };
    *value = Value::String(reference.clone());
    references.push(SecretReference {
        location: location.to_owned(),
        reference,
        kind,
    });
}

fn walk(value: &mut Value, location: &str, references: &mut Vec<SecretReference>) {
    match value {
        Value::Object(map) => {
            // Some agent settings embed conversation/history caches alongside MCP
            // settings. Drop these fields rather than capturing customer content.
            map.retain(|key, _| {
                !matches!(
                    normalized_key(key).as_str(),
                    "history"
                        | "chathistory"
                        | "messages"
                        | "transcript"
                        | "transcripts"
                        | "conversation"
                        | "conversations"
                        | "sessions"
                        | "projects"
                )
            });
            for (key, child) in map {
                let path = pointer(location, key);
                let normalized = normalized_key(key);
                if matches!(
                    normalized.as_str(),
                    "env" | "environment" | "headers" | "httpheaders"
                ) {
                    if let Value::Object(entries) = child {
                        for (name, entry) in entries {
                            replace(entry, &pointer(&path, name), references);
                        }
                    } else {
                        replace(child, &path, references);
                    }
                } else if secret_key(key) {
                    replace(child, &path, references);
                } else if matches!(
                    normalized.as_str(),
                    "args" | "arguments" | "commandline" | "envfile" | "envfilepath"
                ) {
                    // Literal CLI arguments can carry unnamed credentials. Keep only flags
                    // without values and explicit secret references; require rebind otherwise.
                    if let Value::Array(args) = child {
                        for (index, arg) in args.iter_mut().enumerate() {
                            let flag = arg.as_str().is_some_and(|s| {
                                s.starts_with("--")
                                    && s.len() > 2
                                    && s[2..].chars().all(|c| c.is_ascii_alphabetic() || c == '-')
                            });
                            if !flag {
                                replace(arg, &pointer(&path, &index.to_string()), references);
                            }
                        }
                    } else {
                        replace(child, &path, references);
                    }
                } else if normalized == "command"
                    && child
                        .as_str()
                        .is_some_and(|s| s.chars().any(char::is_whitespace))
                {
                    replace(child, &path, references);
                } else {
                    walk(child, &path, references);
                }
            }
        }
        Value::Array(array) => {
            for (index, child) in array.iter_mut().enumerate() {
                walk(child, &pointer(location, &index.to_string()), references);
            }
        }
        Value::String(text) if is_reference(text) || suspicious_value(text) => {
            replace(value, location, references);
        }
        _ => (),
    }
}

/// Structural JSON/TOML sanitization; conservative text line redaction.
/// Parse errors deliberately omit parser diagnostics, which can contain secrets.
pub fn sanitize(bytes: &[u8], format: FileFormat) -> Result<SanitizedContent> {
    if bytes.len() > 1024 * 1024 {
        bail!("configuration exceeds 1 MiB sanitizer cap")
    }
    let input =
        std::str::from_utf8(bytes).map_err(|_| anyhow::anyhow!("non-UTF-8 content refused"))?;
    if input.contains('\0') {
        bail!("binary content refused")
    }
    if input.to_ascii_uppercase().contains("PRIVATE KEY-----") {
        bail!("private key material refused")
    }
    let mut references = vec![];
    let modified;
    let output = match format {
        FileFormat::Json => {
            let mut value: Value = serde_json::from_str(input)
                .map_err(|_| anyhow::anyhow!("invalid JSON configuration (JSONC comments/trailing commas are unsupported); file skipped"))?;
            if !value.is_object() {
                bail!("JSON configuration must be an object")
            }
            let original = value.clone();
            walk(&mut value, "", &mut references);
            modified = value != original;
            serde_json::to_vec_pretty(&value)?
        }
        FileFormat::Toml => {
            let parsed: toml::Value = toml::from_str(input)
                .map_err(|_| anyhow::anyhow!("invalid TOML configuration; snapshot refused"))?;
            let mut value = serde_json::to_value(parsed)
                .map_err(|_| anyhow::anyhow!("unsupported TOML value"))?;
            let original = value.clone();
            walk(&mut value, "", &mut references);
            modified = value != original;
            let output: toml::Value = serde_json::from_value(value)
                .map_err(|_| anyhow::anyhow!("cannot encode sanitized TOML"))?;
            toml::to_string_pretty(&output)
                .map_err(|_| anyhow::anyhow!("cannot encode sanitized TOML"))?
                .into_bytes()
        }
        FileFormat::Text => {
            let output = sanitize_text(input, &mut references)?.into_bytes();
            modified = output != bytes;
            output
        }
    };
    Ok(SanitizedContent {
        modified,
        bytes: if modified { output } else { bytes.to_vec() },
        secret_references: references,
    })
}

fn contains_sensitive_assignment(value: &str) -> bool {
    static ASSIGNMENT: OnceLock<Regex> = OnceLock::new();
    let assignment = regex(
        r#"(?i)(?:^|[\s\"'{,;])(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)[\"']?\s*[:=]"#,
        &ASSIGNMENT,
    );
    assignment.captures_iter(value).any(|c| secret_key(&c[1]))
}

fn sanitize_text(input: &str, references: &mut Vec<SecretReference>) -> Result<String> {
    let mut output = String::new();
    for (index, line) in input.split_inclusive('\n').enumerate() {
        let body = line.trim_end_matches(['\r', '\n']);
        if contains_sensitive_assignment(body) {
            // A line-based sanitizer cannot know where a multiline credential
            // ends. Refuse the whole file rather than leak continuation lines.
            let tail = body
                .rsplit_once(['=', ':'])
                .map(|(_, value)| value.trim())
                .unwrap_or("");
            if tail.is_empty()
                || tail.starts_with(['|', '>'])
                || body.trim_end().ends_with('\\')
                || body.contains("\"\"\"")
                || body.contains("'''")
                || body.chars().filter(|c| *c == '\"').count() % 2 != 0
                || body.chars().filter(|c| *c == '\'').count() % 2 != 0
            {
                bail!("ambiguous multiline credential text; snapshot refused");
            }
        }
        if suspicious_value(body) {
            // Whole-line redaction also removes comments and shell suffixes containing values.
            let mut value = Value::String(body.to_owned());
            replace(&mut value, &format!("line:{}", index + 1), references);
            output.push_str(value.as_str().unwrap());
            if line.ends_with('\n') {
                output.push('\n');
            }
        } else {
            output.push_str(line);
        }
    }
    Ok(output)
}
